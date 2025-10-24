
/* Compile:
 *   g++ -std=c++17 network_monitir.cpp -o network_monitir
 * Run:
 *   sudo ./network_monitir <interface> <filter_src_IP> <filter_dst_IP>
 *
 * Example:
 *   sudo ./network_monitir eth0 192.168.1.10 192.168.1.20
 *
 * Note: run on Linux with root privileges (raw sockets).
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if.h>

using namespace std;

/* -------------------- Configurable constants -------------------- */
const int MAX_PKT_BUF = 65536;
const int ETH_STANDARD_MTU = 1500;
const int MAX_REPLAY_TRIES = 2;
const int OVERSIZE_SKIP_LIMIT = 10;
const int DEMO_SECONDS = 60;
/* ---------------------------------------------------------------- */

/* ------------------------ Utility helpers ----------------------- */
static string timestampNow() {
    time_t t = time(nullptr);
    char buf[64];
    struct tm *tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return string(buf);
}

static string ipv4ToString(uint32_t addr_netorder) {
    struct in_addr a;
    a.s_addr = addr_netorder;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return string(buf);
}

static string ipv6ToString(const struct in6_addr &addr6) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
    return string(buf);
}

static bool isValidIPAddress(const string &ip) {
    struct in_addr sa;
    struct in6_addr sa6;
    if (inet_pton(AF_INET, ip.c_str(), &sa) == 1) return true;
    if (inet_pton(AF_INET6, ip.c_str(), &sa6) == 1) return true;
    return false;
}
/* ---------------------------------------------------------------- */

/* -------------------------- Layer Stack ------------------------- */
/* Stack implemented as linked list holding C-strings (heap) */
struct LayerItem {
    char *name;
    LayerItem *next;
};

struct LayerStackLL {
    LayerItem *top;
    LayerStackLL() : top(nullptr) {}
    ~LayerStackLL() {
        while (top) {
            LayerItem *tmp = top;
            top = top->next;
            if (tmp->name) free(tmp->name);
            free(tmp);
        }
    }

    bool push_cstr(const char *s) {
        LayerItem *n = (LayerItem*)malloc(sizeof(LayerItem));
        if (!n) return false;
        size_t len = strlen(s) + 1;
        n->name = (char*)malloc(len);
        if (!n->name) { free(n); return false; }
        memcpy(n->name, s, len);
        n->next = top;
        top = n;
        return true;
    }

    // pop returns heap string; caller should free()
    char* pop() {
        if (!top) return nullptr;
        LayerItem *n = top;
        top = n->next;
        char *out = n->name;
        free(n);
        return out;
    }

    bool empty() const { return top == nullptr; }
};
/* ---------------------------------------------------------------- */

/* --------------------------- Packet type ------------------------- */
struct CapturedPkt {
    unsigned long long id;
    char ts[64];
    int length;
    unsigned char buf[MAX_PKT_BUF];
    int retry_count;

    // parsed fields
    bool v4;
    bool v6;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    unsigned short sport;
    unsigned short dport;
    char proto[16];

    CapturedPkt() {
        id = 0;
        ts[0] = '\0';
        length = 0;
        retry_count = 0;
        v4 = v6 = false;
        src[0] = dst[0] = '\0';
        sport = dport = 0;
        proto[0] = '\0';
        memset(buf, 0, sizeof(buf));
    }
};
/* ---------------------------------------------------------------- */

/* --------------------------- Packet Queue ------------------------ */
/* Simple linked-list FIFO queue */
struct PktNode {
    CapturedPkt pkt;
    PktNode *next;
};

struct PktQueue {
    PktNode *head;
    PktNode *tail;
    int cnt;
    PktQueue() : head(nullptr), tail(nullptr), cnt(0) {}
    ~PktQueue() {
        while (head) {
            PktNode *n = head;
            head = head->next;
            free(n);
        }
    }

    bool push(const CapturedPkt &p) {
        PktNode *n = (PktNode*)malloc(sizeof(PktNode));
        if (!n) return false;
        n->pkt = p;
        n->next = nullptr;
        if (!tail) head = tail = n;
        else { tail->next = n; tail = n; }
        ++cnt;
        return true;
    }

    bool pop(CapturedPkt &out) {
        if (!head) return false;
        PktNode *n = head;
        out = n->pkt;
        head = n->next;
        if (!head) tail = nullptr;
        free(n);
        --cnt;
        return true;
    }

    bool empty() const { return head == nullptr; }
    int size() const { return cnt; }
};
/* ---------------------------------------------------------------- */

/* -------------------------- Global counters ---------------------- */
unsigned long long g_pkt_id = 1;
int g_oversize_skipped = 0;
int g_oversize_total = 0;
unsigned long long g_captured = 0;
unsigned long long g_dissected = 0;
unsigned long long g_filtered = 0;
unsigned long long g_replayed = 0;

PktQueue g_replay_q;
PktQueue g_backup_q;
/* ---------------------------------------------------------------- */

/* ------------------------- Network helpers ----------------------- */
int get_iface_index(int sockfd, const string &ifn) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifn.c_str(), IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) return -1;
    return ifr.ifr_ifindex;
}

bool get_iface_mac(int sockfd, const string &ifn, unsigned char outmac[6]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifn.c_str(), IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) return false;
    memcpy(outmac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}
/* ---------------------------------------------------------------- */

/* ------------------------- Packet analysis ----------------------- */
void analyzePacket(CapturedPkt &p) {
    LayerStackLL stack;
    stack.push_cstr("Ethernet");

    if (p.length < (int)sizeof(struct ethhdr)) {
        printf("[%s] Packet %llu too small for Ethernet\n", timestampNow().c_str(), p.id);
        return;
    }

    struct ethhdr eth;
    memcpy(&eth, p.buf, sizeof(eth));
    uint16_t ethertype = ntohs(eth.h_proto);
    size_t offset = sizeof(struct ethhdr);

    if (ethertype == ETH_P_IP) {
        stack.push_cstr("IPv4");
        if (p.length >= (int)(offset + sizeof(struct iphdr))) {
            struct iphdr iph;
            memcpy(&iph, p.buf + offset, sizeof(iph));
            p.v4 = true;
            string s = ipv4ToString(iph.saddr);
            string d = ipv4ToString(iph.daddr);
            strncpy(p.src, s.c_str(), sizeof(p.src)-1);
            strncpy(p.dst, d.c_str(), sizeof(p.dst)-1);
            int ihl = iph.ihl * 4;
            offset += ihl;

            if (iph.protocol == IPPROTO_TCP) {
                stack.push_cstr("TCP");
                strncpy(p.proto, "TCP", sizeof(p.proto)-1);
                if (p.length >= (int)(offset + sizeof(struct tcphdr))) {
                    struct tcphdr tcph;
                    memcpy(&tcph, p.buf + offset, sizeof(tcph));
                    p.sport = ntohs(tcph.source);
                    p.dport = ntohs(tcph.dest);
                }
            } else if (iph.protocol == IPPROTO_UDP) {
                stack.push_cstr("UDP");
                strncpy(p.proto, "UDP", sizeof(p.proto)-1);
                if (p.length >= (int)(offset + sizeof(struct udphdr))) {
                    struct udphdr udph;
                    memcpy(&udph, p.buf + offset, sizeof(udph));
                    p.sport = ntohs(udph.source);
                    p.dport = ntohs(udph.dest);
                }
            } else {
                strncpy(p.proto, "Other", sizeof(p.proto)-1);
            }
        } else {
            printf("[%s] Packet %llu malformed IPv4\n", timestampNow().c_str(), p.id);
        }
    } else if (ethertype == ETH_P_IPV6) {
        stack.push_cstr("IPv6");
        if (p.length >= (int)(offset + sizeof(struct ip6_hdr))) {
            struct ip6_hdr ip6h;
            memcpy(&ip6h, p.buf + offset, sizeof(ip6h));
            p.v6 = true;
            string s = ipv6ToString(ip6h.ip6_src);
            string d = ipv6ToString(ip6h.ip6_dst);
            strncpy(p.src, s.c_str(), sizeof(p.src)-1);
            strncpy(p.dst, d.c_str(), sizeof(p.dst)-1);
            offset += sizeof(struct ip6_hdr);

            uint8_t nxt = ip6h.ip6_nxt;
            if (nxt == IPPROTO_TCP) {
                stack.push_cstr("TCP");
                strncpy(p.proto, "TCP", sizeof(p.proto)-1);
                if (p.length >= (int)(offset + sizeof(struct tcphdr))) {
                    struct tcphdr tcph;
                    memcpy(&tcph, p.buf + offset, sizeof(tcph));
                    p.sport = ntohs(tcph.source);
                    p.dport = ntohs(tcph.dest);
                }
            } else if (nxt == IPPROTO_UDP) {
                stack.push_cstr("UDP");
                strncpy(p.proto, "UDP", sizeof(p.proto)-1);
                if (p.length >= (int)(offset + sizeof(struct udphdr))) {
                    struct udphdr udph;
                    memcpy(&udph, p.buf + offset, sizeof(udph));
                    p.sport = ntohs(udph.source);
                    p.dport = ntohs(udph.dest);
                }
            } else {
                strncpy(p.proto, "Other", sizeof(p.proto)-1);
            }
        } else {
            printf("[%s] Packet %llu malformed IPv6\n", timestampNow().c_str(), p.id);
        }
    } else {
        strncpy(p.proto, "Non-IP", sizeof(p.proto)-1);
    }

    // print dissection summary
    printf("[%s] === Analysis for pkt #%llu ===\n", timestampNow().c_str(), p.id);
    printf("    captured at: %s\n", p.ts);
    printf("    len: %d\n", p.length);
    printf("    Layers (top->bottom):\n");
    int idx = 0;
    while (!stack.empty()) {
        char *lname = stack.pop();
        if (!lname) break;
        printf("      %d: %s\n", ++idx, lname);
        free(lname);
    }
    if (p.v4 || p.v6) {
        printf("    %s -> %s (%s)\n", p.src, p.dst, p.proto);
        if (p.sport || p.dport) {
            printf("    ports: %u -> %u\n", p.sport, p.dport);
        }
    }
    printf("\n");

    ++g_dissected;
}
/* ---------------------------------------------------------------- */

/* --------------------------- Filtering --------------------------- */
string g_filter_src;
string g_filter_dst;

bool matchesFilter(const CapturedPkt &p) {
    if ((p.v4 || p.v6) && p.src[0] && p.dst[0]) {
        if (g_filter_src == string(p.src) && g_filter_dst == string(p.dst)) return true;
    }
    return false;
}
/* ---------------------------------------------------------------- */

/* -------------------------- Replay sender ------------------------ */
bool sendReplay(int sockfd, struct sockaddr_ll *dev, CapturedPkt &p) {
    for (int at = 0; at <= MAX_REPLAY_TRIES; ++at) {
        ssize_t sent = sendto(sockfd, p.buf, p.length, 0, (struct sockaddr*)dev, sizeof(*dev));
        if (sent == p.length) {
            printf("[%s] OK: replayed pkt #%llu (try %d/%d)\n",
                   timestampNow().c_str(), p.id, at+1, MAX_REPLAY_TRIES+1);
            ++g_replayed;
            return true;
        } else {
            fprintf(stderr, "[%s] ERROR: replay try %d/%d for pkt #%llu (errno=%d)\n",
                    timestampNow().c_str(), at+1, MAX_REPLAY_TRIES+1, p.id, errno);
            usleep(100 * 1000);
        }
    }
    return false;
}
/* ---------------------------------------------------------------- */

/* ------------------------------ main ----------------------------- */
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: sudo %s <interface> <filter_src_IP> <filter_dst_IP>\n", argv[0]);
        return 1;
    }

    string ifname = argv[1];
    g_filter_src = string(argv[2]);
    g_filter_dst = string(argv[3]);

    if (!isValidIPAddress(g_filter_src) || !isValidIPAddress(g_filter_dst)) {
        fprintf(stderr, "Invalid filter IP(s)\n");
        return 1;
    }

    printf("\nNETWORK MONITIR - Live Capture\n");
    printf(" Interface: %s\n", ifname.c_str());
    printf(" Filter:    %s -> %s\n", g_filter_src.c_str(), g_filter_dst.c_str());
    printf(" Duration:  %d seconds\n\n", DEMO_SECONDS);

    int rcv_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rcv_sock < 0) { perror("socket"); return 1; }

    struct sockaddr_ll bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ALL);
    int idx = get_iface_index(rcv_sock, ifname);
    if (idx < 0) { fprintf(stderr, "Cannot get index for %s\n", ifname.c_str()); close(rcv_sock); return 1; }
    bind_addr.sll_ifindex = idx;

    if (bind(rcv_sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind");
        close(rcv_sock);
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(rcv_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    printf("[%s] capture initiated on %s\n", timestampNow().c_str(), ifname.c_str());

    time_t start = time(nullptr);
    unsigned char buffer[MAX_PKT_BUF];

    while (difftime(time(nullptr), start) < DEMO_SECONDS) {
        ssize_t rsz = recvfrom(rcv_sock, buffer, MAX_PKT_BUF, 0, nullptr, nullptr);
        if (rsz < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            else { perror("recvfrom"); continue; }
        }

        CapturedPkt cp;
        cp.id = g_pkt_id++;
        string t = timestampNow();
        strncpy(cp.ts, t.c_str(), sizeof(cp.ts)-1);
        cp.length = (int)rsz;
        if (cp.length > MAX_PKT_BUF) cp.length = MAX_PKT_BUF;
        memcpy(cp.buf, buffer, cp.length);

        ++g_captured;

        if (cp.length > ETH_STANDARD_MTU) {
            ++g_oversize_total;
            if (g_oversize_skipped >= OVERSIZE_SKIP_LIMIT) {
                printf("[%s] skipping too-large pkt #%llu len=%d (limit reached)\n",
                       timestampNow().c_str(), cp.id, cp.length);
                continue;
            } else {
                ++g_oversize_skipped;
                printf("[%s] warning: oversized pkt #%llu len=%d (skipped count %d)\n",
                       timestampNow().c_str(), cp.id, cp.length, g_oversize_skipped);
            }
        }

        printf("[%s] captured pkt #%llu len=%d\n", timestampNow().c_str(), cp.id, cp.length);

        analyzePacket(cp);

        if (matchesFilter(cp)) {
            double delayms = ((double)cp.length) / 1000.0;
            printf("[%s] MATCHED: pkt #%llu %s -> %s (%s), est delay %.2f ms\n",
                   timestampNow().c_str(), cp.id, cp.src, cp.dst, cp.proto, delayms);
            ++g_filtered;
            if (!g_replay_q.push(cp)) {
                fprintf(stderr, "[%s] enqueue failed for pkt %llu; moving to backup\n", timestampNow().c_str(), cp.id);
                g_backup_q.push(cp);
            }
        }
    } // end capture loop

    printf("\n[%s] capture finished. Processing replay queue...\n", timestampNow().c_str());

    int send_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (send_sock < 0) {
        perror("send socket");
    } else {
        int send_idx = get_iface_index(send_sock, ifname);
        if (send_idx < 0) {
            fprintf(stderr, "Cannot get index for interface %s (replay)\n", ifname.c_str());
            close(send_sock);
            send_sock = -1;
        } else {
            struct sockaddr_ll device;
            memset(&device, 0, sizeof(device));
            device.sll_family = AF_PACKET;
            device.sll_ifindex = send_idx;
            device.sll_halen = ETH_ALEN;
            device.sll_protocol = htons(ETH_P_ALL);

            unsigned char mac[6];
            if (!get_iface_mac(send_sock, ifname, mac)) {
                fprintf(stderr, "Warning: could not read MAC for %s\n", ifname.c_str());
            }

            CapturedPkt rp;
            while (g_replay_q.pop(rp)) {
                if (rp.length >= (int)sizeof(struct ethhdr)) {
                    struct ethhdr eth;
                    memcpy(&eth, rp.buf, sizeof(eth));
                    memcpy(device.sll_addr, eth.h_dest, ETH_ALEN);
                } else {
                    memset(device.sll_addr, 0xff, ETH_ALEN);
                }

                bool ok = sendReplay(send_sock, &device, rp);
                if (!ok) {
                    rp.retry_count = MAX_REPLAY_TRIES + 1;
                    printf("[%s] moving pkt #%llu to backup (replay failed)\n", timestampNow().c_str(), rp.id);
                    g_backup_q.push(rp);
                }
            } // end replay processing
        }
    }

    // Try one-shot recovery of backups (optional)
    if (!g_backup_q.empty() && send_sock >= 0) {
        printf("\n[%s] Attempting recovery for backup queue (size=%d)...\n", timestampNow().c_str(), g_backup_q.size());
        CapturedPkt bp;
        while (g_backup_q.pop(bp)) {
            struct sockaddr_ll device;
            memset(&device, 0, sizeof(device));
            device.sll_family = AF_PACKET;
            device.sll_ifindex = idx;
            device.sll_halen = ETH_ALEN;
            if (bp.length >= (int)sizeof(struct ethhdr)) {
                struct ethhdr eth;
                memcpy(&eth, bp.buf, sizeof(eth));
                memcpy(device.sll_addr, eth.h_dest, ETH_ALEN);
            } else {
                memset(device.sll_addr, 0xff, ETH_ALEN);
            }

            ssize_t sent = sendto(send_sock, bp.buf, bp.length, 0, (struct sockaddr*)&device, sizeof(device));
            if (sent == bp.length) {
                printf("[%s] RECOVERED backup pkt #%llu\n", timestampNow().c_str(), bp.id);
                ++g_replayed;
            } else {
                fprintf(stderr, "[%s] RECOVERY FAIL for pkt #%llu (errno=%d). Dropping.\n",
                        timestampNow().c_str(), bp.id, errno);
            }
        }
    }

    if (send_sock >= 0) close(send_sock);
    close(rcv_sock);

    // final summary
    printf("\nFINAL CAPTURE REPORT\n");
    printf("  Total captured:  %llu\n", g_captured);
    printf("  Total analyzed:  %llu\n", g_dissected);
    printf("  Total filtered:  %llu\n", g_filtered);
    printf("  Total replayed:  %llu\n", g_replayed);
    printf("  Oversize total:  %d\n", g_oversize_total);
    printf("  Oversize skipped: %d\n", g_oversize_skipped);
    printf("  Backup queue size: %d\n", g_backup_q.size());

    return 0;
}
