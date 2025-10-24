# DSA_ASSIGNMENT2

Network Monitor — CS250 Data Structures & Algorithms
 # Overview:
This project implements a Network Packet Monitor using C++ raw sockets on Linux.
It continuously captures, filters, dissects, and replays network packets in real time.
The system uses custom implementations of Stack and Queue (no STL) to efficiently manage network traffic and protocol layers.

This project demonstrates the use of data structures and algorithms in a real-world network environment.

# Features:
-Custom Stack and Queue for packet and layer management
-Raw Socket Capture for real-time packet sniffing
-Protocol Dissection: Ethernet, IPv4, IPv6, TCP, and UDP
-Packet Filtering based on source and destination IPs
-Replay Mechanism with up to 2 retry attempts
-Error Handling and Backup Queue for failed replays

Display Functions to show:

-Captured packets (ID, timestamp, IPs)
-Dissected layers
-Filtered packets with delay calculation

# Assumptions:

-Program is executed on Linux with root privileges (sudo)
-Packet capture is limited to one network interface (e.g., eth0)
-No external libraries or STL containers are used for Stack or Queue
-Maximum packet size: 1500 bytes
-Replay attempts: 2 retries per failed packet

# Data Structures Used:

Stack:
Used for protocol dissection.
Each packet’s layers (Ethernet → IP → TCP/UDP) are pushed onto the stack and popped as parsing proceeds.
Helps maintain the correct order of protocol interpretation.

Queue:
Used for packet management.
Packets are enqueued as they are captured and dequeued when processed or replayed.
This structure allows continuous and ordered packet processing.

# Core Algorithms:

1.Packet Capture:

-Uses raw sockets to read packets directly from the network interface.
-Each packet is stored with ID, timestamp, source, destination, and raw data.

2.Dissection:

-A custom stack-based approach is used to peel off protocol layers (Ethernet → IPv4/6 → TCP/UDP).
-Each layer is identified and parsed manually.

3.Filtering:

-Matches packets with user-specified source and destination IPs.
-Moves matching packets to a separate replay list.
-Skips packets >1500 bytes if threshold exceeded.

4.Replay:

-Sends filtered packets back onto the network.
-Delay estimated as: Total Delay = Packet Size / 1000 ms
-Retries each failed packet up to 2 times.

5.Error Handling:

-Failed packets are moved to a backup queue.
-Retries are logged, ensuring fault-tolerant replay operation.

🖥️ How to Compile and Run
# Step 1: Compile the program
# Step 2: Run the program with root privileges

The program will continuously capture packets for at least 1 minute.
To stop it, press Ctrl + C.

 Demonstration:

-Start continuous capture for 1 minute.
-Dissect packets using the stack-based parser.
-Filter by specific source and destination IPs.
-Replay filtered packets with calculated delay.
-Observe error handling and backup retries.

📂 Repository Structure
📦 NetworkMonitor/
 ┣ 📄 network_monitor.cpp   # Main source file
 ┣ 📄 README.md             # Instructions and project overview
 ┗ 📄 Report.pdf            # Well-documented report for submission

👨‍💻 Author

Name: Sara Fawad
Cms id: 509615
Course: CS250 — Data Structures & Algorithms
Semester: Fall 2025
Section: BSDS-2
Department: Department of Computing

