# PacketEye
PacketEye is a user-friendly tool designed to introduce aspiring developers to the fundamental concepts of network packet analysis. This project aims to make packet analysis accessible for individuals with limited programming experience by focusing on capturing, decoding, and displaying basic network packets in real-time.

****Features****
Real-Time Packet Capture: Capture live network packets from sources like Ethernet or Wi-Fi interfaces.
Protocol Decoding: Decode and display essential details of common network protocols, including:
1.Ethernet
1.IP
3.TCP/UDP
Detailed Packet Information: Extract and display critical information, such as:
i.Source and destination IP addresses
ii.Port numbers
iii.Packet payload data
File Import Support: Load and analyze pre-saved packet capture files in popular formats such as .pcap and .pcapng.
**Technology Stack**
Languages: C (primary), C++ (optional)
Tools & Libraries:
Wireshark: for packet analysis.
Libpcap: optional library for packet capturing.
Getting Started
Prerequisites
Install Wireshark for packet analysis.
Install Libpcap if you intend to add packet capture capabilities.
Installation
**Clone the repository:**
git clone https://github.com/yourusername/PacketEye.git
Navigate to the project directory:
cd PacketEye
Compile the project:
make
Usage
To run the PacketEye tool:
./PacketEye
