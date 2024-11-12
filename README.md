# PacketEye
PacketEye is a user-friendly tool designed to introduce aspiring developers to the fundamental concepts of network packet analysis. This project aims to make packet analysis accessible for individuals with limited programming experience by focusing on capturing, decoding, and displaying basic network packets in real-time.

****Features****<br>
Real-Time Packet Capture: Capture live network packets from sources like Ethernet or Wi-Fi interfaces.
Protocol Decoding: Decode and display essential details of common network protocols, including:<br>
1.Ethernet<br>
1.IP<br>
3.TCP/UDP<br>
Detailed Packet Information: Extract and display critical information, such as:<br>
i.Source and destination IP addresses<br>
ii.Port numbers<br>
iii.Packet payload data<br>
File Import Support: Load and analyze pre-saved packet capture files in popular formats such as .pcap and .pcapng.<br>
**Technology Stack**<br>
Languages: C (primary), C++ (optional)<br>
Tools & Libraries:<br>
Wireshark: for packet analysis.<br>
Libpcap: optional library for packet capturing.<br>
Getting Started<br>
Prerequisites<br>
Install Wireshark for packet analysis.<br>
Install Libpcap if you intend to add packet capture capabilities.<br>
Installation<br>
**Clone the repository:** <br>
git clone https://github.com/yourusername/PacketEye.git <br>
Navigate to the project directory:<br>
cd PacketEye<br>
Compile the project:<br>
make<br>
Usage<br>
To run the PacketEye tool:<br>
./PacketEye
