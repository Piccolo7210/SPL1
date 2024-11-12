# PacketEye
PacketEye aims to create a simple and user-friendly tool that introduces aspiring developers to the fundamental concepts of network packet analysis. The project will focus on capturing, decoding, and displaying basic network packets, making it accessible to individuals with limited programming experience. PacketEye should be capable of capturing network packets from various sources, such as
Ethernet or Wi-Fi. It will capture packets in real-time or allow loading packet capture files saved in popular formats (e.g., pcap, pcapng).

### Features----------------------------------------------<br>
Real-Time Packet Capture: Capture live network packets from sources like Ethernet or Wi-Fi interfaces.
Protocol Decoding: Decode and display essential details of common network protocols, including:<br>
1. Ethernet<br>
1. IP<br>
3. TCP/UDP <br>
Detailed Packet Information: Extract and display critical information, such as:<br>
i. Source and destination IP addresses<br>
ii. Port numbers<br>
iii. Packet payload data<br>
### Technology Stack<br>
Languages: C (primary), C++ (optional)<br>
Tools & Libraries: Wireshark, Libpcap<br>
Prerequisites<br>
Install Wireshark for packet analysis. Install Libpcap if you intend to add packet capture capabilities.<br>
### Installation----------------------------------------<br>
 **Clone the repository:**
git clone https://github.com/yourusername/PacketEye.git <br>
**Navigate to the project directory:<br>**
cd PacketEye<br>
**Compile the project:<br>**
make<br>
**To run the PacketEye tool:<br>**
./PacketEye
