from scapy.all import *
import datetime
import base64

# --- 1. CONFIGURATION ---
# Replace these with your actual details
student_name = "iribiriee"
student_id = "12345" 

# Create the timestamped payload string
# Format: YourName-YourStudentID YYYY-MM-DD HH:MM:SS
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
payload_str = f"{student_name}-{student_id} {timestamp}"

# List to store all generated packets
packets = []

print("Generating packets...")

# --- 2. PACKET GENERATION ---

# [A] Student's Packet
# Protocol: TCP | Src: Random | Dst: 192.168.1.1 | Port: 54321
pkt1 = IP(src=RandIP(), dst="192.168.1.1") / TCP(dport=54321) / Raw(load=payload_str)
packets.append(pkt1)
print(f" - Generated Student Packet for {student_name}")

# [B] Port Scan Packets 
# Services: HTTP, HTTPS, SSH, TELNET, FTP, DNS, RTSP, SQL, RDP, MQTT
# Dst: 192.168.1.2 
# Protocol: Configure accordingly 
services = {
    80: "TCP",   # HTTP
    443: "TCP",  # HTTPS
    22: "TCP",   # SSH
    23: "TCP",   # TELNET
    21: "TCP",   # FTP
    53: "UDP",   # DNS (Standard DNS is UDP)
    554: "TCP",  # RTSP
    3306: "TCP", # SQL
    3389: "TCP", # RDP
    1883: "TCP"  # MQTT
}

for port, proto in services.items():
    if proto == "TCP":
        pkt = IP(src=RandIP(), dst="192.168.1.2") / TCP(dport=port) / Raw(load=payload_str)
    else: # UDP
        pkt = IP(src=RandIP(), dst="192.168.1.2") / UDP(dport=port) / Raw(load=payload_str)
    packets.append(pkt)
print(f" - Generated 10 Port Scan packets")

# [C] Base64 Malicious Packet
# Protocol: TCP | Dst: 192.168.1.3 | Port: 8080 | Src: Random
# Payload: Base64 encoded student ID
encoded_id = base64.b64encode(student_id.encode()).decode()
pkt_mal = IP(src=RandIP(), dst="192.168.1.3") / TCP(dport=8080) / Raw(load=encoded_id)
packets.append(pkt_mal)
print(f" - Generated Base64 Malicious Packet (Encoded ID: {encoded_id})")

# [D] DNS Suspicious Domain Packet 
# Protocol: UDP | Port: 53 | Src: Random
# Dst: Use VM DNS IP (Replace '127.0.0.53' if your cat /etc/resolv.conf gave a different IP) 
dns_dst_ip = "127.0.0.53" 
dns_query = IP(src=RandIP(), dst=dns_dst_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="malicious.example.com"))
packets.append(dns_query)
print(" - Generated Suspicious DNS Packet")

# [E] Ping Test Packet
# Protocol: ICMP | Dst: 192.168.1.4 | Src: Random
# Payload: "PingTest-2024" 
pkt_ping = IP(src=RandIP(), dst="192.168.1.4") / ICMP() / Raw(load="PingTest-2024")
packets.append(pkt_ping)
print(" - Generated Ping Test Packet")

# --- 3. SAVE TO PCAP ---
output_file = "my_traffic.pcap"
wrpcap(output_file, packets)
print(f"\nSUCCESS: All packets saved to {output_file}")
