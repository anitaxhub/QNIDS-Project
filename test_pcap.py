"""
generate_test_pcap.py
Generates a test PCAP with 3 traffic types:
    - Normal HTTP traffic
    - SYN Flood (DoS)
    - Port Scan (nmap-style)
"""
import os
from scapy.all import (
    IP, TCP, UDP, Raw, Ether,
    wrpcap, RandShort
)

packets = []

# ── 1. Normal HTTP Traffic (200 packets)
print("Generating normal HTTP traffic...")
for i in range(200):
    src = f"192.168.1.{(i % 50) + 10}"
    pkt = (
        IP(src=src, dst="93.184.216.34") /
        TCP(sport=RandShort(), dport=80,
            flags="S", seq=1000 + i)
    )
    packets.append(pkt)

    ack = (
        IP(src="93.184.216.34", dst=src) /
        TCP(sport=80, dport=packets[-1][TCP].sport,
            flags="SA", seq=2000 + i, ack=1001 + i)
    )
    packets.append(ack)

# ── 2. SYN Flood / DoS (300 packets from one IP)
print("Generating DoS / SYN flood traffic...")
for i in range(300):
    pkt = (
        IP(src="10.0.0.99", dst="192.168.1.1") /
        TCP(sport=RandShort(), dport=80,
            flags="S", seq=i * 100)
    )
    packets.append(pkt)

# ── 3. Port Scan / nmap-style (250 packets)
print("Generating Port Scan traffic...")
for port in range(1, 251):
    pkt = (
        IP(src="172.16.0.55", dst="192.168.1.100") /
        TCP(sport=54321, dport=port,
            flags="S", seq=9999)
    )
    packets.append(pkt)

    # RST reply — port closed
    rst = (
        IP(src="192.168.1.100", dst="172.16.0.55") /
        TCP(sport=port, dport=54321,
            flags="RA", seq=0, ack=10000)
    )
    packets.append(rst)

# ── Save
os.makedirs("data", exist_ok=True)
output = "data/test_attack.pcap"
wrpcap(output, packets)
print(f"\n✅ PCAP saved: {output}")
print(f"   Total packets : {len(packets)}")
print(f"   Normal traffic: 400 packets")
print(f"   DoS / SYN flood: 300 packets")
print(f"   Port scan      : 500 packets")