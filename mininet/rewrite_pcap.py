from scapy.all import *
import random

IN_PCAP  = "univ.pcap"
OUT_PCAP = "rewritten_partial.pcap"
MAX_PKTS = 10000

DST_MAC = "00:00:00:00:00:02"

DST_IP  = "10.0.1.2"

out = []

with PcapReader(IN_PCAP) as pcap:
    for i, p in enumerate(pcap):
        if i >= MAX_PKTS:
            break

        if Ether not in p:
            continue

        p[Ether].src = f"02:00:00:{i//256:02x}:{i%256:02x}"
        p[Ether].dst = DST_MAC

        if IP in p:
            p[IP].src = f"10.0.1.{(i % 6) + 1}"
            p[IP].dst = DST_IP
            del p[IP].chksum

        if TCP in p:
            del p[TCP].chksum
        if UDP in p:
            del p[UDP].chksum

        out.append(p)

wrpcap(OUT_PCAP, out)
print(f"Written {len(out)} packets")
