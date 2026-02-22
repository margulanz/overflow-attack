from scapy.all import *
import random

IN_PCAP  = "univ.pcap"
MAX_PKTS = 100000

REAL_HOSTS = {
    1: {"mac": "00:00:00:00:00:01", "ip": "10.0.1.1"},
    2: {"mac": "00:00:00:00:00:02", "ip": "10.0.1.2"},
    3: {"mac": "00:00:00:00:00:03", "ip": "10.0.1.3"},
    4: {"mac": "00:00:00:00:00:04", "ip": "10.0.1.4"},
    5: {"mac": "00:00:00:00:00:05", "ip": "10.0.1.5"},
    6: {"mac": "00:00:00:00:00:06", "ip": "10.0.1.6"},
}

# Controlled virtual host pool (noise)
VIRTUAL_POOL_SIZE = 175
VIRTUAL_HOSTS = {}

for i in range(1, VIRTUAL_POOL_SIZE + 1):
    VIRTUAL_HOSTS[i] = {
        "mac": f"02:00:00:00:{i//256:02x}:{i%256:02x}",
        "ip": f"10.1.0.{i}"
    }

host_packets = {h: [] for h in REAL_HOSTS.keys()}

with PcapReader(IN_PCAP) as pcap:
    for i, p in enumerate(pcap):
        if i >= MAX_PKTS:
            break

        if Ether not in p:
            continue

        src_host = random.randint(1, 6)

        # 80% normal traffic, 20% noise
        if random.random() < 0.8:
            # Normal traffic between real hosts
            dst_host = random.randint(1, 6)
            while dst_host == src_host:
                dst_host = random.randint(1, 6)

            dst_mac = REAL_HOSTS[dst_host]["mac"]
            dst_ip  = REAL_HOSTS[dst_host]["ip"]

        else:
            # Noise traffic (virtual hosts)
            v_id = random.randint(1, VIRTUAL_POOL_SIZE)
            dst_mac = VIRTUAL_HOSTS[v_id]["mac"]
            dst_ip  = VIRTUAL_HOSTS[v_id]["ip"]

        # Rewrite Ethernet
        p[Ether].src = REAL_HOSTS[src_host]["mac"]
        p[Ether].dst = dst_mac

        # Rewrite IP
        if IP in p:
            p[IP].src = REAL_HOSTS[src_host]["ip"]
            p[IP].dst = dst_ip
            del p[IP].chksum

        if TCP in p:
            del p[TCP].chksum
        if UDP in p:
            del p[UDP].chksum

        host_packets[src_host].append(p)

# Write per-host pcaps
for h in REAL_HOSTS.keys():
    filename = f"h{h}.pcap"
    wrpcap(filename, host_packets[h])
    print(f"Wrote {len(host_packets[h])} packets to {filename}")
