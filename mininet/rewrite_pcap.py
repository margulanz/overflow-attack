from scapy.all import *
import random

IN_PCAP = "univ2/univ2_pt1"

REAL_HOSTS = {
    1: {"mac": "00:00:00:00:00:01", "ip": "10.0.1.1"},
    2: {"mac": "00:00:00:00:00:02", "ip": "10.0.1.2"},
    3: {"mac": "00:00:00:00:00:03", "ip": "10.0.1.3"},
    4: {"mac": "00:00:00:00:00:04", "ip": "10.0.1.4"},
    5: {"mac": "00:00:00:00:00:05", "ip": "10.0.1.5"},
    6: {"mac": "00:00:00:00:00:06", "ip": "10.0.1.6"},
}

VIRTUAL_POOL_SIZE = 175
VIRTUAL_HOSTS = {
    i: {
        "mac": f"02:00:00:00:{i//256:02x}:{i%256:02x}",
        "ip": f"10.1.0.{i}"
    }
    for i in range(1, VIRTUAL_POOL_SIZE + 1)
}

# Open all writers upfront
writers = {h: PcapWriter(f"h{h}.pcap", append=False) for h in REAL_HOSTS}
counts = {h: 0 for h in REAL_HOSTS}

try:
    with PcapReader(IN_PCAP) as pcap:
        for i, p in enumerate(pcap):
            if i % 10000 == 0:
                print(f"Processed {i} packets")

            if Ether not in p:
                continue

            src_host = random.randint(1, 6)

            if random.random() < 0.8:
                dst_host = random.randint(1, 6)
                while dst_host == src_host:
                    dst_host = random.randint(1, 6)
                dst_mac = REAL_HOSTS[dst_host]["mac"]
                dst_ip  = REAL_HOSTS[dst_host]["ip"]
            else:
                v_id = random.randint(1, VIRTUAL_POOL_SIZE)
                dst_mac = VIRTUAL_HOSTS[v_id]["mac"]
                dst_ip  = VIRTUAL_HOSTS[v_id]["ip"]

            p[Ether].src = REAL_HOSTS[src_host]["mac"]
            p[Ether].dst = dst_mac

            if IP in p:
                p[IP].src = REAL_HOSTS[src_host]["ip"]
                p[IP].dst = dst_ip
                del p[IP].chksum
            if TCP in p:
                del p[TCP].chksum
            if UDP in p:
                del p[UDP].chksum

            # Write immediately, don't buffer
            writers[src_host].write(p)
            counts[src_host] += 1

finally:
    for h, w in writers.items():
        w.close()
        print(f"Wrote {counts[h]} packets to h{h}.pcap")
