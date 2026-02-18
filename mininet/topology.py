#!/usr/bin/python3

import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.clean import cleanup
RYU_CONTROLLER_IP = "127.0.0.1"
RYU_CONTROLLER_PORT = 6653
def run():
    # Create Mininet without default controller
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    # Add Ryu remote controller (Docker is on localhost)
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip=RYU_CONTROLLER_IP,
        port=RYU_CONTROLLER_PORT
    )
    # Create 6 hosts
    h1 = net.addHost('h1', ip='10.0.1.1/24',mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.1.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.1.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.1.4/24', mac='00:00:00:00:00:04')
    h5 = net.addHost('h5', ip='10.0.1.5/24', mac='00:00:00:00:00:05')
    h6 = net.addHost('h6', ip='10.0.1.6/24', mac='00:00:00:00:00:06')

    # Create 4 switches with multiple links
    s1 = net.addSwitch('s1',protocols='OpenFlow13')
    #s2 = net.addSwitch('s2', protocols='OpenFlow13')
    #s3 = net.addSwitch('s3', protocols='OpenFlow13')
    #s4 = net.addSwitch('s4', protocols='OpenFlow13')
    

    # Host connections
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(h5, s1)
    net.addLink(h6, s1)
   
    # Switch mesh (multiple paths)
    #net.addLink(s1, s2)
    #net.addLink(s2, s3)
    #net.addLink(s3, s4)

    # Start network
    net.start()
    time.sleep(5)
    print("\n=== Network is running ===")
    tcpreplay_cmd = (
        "tcpreplay "
        "--multiplier=1 "
        "--intf1=h1-eth0 "
        "--limit=10000 "
        "univ_out.pcap"
    )
    start_ts = time.time()

    # BLOCKING call → guarantees same timing
    h1.cmd(tcpreplay_cmd)

    end_ts = time.time()

    print(f"*** tcpreplay finished in {end_ts - start_ts:.2f}s")
    net.stop()
    cleanup()

if __name__ == '__main__':
    setLogLevel('info')
    run()

