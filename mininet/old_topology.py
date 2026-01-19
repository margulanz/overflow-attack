#!/usr/bin/python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
RYU_CONTROLLER_IP = "127.0.0.1" # "ryu"
def run():
    # Create Mininet without default controller
    net = Mininet(controller=None, switch=OVSSwitch)

    # Add Ryu remote controller (Docker is on localhost)
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip=RYU_CONTROLLER_IP,
        port=6633
    )
    # Create 6 hosts
    h1 = net.addHost('h1', ip='10.0.1.1/24')
    h2 = net.addHost('h2', ip='10.0.1.2/24')
    h3 = net.addHost('h3', ip='10.0.1.3/24')
    h4 = net.addHost('h4', ip='10.0.1.4/24')
    h5 = net.addHost('h5', ip='10.0.1.5/24')
    h6 = net.addHost('h6', ip='10.0.1.6/24')

    # Create 4 switches with multiple links
    s1 = net.addSwitch('s1',protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    
    # Create complex mesh
    # Host connections
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(h5, s3)
    net.addLink(h6, s4)
    
    # Switch mesh (multiple paths)
    net.addLink(s1, s2)
    net.addLink(s1, s3)
    net.addLink(s2, s3)
    net.addLink(s2, s4)
    net.addLink(s3, s4)
    # Add switch (OpenFlow 1.3)
    #s1 = net.addSwitch('s1', protocols='OpenFlow13')
    #s2 = net.addSwitch('s2', protocols='OpenFlow13')
    #s3 = net.addSwitch('s3', protocols='OpenFlow13')

    # Add hosts
    #h1 = net.addHost('h1', ip='10.0.0.1/24')
    #h2 = net.addHost('h2', ip='10.0.0.2/24')

    # Add links
    #net.addLink(h1, s1)
    #net.addLink(h2, s2)
    #net.addLink(s3, s1)
    #net.addLink(s3, s2)
    # Start network
    net.start()

    print("\n=== Network is running ===")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

