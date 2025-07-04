from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

class LinuxRouter(Node):
    def config(self, **params):
        super().config(**params)
        # Enable IP forwarding
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()

class QoSTopo(Topo):
    def build(self):
        # Create router
        router = self.addNode('r1', cls=LinuxRouter, ip='10.0.0.1/24')

        # Create hosts
        h1 = self.addHost('h1', ip='10.0.0.2/24')
        h2 = self.addHost('h2', ip='10.0.0.3/24')
        h3 = self.addHost('h3', ip='10.0.0.4/24')

        # Add links with optional bandwidth/delay control
        self.addLink(h1, router, cls=TCLink)
        self.addLink(h2, router, cls=TCLink)
        self.addLink(h3, router, cls=TCLink)

def run():
    topo = QoSTopo()
    net = Mininet(topo=topo, link=TCLink, switch=OVSKernelSwitch, controller=None)
    net.start()

    # Set default routes
    for h in ['h1', 'h2', 'h3']:
        host = net.get(h)
        host.cmd(f'ip route add default via 10.0.0.1')

    r1 = net.get('r1')

    # Add CAKE qdisc to r1 interface to h1 (repeat for all if needed)
    r1.cmd("tc qdisc add dev r1-eth0 root handle 1: cake bandwidth 10mbit diffserv4")
    r1.cmd("tc qdisc add dev r1-eth1 root handle 2: cake bandwidth 10mbit diffserv4")
    r1.cmd("tc qdisc add dev r1-eth2 root handle 3: cake bandwidth 10mbit diffserv4")

    print("[*] Starting CLI...")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
