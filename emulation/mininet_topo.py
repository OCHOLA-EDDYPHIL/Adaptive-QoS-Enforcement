from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


class LinuxRouter(Node):
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()

class QoSTopo(Topo):
    def build(self):
        router = self.addNode('r1', cls=LinuxRouter)

        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        h3 = self.addHost('h3', ip='10.0.3.2/24', defaultRoute='via 10.0.3.1')

        self.addLink(h1, router, intfName2='r1-eth0', params2={'ip': '10.0.1.1/24'},
                     cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(h2, router, intfName2='r1-eth1', params2={'ip': '10.0.2.1/24'},
                     cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(h3, router, intfName2='r1-eth2', params2={'ip': '10.0.3.1/24'},
                     cls=TCLink, bw=10, delay='50ms', loss=1)

def run_topo():
    topo = QoSTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.start()

    # Set default routes
    for h in ['h1', 'h2', 'h3']:
        net.get(h).cmd('ip route add default via 10.0.0.1')

    r1 = net.get('r1')
    # Start CAKE on each interface
    for iface in ['r1-eth0', 'r1-eth1', 'r1-eth2']:
        r1.cmd(f"tc qdisc replace dev {iface} root cake bandwidth 10mbit diffserv8")
    # Start classifier daemon
    info("[*] Starting classifier daemon in background on router...\n")
    daemon = "/home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/scripts/classifier_daemon.py"
    r1.cmd(f"source /home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/.venv/bin/activate")
    r1.cmd(f"python3 {daemon} &")

    print("[*] Ready. Use xterm h1 h2 h3 to interact. Start daemon on r1.")
    CLI(net)

if __name__ == '__main__':
    setLogLevel('info')
    run_topo()
