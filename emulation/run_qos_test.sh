#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time

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

def run():
    setLogLevel('info')
    topo = QoSTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.start()

    r1, h1, h2, h3 = net.get('r1'), net.get('h1'), net.get('h2'), net.get('h3')

    # Start CAKE on each interface
    for iface in ['r1-eth0', 'r1-eth1', 'r1-eth2']:
        r1.cmd(f"tc qdisc replace dev {iface} root cake bandwidth 10mbit diffserv4")

    # Start classifier daemon
    info("[*] Starting classifier daemon in background on router...\n")
    daemon = "/home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/scripts/classifier_daemon.py"
    r1.cmd(f"source /home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/.venv/bin/activate")
    r1.cmd(f"python3 {daemon} &")

    # Launch simulated traffic
    info("[*] Launching test flows...\n")

    # VOIP: h1 → h3 (UDP)
    h1.cmd("yes | nc -u 10.0.3.2 4000 &")

    # BULK: h2 → h3 (TCP)
    h3.cmd("iperf -s &")
    time.sleep(1)
    h2.cmd("iperf -c 10.0.3.2 -t 10 &")

    # VIDEO: h2 → h3 (HTTP)
    h3.cmd("python3 -m http.server 80 &")
    time.sleep(1)
    h2.cmd("wget --timeout=5 --tries=1 http://10.0.3.2/largefile || curl http://10.0.3.2/largefile &")

    info("[*] Waiting 60 seconds for flows to complete...\n")
    time.sleep(60)

    # Diagnostics
    info("\n[+] iptables mangle rules (from r1):\n")
    print(r1.cmd("iptables -t mangle -L -v"))

    info("\n[+] CAKE Queue Stats:\n")
    for iface in ['r1-eth0', 'r1-eth1', 'r1-eth2']:
        print(f"--- {iface} ---")
        print(r1.cmd(f"tc -s qdisc show dev {iface}"))

    info("[✓] Automated QoS test complete. Entering Mininet CLI...\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
