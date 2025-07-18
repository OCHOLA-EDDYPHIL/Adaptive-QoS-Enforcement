import subprocess
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'traffic_generation'))
import traffic_manager
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
        switch = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        # LAN A hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
        h3 = self.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254')
        # LAN B hosts
        h4 = self.addHost('h4', ip='10.0.1.1/24', defaultRoute='via 10.0.1.254')
        h5 = self.addHost('h5', ip='10.0.1.2/24', defaultRoute='via 10.0.1.254')
        h6 = self.addHost('h6', ip='10.0.1.3/24', defaultRoute='via 10.0.1.254')
        # LAN A switch connections
        self.addLink(h1, switch, cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(h2, switch, cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(h3, switch, cls=TCLink, bw=10, delay='50ms', loss=1)
        # LAN B switch connections
        self.addLink(h4, switch2, cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(h5, switch2, cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(h6, switch2, cls=TCLink, bw=10, delay='50ms', loss=1)

        self.addLink(router, switch, intfName1='r1-eth0', cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(router, switch2, intfName1='r1-eth1', cls=TCLink, bw=10, delay='50ms', loss=1)

def run_topo():
    project_dir = "/home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti"

    topo = QoSTopo()
    net = Mininet(topo=topo, link=TCLink, switch=OVSKernelSwitch, controller=None)
    net.start()
    info("[*] Starting network...\n")
    net.get('s1').cmd('ovs-vsctl set Bridge s1 fail_mode=standalone')
    net.get('s2').cmd('ovs-vsctl set Bridge s2 fail_mode=standalone')
    r1 = net.get('r1')

    # Ensure router's LAN IP is set correctly
    for i,iface in enumerate(['r1-eth0', 'r1-eth1']):
        r1.cmd(f"ip addr flush dev {iface}")
        r1.cmd(f"ip addr add 10.0.{i}.254/24 dev {iface}")
        r1.cmd(f"ip link set {iface} up")
        # Start CAKE on LAN-facing interface only
        r1.cmd(f"tc qdisc replace dev {iface} root cake bandwidth 10mbit diffserv8")

    r1.cmd("sysctl -w net.ipv4.ip_forward=1")
    info(r1.cmd("sysctl net.ipv4.ip_forward"))
    # net.pingAll()

    # Launch interactive terminals for classifier and QoS controller on r1
    info("[*] Launching classifier daemon in xterm...\n")
    r1.cmd("xterm -hold -e bash -c 'source {0}/.venv/bin/activate && python3 {0}/scripts/classification/classifier_daemon.py' &".format(project_dir))

    info("[*] Launching QoS controller in xterm...\n")
    r1.cmd("xterm -hold -e bash -c 'source {0}/.venv/bin/activate && python3 {0}/scripts/qos_controller.py' &".format(project_dir))

    # Start listening servers on hosts
    for i in range(1, 7):
        h = net.get(f'h{i}')
        ip_address = h.IP()
        h.cmd(f"sipp -sn uac {ip_address} -p 5060 &")
        h.cmd("python3 -m http.server 8080 &")
        h.cmd("iperf3 -s -p 5003 &")
        h.cmd("iperf3 -s -p 5010 &")

    info("[*] Starting traffic manager...\n")
    traffic_manager.start_traffic(net)
    print("[*] Ready. Use xterm h1 h2 h3 ... to interact. Start daemon on r1.")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_topo()
