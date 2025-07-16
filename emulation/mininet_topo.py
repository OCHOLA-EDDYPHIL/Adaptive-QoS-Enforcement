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

        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
        h3 = self.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254')

        self.addLink(h1, switch, cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(h2, switch, cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(h3, switch, cls=TCLink, bw=10, delay='50ms', loss=1)
        self.addLink(router, switch, intfName1='r1-eth0', params1={'ip': '10.0.0.254/24'}, cls=TCLink, bw=10, delay='50ms', loss=1)

def run_topo():
    topo = QoSTopo()
    net = Mininet(topo=topo, link=TCLink, switch=OVSKernelSwitch, controller=None)
    net.start()
    net.pingAll()
    r1 = net.get('r1')

    # Ensure router's LAN IP is set correctly
    # r1.cmd("ip addr flush dev r1-eth0")
    # r1.cmd("ip addr add 10.0.0.254/24 dev r1-eth0")
    # r1.cmd("ip link set r1-eth0 up")
    # r1.cmd("sysctl -w net.ipv4.ip_forward=1")

    info(r1.cmd("sysctl net.ipv4.ip_forward"))
    # Start CAKE on LAN-facing interface only
    r1.cmd("tc qdisc replace dev r1-eth0 root cake bandwidth 10mbit diffserv8")

    # Start classifier daemon
    info("[*] Starting classifier daemon in background on router...\n")
    r1.cmd(f"source /home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/.venv/bin/activate")
    r1.cmd(f"python3 /home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/scripts/classification/classifier_daemon.py &")
    for i in range(1, 4):
        h = net.get(f'h{i}')
        h.cmd(f"source /home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/.venv/bin/activate")


    # Start QoS controller
    info("[*] Starting QoS controller in background on router...\n")
    qos_controller = f"/home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/scripts/qos_controller.py"
    # r1.cmd(f"python3 {qos_controller} &")

    print("[*] Ready. Use xterm h1 h2 h3 to interact. Start daemon on r1.")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_topo()
