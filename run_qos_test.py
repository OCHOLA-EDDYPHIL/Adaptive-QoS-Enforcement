import time
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
from emulation.mininet_topo import LinuxRouter, QoSTopo  # Import topology definitions

def run():
    setLogLevel('info')
    topo = QoSTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.start()

    r1, h1, h2, h3 = net.get('r1'), net.get('h1'), net.get('h2'), net.get('h3')

    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr add 10.0.1.1/24 dev r1-eth0")
    r1.cmd("ip link set r1-eth0 up")

    # Start CAKE on each interface
    for iface in ['r1-eth0', 'r1-eth1', 'r1-eth2']:
        r1.cmd(f"tc qdisc replace dev {iface} root cake bandwidth 10mbit diffserv8")

    # Start classifier daemon
    info("[*] Starting classifier daemon in background on router...\n")
    daemon = "/home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/scripts/classifier_daemon.py"
    r1.cmd("source /home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/.venv/bin/activate")
    r1.cmd(f"python3 {daemon} &")

    # Launch simulated traffic
    info("[*] Launching test flows...\n")

    # VOIP: h1 → h3 (UDP)
    for i in range(4):
        h1.cmd("yes | nc -u 10.0.3.2 4000 &")
        time.sleep(0.2)

    # BULK: h2 → h3 (TCP)
    h1.cmd("iperf -s &")
    time.sleep(1)
    h2.cmd("iperf -c 10.0.1.2 -t 30 -P 1 &")

    # VIDEO: h2 → h3 (HTTP)
    h3.cmd("dd if=/dev/zero of=largefile bs=1M count=20")
    h3.cmd("python3 -m http.server 80 &")
    time.sleep(1)
    h2.cmd("wget --limit-rate=1M -O /dev/null http://10.0.3.2/largefile &")

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