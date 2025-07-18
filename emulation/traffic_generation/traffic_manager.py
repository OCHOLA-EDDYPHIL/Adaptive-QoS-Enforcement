import random
import threading
import time


# Traffic functions
def voip_call(src, dst_ip):
    port = random.randint(5060, 5090)
    print(f"[VOIP] {src.name} -> {dst_ip}:{port}")
    src.popen(f"yes | nc -u {dst_ip} {port} &")
    src.popen(f"sipp -sn uac {dst_ip}:{port} -p {port} -m 1 &")

def video_stream(src, dst_ip):
    print(f"[VIDEO] {src.name} streaming from {dst_ip}")
    src.popen(f"wget http://{dst_ip}:8080/largefile -O /dev/null &")

def video_call(src, dst_ip):
    port = 5010
    print(f"[VIDEO CALL] {src.name} -> {dst_ip}:{port}")
    src.popen(f"iperf3 -c {dst_ip} -u -b 3M -t 20 -p {port} &")

def bulk_transfer(src, dst_ip):
    port = 5003
    print(f"[BULK] {src.name} -> {dst_ip}:{port}")
    src.popen(f"iperf3 -c {dst_ip} -p {port} -t 20 &")
    src.popen(f"rsync largefile {dst_ip}:/dev/null &")

# All traffic types
traffic_types = [voip_call, video_stream, video_call, bulk_transfer]

# Subnet-aware selection
def get_random_host_pair(net):
    group1 = [net.get(f"h{i}") for i in range(1, 4)]    # 10.0.0.1-3
    group2 = [net.get(f"h{i}") for i in range(4, 7)]    # 10.0.1.1-3

    if random.random() > 0.5:
        src = random.choice(group1)
        dst = random.choice(group2)
    else:
        src = random.choice(group2)
        dst = random.choice(group1)
    return src, dst

# Traffic generator loop
def generate_random_traffic(net):
    while True:
        src, dst = get_random_host_pair(net)
        traffic_func = random.choice(traffic_types)
        traffic_func(src, dst.IP())
        time.sleep(random.uniform(2, 5))


# === Entry Point Called from Topology ===
def start_traffic(net, threads=5):
    print("[*] Starting traffic generation...")
    for _ in range(threads):
        t = threading.Thread(target=generate_random_traffic, args=(net,))
        t.daemon = True
        t.start()
    print("[*] Traffic manager running in background.")