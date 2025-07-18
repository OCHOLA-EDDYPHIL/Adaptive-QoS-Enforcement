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

traffic_types = [voip_call, video_stream, video_call, bulk_transfer]

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

#  generator with time check
def generate_random_traffic(net, stop_time):
    while time.time() < stop_time:
        src, dst = get_random_host_pair(net)
        traffic_func = random.choice(traffic_types)
        traffic_func(src, dst.IP())
        time.sleep(random.uniform(2, 5))
    print(f"[+] Traffic thread exiting at {time.strftime('%X')}")

# === Entry Point Called from Topology ===
def start_traffic(net, threads=5, duration=30):
    print(f"[*] Starting traffic for {duration} seconds...")
    stop_time = time.time() + duration
    thread_list = []

    for _ in range(threads):
        t = threading.Thread(target=generate_random_traffic, args=(net, stop_time))
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    print("[*] Traffic generation complete.")
