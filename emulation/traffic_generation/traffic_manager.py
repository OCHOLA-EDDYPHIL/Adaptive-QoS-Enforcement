#!/usr/bin/env python3
import subprocess
import threading
import random
import time

def run_voip_calls():
    while True:
        port = random.randint(5060, 5090)
        print(f"[VOIP] New call on port {port}")
        subprocess.Popen(["sipp", "-sn", "uac", "10.0.0.3", "-p", str(port), "-m", "1"])
        time.sleep(random.uniform(5, 15))

def run_video_streaming():
    while True:
        print("[VIDEO] Streaming video...")
        subprocess.Popen(["wget", "http://10.0.0.3:8080/bigvideo.mp4", "-O", "/dev/null"])
        time.sleep(random.uniform(10, 20))

def run_video_call():
    while True:
        print("[VIDEO CALL] Simulating call...")
        subprocess.Popen(["iperf3", "-c", "10.0.0.3", "-u", "-b", "3M", "-t", "30", "-p", "5010"])
        time.sleep(random.uniform(15, 30))

def run_bulk_transfer():
    while True:
        print("[BULK] Starting rsync + iperf...")
        subprocess.Popen(["rsync", "bigfile.dat", "user@10.0.0.3:/dev/null"])
        subprocess.Popen(["iperf3", "-c", "10.0.0.3", "-p", "5003", "-t", "60"])
        time.sleep(random.uniform(20, 40))

if __name__ == "__main__":
    threading.Thread(target=run_voip_calls).start()
    threading.Thread(target=run_video_streaming).start()
    threading.Thread(target=run_video_call).start()
    threading.Thread(target=run_bulk_transfer).start()
