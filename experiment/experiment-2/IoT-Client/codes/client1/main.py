# Client
import os
from LeakageResilientSecretSharing import LeakageResilientSecretSharing
import json
import random
import datetime
import time
from SocketConnection import SocketConnection
from HashFunction import HashFunction
# Get temperature of IoT
import os
from gpiozero import CPUTemperature
import psutil

if __name__ == "__main__":
    
    IoT_Info = dict()
    # Temperature
    cpu = CPUTemperature()    
    IoT_Info['Temperature'] = cpu.temperature

    # CPU & RAM usage
    IoT_Info['CPU_usage'] = psutil.cpu_percent()
    IoT_Info['RAM_usage'] = psutil.virtual_memory().percent

    Secret = json.dumps(IoT_Info).encode('utf-8')

    print("[Client] Sending data size:", len(Secret), "bytes")

    # Hash
    print("[Client] Data SHA256: ", end =" ")
    HashFunction.print_sha256(Secret)

    # Secret sharing begins
    lrss = LeakageResilientSecretSharing()

    start_time =  datetime.datetime.now() 
    share_list = lrss.genarate_shares(2, 3, Secret)
    # Use leakage resilient algorithm on shares
    lrss_list = lrss.leakage_resilient(share_list)
    encrypt_end_time =  datetime.datetime.now()
    print("[Client] Encrypt time： ", (encrypt_end_time - start_time).total_seconds() ,"sec")

    # Shuffle the order of shares, send by 3 paths
    random.shuffle(lrss_list)
    lrss_list_length: int = len(lrss_list)
    lrss_list_part_length: int = lrss_list_length//3
    
    p1 = lrss_list[: lrss_list_part_length]
    p2 = lrss_list[lrss_list_part_length: 2*lrss_list_part_length]
    p3 = lrss_list[2*lrss_list_part_length: ]
    
    P1, P2, P3 = p1[0], p2[0], p3[0]
    part_1 = b"".join(P1)
    part_2 = b"".join(P2)
    part_3 = b"".join(P3)

    print("[Client] Sending data to servers...")
    pause_time = 0.1
    SocketConnection.send_data("10.18.173.78",10001, part_1)
    time.sleep(pause_time)
    SocketConnection.send_data("10.18.173.78",10002, part_2)
    time.sleep(pause_time)
    SocketConnection.send_data("10.18.173.78",10003, part_3)

    total_end_time = datetime.datetime.now() - datetime.timedelta(seconds=pause_time*2)
    print("[Client] Total time：", (total_end_time - start_time).total_seconds() ,"sec")