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
    
    part_1 = lrss_list[: lrss_list_part_length]
    part_2 = lrss_list[lrss_list_part_length: 2*lrss_list_part_length]
    part_3 = lrss_list[2*lrss_list_part_length: ]
    
    #test output
    P1 = part_1[0]
    print(P1)
    print(len(P1))
    print('part1[0]: ', type(P1[0]), '\npart1[1]: ', type(P1[1]), '\npart1[2]: ', type(P1[2]))
    
    P2 = part_2[0]
    print(P2)
    print(len(P2))
    print('part2[0]: ', type(P2[0]), '\npart2[1]: ', type(P2[1]), '\npart2[2]: ', type(P2[2]))

    
    P3 = part_3[0]
    print(P3)
    print(len(P3))
    print('part3[0]: ', type(P3[0]), '\npart3[1]: ', type(P3[1]), '\npart3[2]: ', type(P3[2]))

    cipher_bytes_1 = json.dumps(P1).encode('utf-8')
    cipher_bytes_2 = json.dumps(P2).encode('utf-8')
    cipher_bytes_3 = json.dumps(P3).encode('utf-8')

    # Check shares
    print("part_1: ", cipher_bytes_1)
    print("part_2: ", cipher_bytes_2)
    print("part_3: ", cipher_bytes_3)

    print("[Client] Sending data to servers...")
    pause_time = 0.1
    SocketConnection.send_data("10.18.173.78",10001,cipher_bytes_1)
    time.sleep(pause_time)
    SocketConnection.send_data("10.18.173.78",10002,cipher_bytes_2)
    time.sleep(pause_time)
    SocketConnection.send_data("10.18.173.78",10003,cipher_bytes_3)

    total_end_time = datetime.datetime.now() - datetime.timedelta(seconds=pause_time*2)
    print("[Client] Total time：", (total_end_time - start_time).total_seconds() ,"sec")