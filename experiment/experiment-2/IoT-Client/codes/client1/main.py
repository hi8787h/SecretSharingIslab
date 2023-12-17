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
    print('Secret:', Secret)
    print("[Client] Sending data size:", len(Secret), "bytes")

    # Hash
    print("[Client] Data SHA256: ", end =" ")
    HashFunction.print_sha256(Secret)

    # Secret sharing begins
    lrss = LeakageResilientSecretSharing()

    start_time =  datetime.datetime.now() 
    # Use leakage resilient algorithm on secret
    lrss_share_list = lrss.genarate_lrShares(Secret)
    # test output
    print('share_list', lrss_share_list)
    encrypt_end_time =  datetime.datetime.now()
    print("[Client] Encrypt time： ", (encrypt_end_time - start_time).total_seconds() ,"sec")

    # Shuffle the order of shares, send by 3 paths
    part_1 = lrss.shuffle_shares(lrss_share_list, 1)
    part_2 = lrss.shuffle_shares(lrss_share_list, 2)
    part_3 = lrss.shuffle_shares(lrss_share_list, 3)

    #recovered_secret = lrss.combine_lrShares(part_1 + part_2)
    #print('recovered_secret:', recovered_secret)
    
    #cipher_bytes_1 = json.dumps(part_1).encode('utf-8')
    #cipher_bytes_2 = json.dumps(part_2).encode('utf-8')
    #cipher_bytes_3 = json.dumps(part_3).encode('utf-8')

    #print("[Client] Sending data to servers...")
    #pause_time = 0.1
    #SocketConnection.send_data("10.18.173.78", 10001, cipher_bytes_1)
    #time.sleep(pause_time)
    #SocketConnection.send_data("10.18.173.78", 10002, cipher_bytes_2)
    #time.sleep(pause_time)
    #SocketConnection.send_data("10.18.173.78", 10003, cipher_bytes_3)

    #total_end_time = datetime.datetime.now() - datetime.timedelta(seconds = pause_time*2)
    #print("[Client] Total time：", (total_end_time - start_time).total_seconds() ,"sec")