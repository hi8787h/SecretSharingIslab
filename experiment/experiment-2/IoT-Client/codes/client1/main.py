# Client
from LeakageResilientSecretSharing import LeakageResilientSecretSharing
import json
import datetime
import time
from SocketConnection import SocketConnection
from HashFunction import HashFunction
# Get temperature of IoT
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
    print('Secret :', Secret)
    print("[Client] Sending data size:", len(Secret), "bytes")

    # Hash
    print("[Client] Data SHA256: ", end =" ")
    HashFunction.print_sha256(Secret)

    # Secret sharing begins
    lrss = LeakageResilientSecretSharing()

    start_time =  datetime.datetime.now() 
    # Use leakage resilient algorithm on secret
    lrss_share_list = lrss.genarate_lrShares(Secret)
    encrypt_end_time =  datetime.datetime.now()
    print("[Client] Shares construction cost： ", (encrypt_end_time - start_time).total_seconds() ,"sec")

    # Classify the order of shares, send by 3 paths
    part_1 = lrss.classify_shares(lrss_share_list, 1)
    part_2 = lrss.classify_shares(lrss_share_list, 2)
    part_3 = lrss.classify_shares(lrss_share_list, 3)
    
    data_1 = json.dumps(part_1).encode('utf-8')
    data_2 = json.dumps(part_2).encode('utf-8')
    data_3 = json.dumps(part_3).encode('utf-8')

    print("[Client] Sending data to servers...")
    pause_time = 0.1
    SocketConnection.send_data("10.18.173.78", 10001, data_1)
    time.sleep(pause_time)
    SocketConnection.send_data("10.18.173.78", 10002, data_2)
    time.sleep(pause_time)
    SocketConnection.send_data("10.18.173.78", 10003, data_3)

    total_end_time = datetime.datetime.now() - datetime.timedelta(seconds = pause_time*2)
    print("[Client] Total time：", (total_end_time - start_time).total_seconds() ,"sec")