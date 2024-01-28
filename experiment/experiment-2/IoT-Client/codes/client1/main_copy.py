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
    
    total_construction_time = 0.0

    for i in range(1):
        IoT_Info = dict()
        # Temperature
        cpu = CPUTemperature()    
        IoT_Info['Temperature'] = cpu.temperature
        # CPU & RAM usage
        IoT_Info['CPU_usage'] = psutil.cpu_percent()
        IoT_Info['RAM_usage'] = psutil.virtual_memory().percent

        Secret = json.dumps(IoT_Info).encode('utf-8')
        print(f'{i+1} th share construction')
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

        construction_time = (encrypt_end_time - start_time).total_seconds()
        total_construction_time += construction_time
        print("[Client] Shares construction cost： ", construction_time, "sec")

        # Classify the order of shares, send by 3 paths
        part_1 = lrss.classify_shares(lrss_share_list, 1)
        part_2 = lrss.classify_shares(lrss_share_list, 2)
        part_3 = lrss.classify_shares(lrss_share_list, 3)
        
        data_1 = json.dumps(part_1).encode('utf-8')
        data_2 = json.dumps(part_2).encode('utf-8')
        data_3 = json.dumps(part_3).encode('utf-8')

        data_list = []
        data_list += data_1
        data_list += data_2
        data_list += data_3

        recovered_secret = lrss.combine_lrShares(data_list)
        print('Recovered secret:', recovered_secret)