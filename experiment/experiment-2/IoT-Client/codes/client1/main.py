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
import subprocess

if __name__ == "__main__":
    datasize_mb = int(input("[Client] Data Size MB: "))
    data_byte_size = 1024 * datasize_mb
    print("[Client] Sending data size:", data_byte_size, "bytes")

    # Add temperature into the first N bytes of data
    temp_bytes = bytes()

    CheckTemp = subprocess.run(['vcgencmd', 'measure_temp'], capture_output=True, text=True)
    if CheckTemp.returncode == 0:
        t = CheckTemp.stdout.strip()
        temp_str = t.split('=')[1].split("'")[0]

        temp_int = round(float(temp_str))
        temp_bin = bin(temp_int)
        temp_bytes = temp_bin[2:].encode('utf-8')

    else:
        print(f"error: {CheckTemp.stderr}")

    data = temp_bytes + os.urandom(data_byte_size - len(temp_bytes))

    # Hash
    print("[Client] Data SHA256: ", end =" ")
    HashFunction.print_sha256(data)

    # Secret sharing begins
    lrss = LeakageResilientSecretSharing()

    start_time =  datetime.datetime.now() 
    share_list = lrss.genarate_shares(2, 3, data)
    # Use leakage resilient algorithm on shares
    lrss_list = lrss.leakage_resilient(share_list)
    encrypt_end_time =  datetime.datetime.now()
    print("[Client] Encrypt time： ", (encrypt_end_time - start_time).total_seconds() ,"sec")

    # Shuffle the order of shares, send by 3 paths
    random.shuffle(lrss_list)
    lrss_list_length: int = len(lrss_list)
    lrss_list_part_length: int = lrss_list_length//3 + 1
    
    part_1 = lrss_list[: lrss_list_part_length]
    part_2 = lrss_list[lrss_list_part_length: 2 * lrss_list_part_length]
    part_3 = lrss_list[2 * lrss_list_part_length: ]

    cipher_bytes_1 = json.dumps(part_1).encode('utf-8')
    cipher_bytes_2 = json.dumps(part_2).encode('utf-8')
    cipher_bytes_3 = json.dumps(part_3).encode('utf-8')

    print("[Client] Sending data to servers...")
    pause_time = 0.1
    SocketConnection.send_data("10.18.173.78",10001,cipher_bytes_1)
    time.sleep(pause_time)
    SocketConnection.send_data("10.18.173.78",10002,cipher_bytes_2)
    time.sleep(pause_time)
    SocketConnection.send_data("10.18.173.78",10003,cipher_bytes_3)

    total_end_time = datetime.datetime.now() - datetime.timedelta(seconds=pause_time*2)
    print("[Client] Total time：", (total_end_time - start_time).total_seconds() ,"sec")