# Client
import os
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer
import json
import random
import datetime
import time
from SocketConnection import SocketConnection
from HashFunction import HashFunction

if __name__ == "__main__":
    datasize_mb = int(input("[Client] Data Size MB: "))
    data_byte_size = 1024*datasize_mb
    print("[Client] Sending data size:", data_byte_size, "bytes")
    data = os.urandom(data_byte_size)

    print("[Client] Data SHA256: ",end =" ")
    HashFunction.print_sha256(data)

    sssbs = ShamirSecretSharingBytesStreamer()

    start_time =  datetime.datetime.now() 
    cipher_list = sssbs.genarate_shares(2,4,data)
    encrypt_end_time =  datetime.datetime.now()
    print("[Client] Encrypt time：", (encrypt_end_time - start_time).total_seconds() ,"sec")

    random.shuffle(cipher_list)
    cipher_list_length:int = len(cipher_list)
    cipher_list_part_length:int = cipher_list_length//3 +1
    
    part_1 = cipher_list[:cipher_list_part_length]
    part_2 = cipher_list[cipher_list_part_length:2*cipher_list_part_length]
    part_3 = cipher_list[2*cipher_list_part_length:]

    cipher_bytes_1 = json.dumps(part_1).encode('utf-8')
    cipher_bytes_2 = json.dumps(part_2).encode('utf-8')
    cipher_bytes_3 = json.dumps(part_3).encode('utf-8')

    print("[Client] Sending data to servers...")
    pause_time = 0.1
    SocketConnection.send_data("10.5.1.1",80,cipher_bytes_1)
    time.sleep(pause_time)
    SocketConnection.send_data("10.5.1.2",80,cipher_bytes_2)
    time.sleep(pause_time)
    SocketConnection.send_data("10.5.1.3",80,cipher_bytes_3)

    total_end_time = datetime.datetime.now() - datetime.timedelta(seconds=pause_time*2)
    print("[Client] Total time：", (total_end_time - start_time).total_seconds() ,"sec")