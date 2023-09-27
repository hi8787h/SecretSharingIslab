# Client
import socket
import os
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer
import json
import random
import datetime
import time

def send_data(host:str, port:int, data:bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(data)

if __name__ == "__main__":
    data_byte_size = 1024*20
    print("Sending data size:", data_byte_size, "bytes")
    data = os.urandom(data_byte_size)
    sssbs = ShamirSecretSharingBytesStreamer()

    start_time =  datetime.datetime.now() 
    cipher_list = sssbs.genarate_shares(2,4,data)
    encrypt_end_time =  datetime.datetime.now()
    print("Encrypt time：", (encrypt_end_time - start_time).total_seconds() ,"sec")

    random.shuffle(cipher_list)
    cipher_list_length:int = len(cipher_list)
    cipher_list_part_length:int = cipher_list_length//3 +1
    
    part_1 = cipher_list[:cipher_list_part_length]
    part_2 = cipher_list[cipher_list_part_length:2*cipher_list_part_length]
    part_3 = cipher_list[2*cipher_list_part_length:]

    cipher_bytes_1 = json.dumps(part_1).encode('utf-8')
    cipher_bytes_2 = json.dumps(part_2).encode('utf-8')
    cipher_bytes_3 = json.dumps(part_3).encode('utf-8')

    send_data("10.5.1.1",80,cipher_bytes_1)
    time.sleep(0.00005)
    send_data("10.5.1.2",80,cipher_bytes_2)
    time.sleep(0.00005)
    send_data("10.5.1.3",80,cipher_bytes_3)

    total_end_time = datetime.datetime.now() - datetime.timedelta(seconds=0.0001)
    print("Total time：", (total_end_time - start_time).total_seconds() ,"sec")