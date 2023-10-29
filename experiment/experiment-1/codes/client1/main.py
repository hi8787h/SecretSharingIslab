# Client
import socket
import os
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer
import json
import random
import datetime
import time
#gzip
import gzip

def send_data(host:str, port:int, data:bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(data)

if __name__ == "__main__":
    os.system("clear")
    data_byte_size = 1024*int(input("Data size MB: "))
    print("Sending data size:", data_byte_size, "bytes")
    data = os.urandom(data_byte_size)
    sssbs = ShamirSecretSharingBytesStreamer()

    start_time =  datetime.datetime.now() 
    cipher_list = sssbs.genarate_shares(2,4,data)
    encrypt_end_time =  datetime.datetime.now()
    print("Encrypt time：", (encrypt_end_time - start_time).total_seconds() ,"sec")

    random.shuffle(cipher_list)
    cipher_list_length:int = len(cipher_list)
    cipher_list_part_length:int = cipher_list_length//5 +1

    part_1 = cipher_list[:cipher_list_part_length]
    part_2 = cipher_list[cipher_list_part_length: 2*cipher_list_part_length]
    part_3 = cipher_list[2*cipher_list_part_length: 3*cipher_list_part_length]
    part_4 = cipher_list[3*cipher_list_part_length: 4*cipher_list_part_length]
    part_5 = cipher_list[4*cipher_list_part_length:]

    cipher_bytes_1 = json.dumps(part_1).encode('utf-8')
    cipher_bytes_2 = json.dumps(part_2).encode('utf-8')
    cipher_bytes_3 = json.dumps(part_3).encode('utf-8')
    cipher_bytes_4 = json.dumps(part_4).encode('utf-8')
    cipher_bytes_5 = json.dumps(part_5).encode('utf-8')

    cb_gzip1 = gzip.compress(cipher_bytes_1)
    cb_gzip2 = gzip.compress(cipher_bytes_2)
    cb_gzip3 = gzip.compress(cipher_bytes_3)
    cb_gzip4 = gzip.compress(cipher_bytes_4)
    cb_gzip5 = gzip.compress(cipher_bytes_5)

    send_data("10.5.1.1",80,cb_gzip1)
    time.sleep(0.01)
    send_data("10.5.1.2",80,cb_gzip2)
    time.sleep(0.01)
    send_data("10.5.1.3",80,cb_gzip3)
    time.sleep(0.01)
    send_data("10.5.1.1",80,cb_gzip4)
    time.sleep(0.01)
    send_data("10.5.1.2",80,cb_gzip5)

    print("Cipher data size bytes:", len(cb_gzip1) + len(cb_gzip2) + len(cb_gzip3) + len(cb_gzip4) + len(cb_gzip5))

    total_end_time = datetime.datetime.now() - datetime.timedelta(seconds=0.04)
    print("Total time：", (total_end_time - start_time).total_seconds() ,"sec")
