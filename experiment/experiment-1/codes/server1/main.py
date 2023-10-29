# Server
import socket
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer
import json
import datetime
import time

HOST = "0.0.0.0"
PORT = 80

def receive_data():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        data = bytes()
        with conn:
            print(f"[Server] Client IP: {addr}")
            while True:
                temp_data = conn.recv(1024)
                data += temp_data
                if not temp_data:
                    break
        print("[Server] Data length: ", len(data))
        return data

if __name__ == "__main__":
    while True:
        data1 = receive_data().decode('utf-8')
        part1 = json.loads(data1)

        data2 = receive_data().decode('utf-8')
        part2 = json.loads(data2)

        data3 = receive_data().decode('utf-8')
        part3 = json.loads(data3)

        data = part1 + part2 + part3

        sssbs = ShamirSecretSharingBytesStreamer()
        
        start_decryption_time =  datetime.datetime.now()
        recover_text = sssbs.combine_shares(data)
        end_decryption_time =  datetime.datetime.now()

        # print(recover_text)
        print("Decryption time：", (end_decryption_time - start_decryption_time).total_seconds() ,"sec")