# Server
import json
import datetime
from SocketConnection import SocketConnection
from HashFunction import HashFunction
from LeakageResilientSecretSharing import LeakageResilientSecretSharing
import threading
import socket

HOST = "0.0.0.0"
PORT = 80
data_list = []

def receive(data_list, index):
    try:
        data = SocketConnection.receive_data(HOST, PORT).decode('utf-8')
        part = json.loads(data)
        if len(data_list < 2):
            data_list += part
    except Exception as e:
        print(f"Error receiving data on thread {index}: {e}")

if __name__ == "__main__":
    while True:
        threads = []
        
        for i in range(1, 4):
            thread = threading.Thread(target=receive, args=(data_list, i))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()

        if len(data_list) < 2:
            print("Not enough data received")
            continue
        
        #sssbs = ShamirSecretSharingBytesStreamer()
        lrss = LeakageResilientSecretSharing()

        start_decryption_time = datetime.datetime.now()
        recovered_secret = lrss.combine_lrShares(data_list)
        end_decryption_time =  datetime.datetime.now()

        print("[Server] Data SHA256: ",end =" ")
        HashFunction.print_sha256(recovered_secret)

        print("[Server] Decryption time：", (end_decryption_time - start_decryption_time).total_seconds() ,"sec")