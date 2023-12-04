# Server
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer
import json
import datetime
import time
from SocketConnection import SocketConnection
from HashFunction import HashFunction
from LeakageResilientSecretSharing import LeakageResilientSecretSharing

HOST = "0.0.0.0"
PORT = 80

if __name__ == "__main__":
    while True:
        data_list = []
        received_data_count = 0
        
        try:
            data1 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
            part1 = json.loads(data1)
            print("data 1 received.")
            data_list.append(part1)
            received_data_count += 1
        except Exception:
            pass

        try:
            data2 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
            part2 = json.loads(data2)
            print("data 2 received.")
            data_list.append(part2)
            received_data_count += 1
        except Exception:
            pass

        try:
            data3 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
            part3 = json.loads(data3)
            print("data 3 received.")
            data_list.append(part3)
            received_data_count += 1
        except Exception:
            pass
        
        # Check combined data
        print('Received:', data_list)

         # If not received enough data to recover secret 
        if received_data_count < 2 :
            print("No enough data to recover the secret !")
            continue
        
        #sssbs = ShamirSecretSharingBytesStreamer()
        lrss = LeakageResilientSecretSharing()

        start_decryption_time = datetime.datetime.now()
        recovered_secret = lrss.leakage_resilient_recovery(data_list)
        end_decryption_time =  datetime.datetime.now()

        print("[Server] Data SHA256: ",end =" ")
        HashFunction.print_sha256(recovered_secret)

        print("[Server] Decryption time：", (end_decryption_time - start_decryption_time).total_seconds() ,"sec")