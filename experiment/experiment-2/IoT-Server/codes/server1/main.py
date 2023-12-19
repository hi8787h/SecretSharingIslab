# Server
import json
import datetime
from SocketConnection import SocketConnection
from HashFunction import HashFunction
from LeakageResilientSecretSharing import LeakageResilientSecretSharing

HOST = "0.0.0.0"
PORT = 80

if __name__ == "__main__":
    while True:
        received_data_count = 0
        data_list = []
        
        data1 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
        part1 = json.loads(data1)
        data_list += part1
        received_data_count += 1

        data2 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
        part2 = json.loads(data2)
        data_list += part2
        received_data_count += 1

        data3 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
        part3 = json.loads(data3)
        if received_data_count < 2:
            data_list += part3
            received_data_count += 1

         # If not received enough data to recover secret 
        if received_data_count < 2 :
            print("No enough data to recover the secret !")
            continue
        
        #sssbs = ShamirSecretSharingBytesStreamer()
        lrss = LeakageResilientSecretSharing()

        start_decryption_time = datetime.datetime.now()

        recovered_secret = lrss.combine_lrShares(data_list)
        end_decryption_time =  datetime.datetime.now()

        print("[Server] Data SHA256: ",end =" ")
        HashFunction.print_sha256(recovered_secret)

        print("[Server] Decryption time：", (end_decryption_time - start_decryption_time).total_seconds() ,"sec")

        if received_data_count >= 2:
            break