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
        
        data1 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
        # test
        print(data1)
        part1 = json.loads(data1)

        data2 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
        # test
        print(data2)
        part2 = json.loads(data2)
        
        data3 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
        # test
        print(data3)
        part3 = json.loads(data3)

        data_list.append([part1, part2, part3])
        
        # Check combined data
        print(data_list)
        
        #sssbs = ShamirSecretSharingBytesStreamer()
        lrss = LeakageResilientSecretSharing()

        start_decryption_time = datetime.datetime.now()

        #recover_data = sssbs.combine_shares(data)
        recovered_secret = lrss.leakage_resilient_recovery(data_list)

        end_decryption_time =  datetime.datetime.now()

        print("[Server] Data SHA256: ",end =" ")
        HashFunction.print_sha256(recovered_secret)

        print("[Server] Decryption time：", (end_decryption_time - start_decryption_time).total_seconds() ,"sec")