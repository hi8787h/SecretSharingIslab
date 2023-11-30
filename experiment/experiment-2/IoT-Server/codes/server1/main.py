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
        
        try : 
            part1 = json.loads(data1)
            data_list.append(part1)
            break
        except Exception:
            pass

        data2 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')

        try :
            part2 = json.loads(data2)
            data_list.append(part2)
            break
        except Exception:
            pass
        
        data3 = SocketConnection.receive_data(HOST,PORT).decode('utf-8')
        
        try : 
            part3 = json.loads(data3)
            data_list.append(part3)
            break
        except Exception:
            pass

        #sssbs = ShamirSecretSharingBytesStreamer()
        lrss = LeakageResilientSecretSharing()

        start_decryption_time =  datetime.datetime.now()

        #recover_data = sssbs.combine_shares(data)
        recovered_secret = lrss.leakage_resilient_recovery(data_list)

        end_decryption_time =  datetime.datetime.now()

        print("[Server] Data SHA256: ",end =" ")
        HashFunction.print_sha256(recovered_secret)

        print("[Server] Decryption time：", (end_decryption_time - start_decryption_time).total_seconds() ,"sec")