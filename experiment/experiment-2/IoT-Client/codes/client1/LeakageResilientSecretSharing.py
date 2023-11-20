from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import base64
import json
import random

import ShamirSecretSharingBytesStreamer

class LeakageResilientSecretSharing(ShamirSecretSharingBytesStreamer):
        """
        Leakage Resilient Secret Sharing
        Author: NCYU ISlab
        This class inherits from ShamirSecretSharingBytesStreamer.
        That will improve secure of system!
        """

        def __init__(self):
                super().__init__(self)
                
                #For encrypt
                self.data = bytes()
                self.message_length = 0
                self.data_chunk_list = []
                self.shares_list = []
                
                #For decrypt
                self.chunks_shares_ciphertext = dict()

        #set parameters s, r, w
        def chosing_para(self):
                bin_len = 128
                n = 3
                w = [] 

                s = random.choices("01",k=bin_len)
                #test
                print(s)
                
                r = random.choices("01",k=bin_len)
                #test
                print(r)
                
                for i in range(n):
                        w.append(random.choices("01",k=bin_len)) 
                        #test
                        print(w[i])

        #LRshare
        
        #LRrecover

if __name__ == "__main__":
        pass