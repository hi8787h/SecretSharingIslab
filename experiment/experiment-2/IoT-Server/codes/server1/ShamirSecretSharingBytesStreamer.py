from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import base64
import json

class ShamirSecretSharingBytesStreamer:
    """
    Shamir secret sharing bytes streamer
    Author: NCYU ISlab
    This class is used to encrypt and decrypt data using Shamir secret sharing.
    It is based on PyCryptodome library SecretSharing, but support longer data for encrypt and decrypt.
    """
    def __init__(self):
        #For encrypt
        self.data = bytes()
        self.message_length = 0
        self.data_chunk_list = []
        self.shares_list = []
        #For decrypt
        self.chunks_shares_ciphertext = dict()
        
    # Encrypt
    def zero_byte_padding(self,data:bytes)->bytes:
        while len(data)%16 != 0:
            data = b'\x00' + data
        return data
    
    def split_data(self, data:bytes)->list:
        sqeuence_start = 0
        sqeuence_end = 16
        data = self.zero_byte_padding(data)
        for i in range(len(data)//16):
            data_chunk:bytes = data[sqeuence_start:sqeuence_end]
            self.data_chunk_list.append(data_chunk)
            sqeuence_start += 16
            sqeuence_end += 16
            
    def genarate_shares(self, k:int, n:int, data:bytes)->list:
        self.data = data
        self.message_length = len(self.data)
        self.split_data(data)
        shares_number = len(self.data_chunk_list)
        chunk_id = 1
        for data_chunk in self.data_chunk_list:
            shares = Shamir.split(k, n, data_chunk)
            for share in shares:
                share_dict = dict()
                share_index = share[0] 
                share_data = base64.b64encode(share[1]).decode('utf-8')
                share_dict = {
                    "ChunkID": chunk_id,
                    "ShareIndex": share_index,
                    "ShareData": share_data
                }
                self.shares_list.append(share_dict)
            chunk_id += 1
        return self.shares_list

    # Decrypt
    def count_chunks_amount(self)->int:
        # Count chunks number from self.chunks_shares_ciphertext
        chunks_number = 0
        for chunk_id in self.chunks_shares_ciphertext:
            chunks_number += 1
        # Check All chunk exist
        for i in range(1,chunks_number+1):
            if i not in self.chunks_shares_ciphertext:
                raise Exception("Chunk " + str(i) + " not exist")
        return chunks_number

    def save_chunk_shares(self, chunk_id:int, share_id:int,share_data_base64:str):
        share_data_bytes = base64.b64decode(share_data_base64.encode("utf-8"))
        self.chunks_shares_ciphertext[chunk_id].append((share_id,share_data_bytes))
        
    def collect_chunks(self, data_list:list):
        chunk_id_list = []
        for data in data_list:
            #check output
            print('data:', data)

            if data['ChunkID'] not in chunk_id_list:
                chunk_id_list.append(data['ChunkID'])
                self.chunks_shares_ciphertext[data['ChunkID']] = []
            self.save_chunk_shares(data['ChunkID'], data['ShareIndex'],data['ShareData'])
            
    def combine_chunks(self)->bytes:
        result = bytes()
        padding_null_bytes_number:int = 0
        #Count and check chunks number
        chunk_number    = self.count_chunks_amount()
        for i in range(1,chunk_number+1):
            chunk_result = Shamir.combine(self.chunks_shares_ciphertext[i])
            result += chunk_result
        return result
            
    def remove_zero_padding(self,data:bytes)->bytes:
        # Remove header zero padding of bytes
        zero_padding_number = 0
        for i in range(len(data)):
            if data[i] == 0:
                zero_padding_number += 1
            else:
                break
        return data[zero_padding_number:]

    def combine_shares(self, data_list:list)->bytes:
        self.collect_chunks(data_list)
        result = self.combine_chunks()
        result = self.remove_zero_padding(result)
        return result

if __name__ == "__main__":
    pass