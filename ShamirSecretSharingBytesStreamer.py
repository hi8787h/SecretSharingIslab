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
        self.chuncks_number_remainder = 0
        self.chuncks_number =  0
        self.data_chunk_list = []
        self.shares_list = []
        #For decrypt
        self.chunks_shares_ciphertext = dict()
        
    # Encrypt
    def zero_byte_padding(self,data:bytes)->bytes:
        data_length_diff:int = 16 - len(data)
        for i in range(data_length_diff):
            data += b'\0'
        return data
    
    def split_data(self)->list:
        sqeuence_start = 0
        sqeuence_end = 16
        for i in range(self.chuncks_number):
            data_chunk:bytes = data[sqeuence_start:sqeuence_end]
            data_chunk = self.zero_byte_padding(data_chunk) if len(data_chunk) < 16 else data_chunk
            self.data_chunk_list.append(data_chunk)
            sqeuence_start += 16
            sqeuence_end += 16
            
    def genarate_shares(self, k:int, n:int, data:bytes)->list:
        self.data = data
        self.message_length = len(self.data)
        self.chuncks_number_remainder = self.message_length % 16
        self.chuncks_number =  self.message_length//16 if self.chuncks_number_remainder == 0 else self.message_length//16+1
        self.split_data()
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
    def save_chunk_shares(self, chunk_id:int, share_id:int,share_data_base64:str):
        share_data_bytes = base64.b64decode(share_data_base64.encode("utf-8"))
        self.chunks_shares_ciphertext[chunk_id].append((share_id,share_data_bytes))
        
    def collect_chunks(self, data_list:list):
        chunk_id_list = []
        for data in data_list:
            if data['ChunkID'] not in chunk_id_list:
                chunk_id_list.append(data['ChunkID'])
                self.chunks_shares_ciphertext[data['ChunkID']] = []
            self.save_chunk_shares(data['ChunkID'], data['ShareIndex'],data['ShareData'])
            
    def combine_chunks(self)->bytes:
        result_padding = bytes()
        padding_null_bytes_number:int = 0
        for chunk_ciphertext_index in sssb.chunks_shares_ciphertext:
            chunk_result = Shamir.combine(sssb.chunks_shares_ciphertext[chunk_ciphertext_index])
            result_padding += chunk_result        
        for i in reversed(range(len(result_padding))):
            if result_padding[i] == 0 :
                padding_null_bytes_number += 1
            else:
                break
        result = result_padding[:-padding_null_bytes_number]
        return result
            
    def combine_shares(self, data_list:list)->bytes:
        self.collect_chunks(data_list)
        result = self.combine_chunks()
        return result