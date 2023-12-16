import random
import json
import base64
from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir

class LeakageResilientSecretSharing():
        """
        Leakage Resilient Secret Sharing
        Author: NCYU ISlab
        This class can implement encryption & decryption using Shamir Secret Sharing with leakage resilient.
        That will improve secure of system!
        """
        def __init__(self):
                self.bin_len = 128
                self.modulus = 2 ** self.bin_len
                self.k = 2
                self.n = 3
                # For encrypt
                self.data_chunk_list = []
                self.shares_list = []
                # For decrypt
                self.share_chunk = dict()
                self.sr_chunk = dict()

        def set_s(self):
                s = random.choices("01", k=self.bin_len*3)
                combined_s = ''.join(s).encode('utf-8')

                return combined_s
        
        def set_r(self):
                r = random.choices("01", k=self.bin_len)
                combined_r = ''.join(r).encode('utf-8')

                return combined_r
        
        def set_w(self):
                w = random.choices("01", k=self.bin_len*3)
                combined_w = ''.join(w).encode('utf-8')

                return combined_w
        
        def get_inner_product(self, byte1: bytes, byte2: bytes) -> bytes:          
                # Change datatype from bytes to int, and compute inner product
                int_1 = int.from_bytes(byte1, byteorder='big')
                int_2 = int.from_bytes(byte2, byteorder='big')

                inner_product = int_1 * int_2
                inner_mod = inner_product % self.modulus

                inner_bin = bin(inner_mod)[2: ].zfill(128)
                inner_byte = bytes(inner_bin, 'utf-8')

                return inner_byte
        
        def xor(self, byte1: bytes, byte2: bytes) -> bytes :
                xor_bytes = bytes(x^y for x,y in zip(byte1, byte2))

                return xor_bytes
        
        def zero_byte_padding(self, data: bytes) -> bytes:
                while len(data) % 16 != 0:
                        data = b'\x00' + data
                return data
        
        def split_data(self, data: bytes) -> list:
                sqeuence_start = 0
                sqeuence_end = 16
                split_list = []
                data = self.zero_byte_padding(data)
                for i in range(len(data) // 16):
                        data_chunk: bytes = data[sqeuence_start: sqeuence_end]
                        split_list.append(data_chunk)
                        sqeuence_start += 16
                        sqeuence_end += 16

                return split_list
        
        def get_new_shares(self, w: bytes, priXr: bytes, sr_part: bytes) -> str:
                new_share = dict()
                new_share = {
                        "w": w, 
                        "sh_pri_X_r": priXr, 
                        "sr_share": sr_part
                }
                new_share_str = json.dumps(new_share)

                return new_share_str
        
        def shuffle_shares(self, sharelist: list, index: int) -> list:
                modified_list = []
                for share in sharelist:
                        if share['ShareIndex'] == index :
                                modified_list.append(share)

                return modified_list
        
        def generate_sr_shares(self, data: bytes) -> list:
                sr_list = []
                sr_chunklist = self.split_data(data)
                chunk_id = 1
                for sr_chunk in sr_chunklist:
                        sr_shares = Shamir.split(self.k, self.n, sr_chunk)
                        for share in sr_shares:
                                share_dict = dict()
                                share_index = share[0] 
                                share_data = base64.b64encode(share[1]).decode('utf-8')
                                share_dict = {
                                "ChunkID": chunk_id,
                                "ShareIndex": share_index,
                                "ShareData": share_data
                                }
                                sr_list.append(share_dict)
                        chunk_id += 1

                return sr_list
        
        def genarate_lrShares(self, data: bytes)->list:
                self.split_data(data)
                chunk_id = 1

                # For each chunk
                for data_chunk in self.data_chunk_list:
                        # set parameters
                        shared_s = self.set_s()
                        shared_r = self.set_r()
                        shared_sr = shared_s + shared_r
                        shared_sr_list = self.generate_sr_shares(shared_sr)
                        # turn sr_shares into bytes
                        shared_sr_part1 = self.shuffle_shares(shared_sr_list, 1)
                        shared_sr_part2 = self.shuffle_shares(shared_sr_list, 2)
                        shared_sr_part3 = self.shuffle_shares(shared_sr_list, 3)
                        shared_sr_bytes1 = json.dumps(shared_sr_part1).encode('utf-8')
                        shared_sr_bytes2 = json.dumps(shared_sr_part2).encode('utf-8')
                        shared_sr_bytes3 = json.dumps(shared_sr_part3).encode('utf-8')

                        share_sr_bytes = [shared_sr_bytes1, shared_sr_bytes2, shared_sr_bytes3]

                        shared_w_list = []
                        for i in range(self.n):
                                shared_w = self.set_w()
                                shared_w_list.append(shared_w)

                        shared_Ext_list = []
                        for i in range(self.n):
                                shared_Ext = self.get_inner_product(shared_w_list[i], shared_s)
                                shared_Ext_list.append(shared_Ext)

                        # split into 3 shares
                        shares = Shamir.split(self.k, self.n, data_chunk)
                        # test output
                        print('shares split by Shamir:', shares)
                        index = 0
                        
                        for share in shares:
                                share_dict = dict()
                                share_index = share[0] 
                                #share_data = base64.b64encode(share[1]).decode('utf-8')
                                share_data = base64.b64encode(share[1])
                                # use leakage resilient on share_data
                                share_data_pri = self.xor(share_data, shared_Ext_list[index])
                                share_data_pri_X_r = self.xor(share_data_pri, shared_r)

                                # get new share data : (wi, sh' XOR r, Si)
                                new_share_data = self.get_new_shares(shared_w_list[index], share_data_pri_X_r, share_sr_bytes[index])
                                index += 1

                                share_dict = {
                                        "ChunkID": chunk_id,
                                        "ShareIndex": share_index,
                                        "ShareData": new_share_data
                                }
                                self.shares_list.append(share_dict)

                                # check chunks
                                print(share_dict)

                        chunk_id += 1

                return self.shares_list
        
        def combine_shares(self, data_list: list) -> bytes:
                collected_chunks = self.collect_chunks(data_list, self.share_chunk)
                combined_chunks = self.combine_chunks(collected_chunks)

                recovered_chunks = self.remove_zero_padding(combined_chunks)
                print('recovered_chunks:', recovered_chunks)

                return recovered_chunks
        
        def collect_chunks(self, data_list:list, saved_dict: dict) -> dict:
                chunk_id_list = []

                for data in data_list:
                        if data['ChunkID'] not in chunk_id_list:
                                chunk_id_list.append(data['ChunkID'])
                                self.share_chunk[data['ChunkID']] = []

                        self.save_chunk_shares(data['ChunkID'], data['ShareIndex'],data['ShareData'])
        
        def count_chunks_amount(self) -> int :
                # Count chunks number from self.chunks_shares_ciphertext
                chunks_number = 0
                for chunk_id in self.share_chunk:
                        chunks_number += 1

                # Check All chunk exist
                for i in range(1,chunks_number+1):
                        if i not in self.share_chunk:
                                raise Exception("Chunk " + str(i) + " not exist")
                        
                return chunks_number
        
        def save_chunk_shares(self, chunk_id:int, share_id:int, share_data_b64:str):
                share_data = base64.b64decode(share_data_b64.encode("utf-8"))
                self.share_chunk[chunk_id].append((share_id,share_data))
                # check saved chunk shares
                print(chunk_id, ':', self.share_chunk[chunk_id])

        def combine_chunks(self) -> bytes:
                result = bytes()
                #Count and check chunks number
                chunk_number = self.count_chunks_amount()

                for i in range(1, chunk_number+1):
                        chunk_result = Shamir.combine(self.share_chunk[i])
                        # check chunk result
                        print('chunk_result:', chunk_result)

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