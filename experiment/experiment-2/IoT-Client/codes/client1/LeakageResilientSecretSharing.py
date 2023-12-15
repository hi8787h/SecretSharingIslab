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
                # Recover
                self.original_share_chunk = dict()
                self.sr_share_chunk = dict()
                self.new_share_chunk = dict()

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

        def genarate_original_shares(self, k: int, n: int, data: bytes) -> list:
                original_share_list = []
                original_chunklist = self.split_data(data)

                chunk_id = 1
                for original_chunk in original_chunklist:
                        shares = Shamir.split(k, n, original_chunk)
                        for share in shares:
                                share_dict = dict()
                                share_index = share[0] 
                                share_data = base64.b64encode(share[1]).decode('utf-8')
                                share_dict = {
                                "ChunkID": chunk_id,
                                "ShareIndex": share_index,
                                "ShareData": share_data
                                }
                                original_share_list.append(share_dict)
                        chunk_id += 1

                return original_share_list
        
        def generate_sr_shares(self, k: int, n: int, data: bytes) -> list:
                sr_list = []
                sr_chunklist = self.split_data(data)
                chunk_id = 1
                for sr_chunk in sr_chunklist:
                        sr_shares = Shamir.split(k, n, sr_chunk)
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
                                # check
                                print('sr', chunk_id, ':', share_dict)
                        chunk_id += 1

                return sr_list
        
        def genarate_new_shares(self, k: int, n: int, data: bytes) -> list:
                new_share_list = []
                new_chunklist = self.split_data(data)

                chunk_id = 1
                for new_chunk in new_chunklist:
                        shares = Shamir.split(k, n, new_chunk)
                        for share in shares:
                                share_dict = dict()
                                share_index = share[0] 
                                share_data = base64.b64encode(share[1]).decode('utf-8')
                                share_dict = {
                                "ChunkID": chunk_id,
                                "ShareIndex": share_index,
                                "ShareData": share_data
                                }
                                new_share_list.append(share_dict)
                        chunk_id += 1

                return new_share_list
        
        def shuffle_shares(self, sharelist: list, index: int) -> list:
                modified_list = []
                for share in sharelist:
                        if share['ShareIndex'] == index :
                                modified_list.append(share)

                return modified_list
        
        def lrShare(self, secret: bytes) -> list:
                original_sharelist = self.genarate_original_shares(self.k, self.n, secret)
                # just test output
                for i in range(len(original_sharelist)):
                        print('original_share', i+1, ':', original_sharelist[i])

                # set parameters
                s = self.set_s()
                r = self.set_r()
                print('shared s :', s)
                print('shared r :', r)

                w_list = []
                for i in range(self.n):
                        w = self.set_w()
                        # just test output
                        print('w', i+1, ':', w)
                        w_list.append(w)
                
                # Sh' = Sh XOR Ext(wi, s)
                share_pri_list = []
                for i in range(self.n):
                        Ext = self.get_inner_product(w_list[i], s)
                        print('Ext', i+1, ':', Ext)
                        original_share = json.dumps(original_sharelist[i]).encode('utf-8')
                        share_pri = self.xor(original_share, Ext)
                        # just test output
                        print('sh\'', i+1, ':', share_pri_list)
                        
                        share_pri_list.append(share_pri)
                
                # combine s and r, then obtain S1 to Sn
                sr = s + r
                sr_list = self.generate_sr_shares(self.k, self.n, sr)
                        
                sr_part1 = self.shuffle_shares(sr_list, 1)
                sr_part2 = self.shuffle_shares(sr_list, 2)
                sr_part3 = self.shuffle_shares(sr_list, 3)

                sr_byte1 = json.dumps(sr_part1).encode('utf-8')
                sr_byte2 = json.dumps(sr_part2).encode('utf-8')
                sr_byte3 = json.dumps(sr_part3).encode('utf-8')

                sr_bytes = [sr_byte1, sr_byte2, sr_byte3]

                # generate new shares (w, sh' xor r, sr)
                new_share_list = []
                for i in range(self.n):
                        # change type of (w, sh' xor r, sr) from bytes to string
                        # because json dumps can't have type bytes
                        w_b64 = base64.b64encode(w_list[i]).decode('utf-8')
                        sh_xor_r = self.xor(share_pri[i], r)
                        sh_xor_r_b64 = base64.b64encode(sh_xor_r).decode('utf-8')
                        sr_b64 = base64.b64encode(sr_bytes[i]).decode('utf-8')

                        new_share = dict()
                        new_share = {
                                "w": w_b64,
                                "share_pri_xor_r": sh_xor_r_b64,
                                "sr": sr_b64
                        }
                        new_share_list.append(new_share)
                
                new_secret = json.dumps(new_share_list).encode('utf-8')

                new_shares_list = self.genarate_new_shares(self.k, self.n, new_secret)

                return new_shares_list

        def recover_lrShare(self, sharelist: list):
                # extract shares: (w, sh' xor r, sr)
                new_secret_rec = self.combine_shares(sharelist, self.new_share_chunk)
                new_bytes_rec = new_secret_rec[new_secret_rec.index(b'['): ]
                new_rec = json.loads(new_bytes_rec)

                # recover (w, sh' xor r, sr)
                w_reclist = []
                sh_pri_xor_r_reclist = []
                sr_chunk_reclist = []

                # check new_rec length
                print('new_rec length:', len(new_rec))

                for i in range(len(new_rec)):
                        w_rec = base64.b64decode(new_rec[i]['w'])
                        # just test output
                        print('recovered w', i+1, ':', w_rec)
                        w_reclist.append(w_rec)
                        sh_pri_xor_r_rec = base64.b64decode(new_rec[i]['share_pri_xor_r'])
                        # just test output
                        print('recovered sh\' xor r', i+1, ':', sh_pri_xor_r_rec)
                        
                        sh_pri_xor_r_reclist.append(sh_pri_xor_r_rec)
                        chunk_rec = base64.b64decode(new_rec[i]['sr'])
                        sr_chunk_rec = json.loads(chunk_rec.decode('utf-8'))
                        sr_chunk_reclist.append(sr_chunk_rec)
                
                # get two shares of (s,r), to combine full one
                rec_sr_list = sr_chunk_reclist[0] + sr_chunk_reclist[1]
                rec_sr = self.combine_shares(rec_sr_list, self.sr_share_chunk)
                s_rec = rec_sr[0: 3*self.bin_len]
                r_rec = rec_sr[3*self.bin_len: ]
                print('recovered s:', s_rec)
                print('recovered r:', r_rec)

                recovered_result = bytes()
                for i in range(self.k):
                        sh_pri_rec = self.xor(sh_pri_xor_r_reclist[i], r_rec)
                        print('sh_pri_rec:', sh_pri_rec)
                        Ext_rec: bytes = self.get_inner_product(w_reclist[i], s_rec)
                        print('Ext_rec:', Ext_rec)
                        
                        original_secret_rec = self.xor(sh_pri_rec, Ext_rec)
                        print('original_secret_rec:', original_secret_rec)
                        recovered_result += original_secret_rec

                return recovered_result

# 12.14紀錄 : 將original, sr, new各用一個dict來收集chunk

        def combine_shares(self, sharelist: list, recover_dict: dict):
                collected_chunks = self.collect_chunks(sharelist, recover_dict)
                combined_chunks = self.combine_chunks(collected_chunks)
                recovered_chunks = self.remove_zero_padding(combined_chunks)

                return recovered_chunks
        
        def collect_chunks(self, sharelist: list, recover_dict: dict) -> dict:
                chunk_id_list = []
                for data in sharelist:
                        if data['ChunkID'] not in chunk_id_list:
                                chunk_id_list.append(data['ChunkID'])
                                recover_dict[data['ChunkID']] = []

                        share_data = base64.b64decode(data['ShareData'].encode("utf-8"))
                        if self.check_duplicate_shares(data['ChunkID'], share_data):
                                print(f"Duplicate share_data for chunk_id {data['ChunkID']}, share_id {data['ShareIndex']}")
                        else:
                                recover_dict[data['ChunkID']].append((data['ShareIndex'], share_data))

                return recover_dict
        
        def combine_chunks(self, collected_chunks: dict) -> bytes:
                result = bytes()
                #Count and check chunks number
                chunk_number = self.count_chunks_amount(collected_chunks)

                # check chunk number
                print('Total chunk number:', chunk_number)

                for i in range(1, chunk_number+1):
                        chunk_result = Shamir.combine(collected_chunks[i])
                        result += chunk_result    

                return result
        
        def count_chunks_amount(self, chunklist: dict):
                chunks_number = 0
                for chunk_id in chunklist:
                        chunks_number += 1        
                # Check All chunk exist
                for i in range(1, chunks_number + 1):
                        if i not in chunklist:
                                raise Exception("Chunk " + str(i) + " not exist")
                return chunks_number

        def remove_zero_padding(self, data: bytes) -> bytes:
                # Remove header zero padding of bytes
                zero_padding_number = 0
                for i in range(len(data)):
                        if data[i] == 0:
                                zero_padding_number += 1
                        else:
                                break
                return data[zero_padding_number:]

        def check_duplicate_shares(self, chunk_id: int, new_share_data: bytes) -> bool:
                for _, existing_share_data in self.original_share_chunk.get(chunk_id, []):
                        if existing_share_data == new_share_data:
                                return True
                return False