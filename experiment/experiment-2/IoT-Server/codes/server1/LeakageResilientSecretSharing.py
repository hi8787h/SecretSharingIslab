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
                self.eta = 197
                self.k = 2
                self.n = 3
                # For encrypt
                self.data_chunk_list = []
                self.shares_list = []
                # For decrypt
                self.share_chunk_dict = dict()
                self.sr_chunk_dict = dict()
        def set_s(self):
                s = random.choices("01", k=self.bin_len*self.eta)
                combined_s = ''.join(s).encode('utf-8')
                return combined_s
        
        def set_r(self):
                r = random.choices("01", k=self.bin_len)
                combined_r = ''.join(r).encode('utf-8')
                return combined_r
        
        def set_w(self):
                w = random.choices("01", k=self.bin_len*self.eta)
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
        
        def split_data(self, data: bytes, chunk_list: list):
                sqeuence_start = 0
                sqeuence_end = 16
                data = self.zero_byte_padding(data)
                for i in range(len(data)//16):
                        data_chunk: bytes = data[sqeuence_start:sqeuence_end]
                        chunk_list.append(data_chunk)
                        sqeuence_start += 16
                        sqeuence_end += 16
        
        def get_new_shares(self, w: bytes, priXr: bytes, sr_part: bytes) -> bytes:
                w_b64 = base64.b64encode(w).decode('utf-8')
                priXr_b64 = base64.b64encode(priXr).decode('utf-8')
                sr_part_b64 = base64.b64encode(sr_part).decode('utf-8')
                
                new_share = dict()
                new_share = {
                        "w": w_b64, 
                        "sh_pri_X_r": priXr_b64, 
                        "sr_share": sr_part_b64
                }
                new_share_bytes = json.dumps(new_share).encode('utf-8')
                return new_share_bytes
        
        def classify_shares(self, sharelist: list, index: int) -> list:
                modified_list = []
                for share in sharelist:
                        if share['ShareIndex'] == index :
                                modified_list.append(share)
                return modified_list
        
        def generate_sr_shares(self, data: bytes) -> list:
                sr_list = []
                sr_chunk_list = []
                self.split_data(data, sr_chunk_list)
                
                chunk_id = 1
                for sr_chunk in sr_chunk_list:
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
        
        def genarate_lrShares(self, data: bytes)-> list:
                self.split_data(data, self.data_chunk_list)
                # For each chunk
                chunk_id = 1
                for data_chunk in self.data_chunk_list:
                        # set parameters
                        shared_s = self.set_s()
                        shared_r = self.set_r()
                        shared_sr = shared_s + shared_r
                        shared_sr_list = self.generate_sr_shares(shared_sr)
                        # turn sr_shares into bytes
                        shared_sr_part1 = self.classify_shares(shared_sr_list, 1)
                        shared_sr_part2 = self.classify_shares(shared_sr_list, 2)
                        shared_sr_part3 = self.classify_shares(shared_sr_list, 3)
                        shared_sr_bytes1 = json.dumps(shared_sr_part1).encode('utf-8')
                        shared_sr_bytes2 = json.dumps(shared_sr_part2).encode('utf-8')
                        shared_sr_bytes3 = json.dumps(shared_sr_part3).encode('utf-8')
                        shared_sr_bytes = [shared_sr_bytes1, shared_sr_bytes2, shared_sr_bytes3]
                        shared_w_list = []
                        for i in range(self.n):
                                shared_w = self.set_w()
                                shared_w_list.append(shared_w)

                        shared_Ext_list = []
                        for i in range(self.n):
                                shared_Ext = self.get_inner_product(shared_w_list[i], shared_s)
                                shared_Ext_list.append(shared_Ext)

                        # split into n shares
                        shares = Shamir.split(self.k, self.n, data_chunk)

                        index = 0
                        for share in shares:
                                share_dict = dict()
                                share_index = share[0]
                                share_data = base64.b64encode(share[1])
                                # use leakage resilient on share_data
                                # new share form: (wi, sh' XOR r, Si)
                                share_data_pri = self.xor(share_data, shared_Ext_list[index])
                                share_data_pri_X_r = self.xor(share_data_pri, shared_r)
                                new_share_bytes = self.get_new_shares(shared_w_list[index], share_data_pri_X_r, shared_sr_bytes[index])
                                new_share_data = base64.b64encode(new_share_bytes).decode('utf-8')
                                index += 1
                                share_dict = {
                                        "ChunkID": chunk_id,
                                        "ShareIndex": share_index,
                                        "ShareData": new_share_data
                                }

                                self.shares_list.append(share_dict)
                        chunk_id += 1
                return self.shares_list
        
        def combine_lrShares(self, recoverlist: list):
                sr_id_list = []
                w_dict = dict()
                priXr_dict = dict()
                sr_dict = dict()
                
                # get each sr share to combine 4 (s, r)
                for data in recoverlist:
                        if data['ChunkID'] not in sr_id_list:
                                sr_id_list.append(data['ChunkID'])
                                sr_dict[data['ChunkID']] = []
                                w_dict[data['ChunkID']] = []
                                priXr_dict[data['ChunkID']] = []
                        # recover {'w', 'Sh_pri XOR r', sr_share}
                        recovered_data = base64.b64decode(data['ShareData'].encode("utf-8"))
                        recovered_json = json.loads(recovered_data)
                        # save each w
                        recovered_w_json = recovered_json['w']
                        recovered_w_bytes = base64.b64decode(recovered_w_json)
                        w_dict[data['ChunkID']].append([data['ShareIndex'], recovered_w_bytes])
                        # save each Sh_pri XOR r
                        recovered_priXr_json = recovered_json['sh_pri_X_r']
                        recovered_priXr_bytes = base64.b64decode(recovered_priXr_json)
                        priXr_dict[data['ChunkID']].append([data['ShareIndex'], recovered_priXr_bytes])
                        # save sr chunks
                        recovered_sr_json = recovered_json['sr_share']
                        recovered_sr_bytes = base64.b64decode(recovered_sr_json)
                        sr_dict[data['ChunkID']].append([data['ShareIndex'], recovered_sr_bytes])
                # recover (s, r), and then recover the share data
                recovered_datalist = []
                recovered_sr_count = 1
                for srID in sr_dict:
                        # recover (s, r)
                        sr_bytes = bytes()
                        for sr in sr_dict[srID]:
                                sr_bytes += sr[1]
                        
                        sr_dec = sr_bytes.decode('utf-8')
                        sr_str = sr_dec.replace('][', ',')
                        recovered_sr_list = json.loads(sr_str)
                        self.collect_chunks(recovered_sr_list, self.sr_chunk_dict)
                        recovered_sr = self.combine_chunks(self.sr_chunk_dict)

                        recovered_s = recovered_sr[0: self.eta*self.bin_len]
                        recovered_r = recovered_sr[self.eta*self.bin_len: ]
                        recovered_sr_count += 1

                        # recover Sh' = Sh' XOR r
                        recovered_sh_pri_list = []
                        for sh_pri_X_r in priXr_dict[srID]:
                                recovered_sh_pri = self.xor(sh_pri_X_r[1], recovered_r)
                                recovered_sh_pri_list.append(recovered_sh_pri)
                        # recover Sh = Sh' XOR Ext(w, s)
                        count = 0
                        for w in w_dict[srID]:
                                recovered_Ext = self.get_inner_product(w[1], recovered_s)
                                recovered_share = self.xor(recovered_sh_pri_list[count], recovered_Ext)
                                recovered_datalist.append(recovered_share)

                                count += 1
                # combine secret
                share_id_list = []
                share_id = 0
                chunk_id = 1
                shareIndex = 0
                for data in recoverlist:
                        shareIndex += 1
                        if data['ChunkID'] not in share_id_list:
                                share_id_list.append(data['ChunkID'])
                                self.share_chunk_dict[data['ChunkID']] = []
                        share_data_bytes = base64.b64decode(recovered_datalist[share_id])
                        self.share_chunk_dict[chunk_id].append((shareIndex, share_data_bytes))
                        
                        if shareIndex % self.k == 0:
                                shareIndex = 0
                                chunk_id = chunk_id % (len(recoverlist)//self.k) + 1
                        share_id += 1
                result = self.combine_chunks(self.share_chunk_dict)
                recovered_secret = self.remove_zero_padding(result)
                return recovered_secret
        
        def collect_chunks(self, sharelist: list, recover_dict: dict):
                chunk_id_list = []
                for data in sharelist:
                        if data['ChunkID'] not in chunk_id_list:
                                chunk_id_list.append(data['ChunkID'])
                                recover_dict[data['ChunkID']] = []
                        share_data = base64.b64decode(data['ShareData'].encode("utf-8"))
                        
                        recover_dict[data['ChunkID']].append((data['ShareIndex'], share_data))
        
        def combine_chunks(self, recover_dict: dict) -> bytes:
                result = bytes()
                #Count and check chunks number
                chunk_number = self.count_chunks_amount(recover_dict)

                for i in range(1, chunk_number+1):
                        chunk_result = Shamir.combine(recover_dict[i])
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