import random
import json
import random
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
                super().__init__()
                self.bin_len = 128
                self.modulus = 2 ** self.bin_len
                self.s = []
                self.r = []
                self.k = 2
                self.n = 3
                self.w = []
                self.Ext = bytes()
                
                #For encrypt
                self.data_chunk_list = []
                self.sr_chunk_list = []
                self.new_chunk_list = []
                self.new_shares_list = []
                self.sr_list = []
                #For decrypt
                self.chunks_shares_ciphertext = dict()
        
        def set_s(self) -> bytes :
                s = random.choices("01", k=self.bin_len*3)
                combined_s = ''.join(s).encode('utf-8')
                return combined_s

        def set_r(self) -> bytes :
                r = random.choices("01", k=self.bin_len)
                combined_r = ''.join(r).encode('utf-8')
                return combined_r

        def set_w(self) -> bytes :
                w = random.choices("01", k=self.bin_len*3)
                combined_w = ''.join(w).encode('utf-8')
                return combined_w
        
        # Compute inner product
        def get_inner_product(self, byte1: bytes, byte2: bytes, modulus: int) -> bytes:          
                # Change datatype from bytes to int, and compute inner product
                int_1 = int.from_bytes(byte1, byteorder='big')
                int_2 = int.from_bytes(byte2, byteorder='big')

                inner_product = int_1 * int_2
                inner_mod = inner_product % modulus

                inner_bin = bin(inner_mod)[2: ].zfill(128)
                inner_byte = bytes(inner_bin, 'utf-8')
                return inner_byte

        # XOR
        def xor(self, byte1: bytes, byte2: bytes) -> bytes :
                
                xor_bytes = bytes(x^y for x,y in zip(byte1, byte2))
                return xor_bytes

        # Encrypt
        def zero_byte_padding(self, data: bytes) -> bytes:
                while len(data) % 16 != 0:
                        data = b'\x00' + data
                return data

        def split_data(self, data: bytes) -> list:
                sqeuence_start = 0
                sqeuence_end = 16
                data = self.zero_byte_padding(data)
                for i in range(len(data) // 16):
                        data_chunk: bytes = data[sqeuence_start: sqeuence_end]
                        self.data_chunk_list.append(data_chunk)
                        sqeuence_start += 16
                        sqeuence_end += 16

        def split_sr(self, data: bytes) -> list:
                sqeuence_start = 0
                sqeuence_end = 16
                data = self.zero_byte_padding(data)
                for i in range(len(data) // 16):
                        S_chunk: bytes = data[sqeuence_start: sqeuence_end]
                        self.sr_chunk_list.append(S_chunk)
                        sqeuence_start += 16
                        sqeuence_end += 16

        def split_new_data(self, new_data: bytes) -> list:
                sqeuence_start = 0
                sqeuence_end = 16
                data = self.zero_byte_padding(new_data)
                for i in range(len(data) // 16):
                        S_chunk: bytes = data[sqeuence_start: sqeuence_end]
                        self.new_chunk_list.append(S_chunk)
                        sqeuence_start += 16
                        sqeuence_end += 16
        
        def check_duplicate_shares(self, chunk_id: int, new_share_data: bytes) -> bool:
                # check duplicate shares
                for _, existing_share_data in self.chunks_shares_ciphertext.get(chunk_id, []):
                        if existing_share_data == new_share_data:
                                return True
                return False

        def save_chunk_shares(self, chunk_id: int, share_id: int, share_data_base64: str):
                share_data = base64.b64decode(share_data_base64.encode("utf-8"))
                
                if self.check_duplicate_shares(chunk_id, share_data):
                        print(f"Duplicate share_data for chunk_id {chunk_id}, share_id {share_id}")
                else:
                        self.chunks_shares_ciphertext[chunk_id].append((share_id, share_data))

        def collect_chunks(self, data_list: list):
                chunk_id_list = []
                for data in data_list:
                        if data['ChunkID'] not in chunk_id_list:
                                chunk_id_list.append(data['ChunkID'])
                                self.chunks_shares_ciphertext[data['ChunkID']] = []
                        self.save_chunk_shares(data['ChunkID'], data['ShareIndex'], data['ShareData'])
        
        def count_chunks_amount(self) -> int:
                # Count chunks number from self.chunks_shares_ciphertext
                chunks_number = 0
                for chunk_id in self.chunks_shares_ciphertext:
                        chunks_number += 1        
                # Check All chunk exist
                for i in range(1, chunks_number + 1):
                        if i not in self.chunks_shares_ciphertext:
                                raise Exception("Chunk " + str(i) + " not exist")
                return chunks_number

        def combine_chunks(self) -> bytes:
                result = bytes()
                #Count and check chunks number
                chunk_number = self.count_chunks_amount()

                # check chunk number
                print('Total chunk number:', chunk_number)

                for i in range(1, chunk_number+1):
                        chunk_result = Shamir.combine(self.chunks_shares_ciphertext[i])
                        # check chunk result
                        print('chunk_result', i+1, ':', chunk_result)

                        result += chunk_result    
                return result
        
        def remove_zero_padding(self, data: bytes) -> bytes:
                # Remove header zero padding of bytes
                zero_padding_number = 0
                for i in range(len(data)):
                        if data[i] == 0:
                                zero_padding_number += 1
                        else:
                                break
                return data[zero_padding_number:]

        def combine_shares(self, data_list: list) -> bytes:
                self.collect_chunks(data_list)
                result_cc = self.combine_chunks()
                
                result_rzp = self.remove_zero_padding(result_cc)

                return result_rzp
        
        # shuffle the order of list
        def shuffle_shares(self, object_list: list, shareID: int) -> list:
                new_list = []
                for share in object_list:
                        if share['ShareIndex'] == shareID :
                                new_list.append(share)

                return new_list

        # generate original share
        def genarate_original_shares(self, k: int, n: int, secret: bytes) -> list:
                original_share_list = []
                self.split_data(secret)
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
                                original_share_list.append(share_dict)
                                # check chunks
                                print('original share', chunk_id, ':', share_dict)
                        chunk_id += 1

                return original_share_list
        
        def generate_sr_shares(self, k: int, n: int, sr: bytes) -> list:
                sr_list = []
                self.split_sr(sr)
                sr_id = 1
                for sr_chunk in self.sr_chunk_list:
                        sr_shares = Shamir.split(k, n, sr_chunk)
                        for share in sr_shares:
                                share_dict = dict()
                                share_index = share[0] 
                                share_data = base64.b64encode(share[1]).decode('utf-8')
                                share_dict = {
                                "ChunkID": sr_id,
                                "ShareIndex": share_index,
                                "ShareData": share_data
                                }
                                sr_list.append(share_dict)
                                # check
                                print('sr', sr_id, ':', share_dict)
                        sr_id += 1

                return sr_list
        
        def genarate_new_shares(self, k: int, n: int, new_secret: bytes):
                new_share_list = []
                self.split_new_data(new_secret)
                new_id = 1
                for new_chunk in self.new_chunk_list:
                        new_shares = Shamir.split(k, n, new_chunk)
                        for share in new_shares:
                                share_dict = dict()
                                share_index = share[0] 
                                share_data = base64.b64encode(share[1]).decode('utf-8')
                                share_dict = {
                                "ChunkID": new_id,
                                "ShareIndex": share_index,
                                "ShareData": share_data
                                }
                                new_share_list.append(share_dict)
                        new_id += 1

                return new_share_list
        
        def generate_lrShare(self, secret: bytes) -> list:
                share_pri = []
                original_sharelist = self.genarate_original_shares(self.k, self.n, secret)
                new_share_list = []
                # set s, r, w (and check parameters)
                self.s = self.set_s()
                self.r = self.set_r()
                print('s:', self.s)
                print('r:', self.r)
                for i in range(self.n):
                        self.w.append(self.set_w())
                        print('w', i+1, ':', self.w[i])
                
                # Sh' = Sh XOR Ext(wi, s)
                for i in range(self.n):
                        self.Ext = self.get_inner_product(self.w[i], self.s, self.modulus)
                        original_share = json.dumps(original_sharelist[i]).encode('utf-8')
                        share_pri.append(self.xor(original_share, self.Ext))
                        # check
                        print('Ext', i+1, ':', self.Ext)
                        print('share:', original_share, 'length:', len(original_share))
                        print('Sh\'', i+1, ':', share_pri[i], 'length:', len(share_pri[i]))
                
                # combine s and r, then obtain S1 to Sn
                sr = self.s + self.r
                self.sr_list = self.generate_sr_shares(self.k, self.n, sr)
                
                sr_part1 = self.shuffle_shares(self.sr_list, 1)
                sr_part2 = self.shuffle_shares(self.sr_list, 2)
                sr_part3 = self.shuffle_shares(self.sr_list, 3)

                # test whether any two shares can recover full sr
                sr_part_12 = sr_part1 + sr_part2
                print('sr_part1 + sr_part2 =', sr_part_12)
                sr_rec = self.combine_shares(sr_part_12)
                print('sr_rec:', sr_rec)

                sr_byte1 = json.dumps(sr_part1).encode('utf-8')
                sr_byte2 = json.dumps(sr_part2).encode('utf-8')
                sr_byte3 = json.dumps(sr_part3).encode('utf-8')

                sr_bytes = [sr_byte1, sr_byte2, sr_byte3]
                
                # generate new shares (w, sh' xor r, sr)
                for i in range(self.n):
                        # change type of (w, sh' xor r, sr) from bytes to string
                        # because json dumps can't have type bytes
                        w_b64 = base64.b64encode(self.w[i]).decode('utf-8')
                        sh_xor_r = self.xor(share_pri[i], self.r)
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
                # print('new_secret:', new_secret)
                self.new_shares_list = self.genarate_new_shares(self.k, self.n, new_secret)
                # print('lrss shares:', self.shares_list)
                
                share_1 = self.shuffle_shares(self.new_shares_list, 1)
                share_2 = self.shuffle_shares(self.new_shares_list, 2)
                share_3 = self.shuffle_shares(self.new_shares_list, 3)

                # test whether any two shares can recover
                share_12 = share_1 + share_2
                print('share1 + share2 =', share_12)

                # test recover
                self.recover_lrShare(share_12)
                
                return self.new_shares_list

        def recover_lrShare(self, shares_list: list):
                # extract shares: (w, sh' xor r, sr)
                shares_rec = self.combine_shares(shares_list)

                bytes_rec = shares_rec[shares_rec.index(b'['): ]
                print('bytes_rec:', bytes_rec)
                new_share_rec = json.loads(bytes_rec)
                print('new_share_rec:', new_share_rec)
                # check (w, sh' xor r, sr)
                rec_w1 = base64.b64decode(new_share_rec[0]['w'])
                rec_w2 = base64.b64decode(new_share_rec[1]['w'])
                rec_w3 = base64.b64decode(new_share_rec[2]['w'])

                rec_sh_pri_xor_r_1 = base64.b64decode(new_share_rec[0]['share_pri_xor_r'])
                rec_sh_pri_xor_r_2 = base64.b64decode(new_share_rec[1]['share_pri_xor_r'])
                rec_sh_pri_xor_r_3 = base64.b64decode(new_share_rec[2]['share_pri_xor_r'])
                rec_sr_byte_1 = base64.b64decode(new_share_rec[0]['sr'])
                rec_sr_byte_2 = base64.b64decode(new_share_rec[1]['sr'])
                rec_sr_byte_3 = base64.b64decode(new_share_rec[2]['sr'])
                rec_sr_1 = json.loads(rec_sr_byte_1)
                rec_sr_2 = json.loads(rec_sr_byte_2)
                rec_sr_3 = json.loads(rec_sr_byte_3)
                
                rec_sr_list = rec_sr_1 + rec_sr_2 + rec_sr_3
                print('rec sr list:', rec_sr_list)
                # recover (s,r)
                rec_sr = self.combine_shares(rec_sr_list)
                print('recovered sr:', rec_sr)

                # Sh' = S' xor r
                rec_sh_pri1 = self.xor(rec_sh_pri_xor_r_1, self.r)
                rec_sh_pri2 = self.xor(rec_sh_pri_xor_r_2, self.r)
                rec_sh_pri3 = self.xor(rec_sh_pri_xor_r_3, self.r)

if __name__ == "__main__":
        pass