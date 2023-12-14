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
                self.S_chunk_list = []
                self.shares_list = []
                self.S_list = []
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

        def split_S(self, data: bytes) -> list:
                sqeuence_start = 0
                sqeuence_end = 16
                data = self.zero_byte_padding(data)
                for i in range(len(data) // 16):
                        S_chunk: bytes = data[sqeuence_start: sqeuence_end]
                        self.S_chunk_list.append(S_chunk)
                        sqeuence_start += 16
                        sqeuence_end += 16

        def genarate_shares(self, k: int, n: int, secret: bytes) -> list:
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
                                self.shares_list.append(share_dict)
                                # check chunks
                                print('share', chunk_id, ':', share_dict)
                        chunk_id += 1

                return self.shares_list
        
        def genarate_S(self, k:int, n:int, data:bytes)->list:
                S_list = []
                self.split_S(data)
                sr_id = 1
                for S_chunk in self.S_chunk_list:
                        shares = Shamir.split(k, n, S_chunk)
                        for share in shares:
                                share_dict = dict()
                                share_index = share[0] 
                                share_data = base64.b64encode(share[1]).decode('utf-8')
                                share_dict = {
                                "ChunkID": sr_id,
                                "ShareIndex": share_index,
                                "ShareData": share_data
                                }
                                S_list.append(share_dict)
                                # check chunks
                                print('sr', sr_id, ':', share_dict)
                        sr_id += 1

                return S_list

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
                # check saved chunk shares
                print(chunk_id, ':', self.chunks_shares_ciphertext[chunk_id])

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
                # check remove_zero_padding
                print('recovered secret:', result_rzp)

                return result_rzp
        
        # shuffle the order of list
        def shuffle_sr(self, object_list: list, shareID: int) -> list:
                new_list = []
                for share in object_list:
                        if share['ShareIndex'] == shareID :
                                new_list.append(share)

                return new_list

        # shuffle the order of list
        def shuffle_share(self, object_list: list, shareID: int) -> list:
                new_list = []
                for share in object_list:
                        if share['ShareIndex'] == shareID :
                                new_list.append(share)

                return new_list

        def generate_lrShare(self, k:int, n:int, secret:bytes) -> list:
                
        
        def leakage_resilient(self, cipher_list: list) -> list:
                share_pri = []
                lr_share_list = []
                # Set s, r
                self.s = self.set_s()
                # check s
                print('s:', self.s)

                self.r = self.set_r()
                # check r
                print('r:', self.r)
                
                # Set each w
                for i in range(self.n):
                        self.w.append(self.set_w())
                        # check each w
                        print('w', i+1, ':', self.w[i])
                # Sh' = Sh XOR Ext(wi, s)
                for i in range(self.n):
                        self.Ext = self.get_inner_product(self.w[i], self.s, self.modulus)
                        # check each Ext
                        print('Ext', i+1, ':', self.Ext)

                        cipher_bytes = json.dumps(cipher_list[i]).encode('utf-8')
                        # check cipher list
                        print('share:', cipher_list[i], 'length:', len(cipher_list[i]))

                        share_pri.append(self.xor(cipher_bytes, self.Ext))
                        # check each Ext
                        print('share_pri', i+1, ':', share_pri[i], 'length:', len(share_pri[i]))
                
                # obtain S1 to Sn
                sr = self.s + self.r # 128*3 + 128 = 512 bits
                self.S_list = self.genarate_S(self.k, self.n, sr)
                 
                # Shuffle the order of S list
                S1 = self.shuffle_sr(self.S_list, 1)
                S2 = self.shuffle_sr(self.S_list, 2)
                S3 = self.shuffle_sr(self.S_list, 3)

                print('S1=', S1)
                print('S2=', S2)
                print('S3=', S3)

                # test whether any two shares can recover full sr
                S_12 = S1 + S2
                print('S1 + S2 =', S_12)
                check_sr_rec = self.combine_shares(S_12)
                print('check_sr_rec:', check_sr_rec)
                
                S1_bytes = json.dumps(S1).encode('utf-8')
                S2_bytes = json.dumps(S2).encode('utf-8')
                S3_bytes = json.dumps(S3).encode('utf-8')

                S_bytes = [S1_bytes, S2_bytes, S3_bytes]
                
                # Output share
                for i in range(self.n):
                        sh_xor_r = self.xor(share_pri[i], self.r)
                        
                        w_base64 = base64.b64encode(self.w[i]).decode('utf-8')
                        sh_xor_r_base64 = base64.b64encode(sh_xor_r).decode('utf-8')
                        S_base64 = base64.b64encode(S_bytes[i]).decode('utf-8')
                        # Store (wi, sh' xor r, si) to a dictionary
                        secret_dict = dict()
                        secret_dict = {
                                "wi": w_base64, 
                                "sh_pri_xor_r": sh_xor_r_base64,
                                "S": S_base64
                        }
                        # Combine 
                        lr_share_list.append(secret_dict)

                return lr_share_list
        
        def leakage_resilient_recovery(self, shares_list: list):
                
                json_sr_list = []
                # Get two shares to recover (s,r)
                #share_list_rec = [shares_list[0], shares_list[1]]

                # Decode S to [chunk id, share id, share data]
                chunks_sr_1 = base64.b64decode(shares_list[0][0]['S'])
                chunks_sr_2 = base64.b64decode(shares_list[1][0]['S'])
                sr_1 = chunks_sr_1.decode('utf-8')
                sr_2 = chunks_sr_2.decode('utf-8')
                json_sr_1 = json.loads(sr_1)
                json_sr_2 = json.loads(sr_2)
                # Combine 
                json_sr_list = json_sr_1 + json_sr_2

                # Check chunk_sr_list
                print('json_sr:', json_sr_list)

                sr_rec = self.combine_shares(json_sr_list)
                
                # Check sr_rec
                print('sr_rec:', sr_rec)

                s_rec = sr_rec[0: 3*self.bin_len]
                r_rec = sr_rec[3*self.bin_len: ]

                # check s, r
                print('s_rec:', s_rec)
                print('r_rec:',r_rec)

                secret_rec = []
                for i in range(self.k) :
                        # Get sh'i
                        sh_pri_xor_r_decode = base64.b64decode(shares_list[i][0]['sh_pri_xor_r'])

                        # Check shi'_xor_r
                        print('shi_pri_xor_r:', sh_pri_xor_r_decode)

                        share_pri_rec = self.xor(sh_pri_xor_r_decode, r_rec)
                        
                        # Check share_pri
                        print('share_pri:', share_pri_rec)

                        # Get shi
                        wi_decode = base64.b64decode(shares_list[i][0]['wi'])

                        # Check wi
                        print('wi:', wi_decode)

                        Ext_rec = self.get_inner_product(wi_decode, self.s, self.modulus)

                        # Check Ext
                        print('Ext_rec:', Ext_rec)

                        Sh = self.xor(share_pri_rec, Ext_rec)

                        # Check Sh
                        print('Sh:', Sh)

                        secret_rec.append(Sh)

                # 運行 Shamir 的恢復函數
                secret = Shamir.combine(secret_rec)

                # check result
                print('Recoverd Secret:', secret)

                return secret

if __name__ == "__main__":
        pass