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
                self.data = bytes()
                self.message_length = 0
                self.data_chunk_list = []
                self.shares_list = []
                #For decrypt
                self.chunks_shares_ciphertext = dict()
        
        def set_s(self) -> bytes :
                s = random.choices("01",k=self.bin_len*3)
                combined_s = ''.join(s).encode('utf-8')
                return combined_s

        def set_r(self) -> bytes :
                r = random.choices("01",k=self.bin_len)
                combined_r = ''.join(r).encode('utf-8')
                return combined_r

        def set_w(self) -> bytes :
                w = random.choices("01",k=self.bin_len*3)
                combined_w = ''.join(w).encode('utf-8')
                return combined_w
        
        # Compute inner product
        def get_inner_product(self, byte1:bytes, byte2:bytes, modulus:int) -> bytes:
                                
                # Change datatype from bytes to int, and compute inner product
                int_1 = int.from_bytes(byte1, byteorder='big')
                int_2 = int.from_bytes(byte2, byteorder='big')

                inner_product = int_1 * int_2
                inner_mod = inner_product % modulus

                inner_bin = bin(inner_mod)[2:].zfill(128)
                inner_byte = bytes(inner_bin, 'utf-8')
                return inner_byte

        # XOR
        def xor(self, byte1:bytes, byte2:bytes) -> bytes :
                
                xor_bytes = bytes(x^y for x,y in zip(byte1, byte2))
                return xor_bytes

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

        # Leakage resilient algorithm implementation
        def leakage_resilient(self, cipher_list:list):
                share_pri = []
                lr_share_list = []
                # Set s, r
                self.s = self.set_s()
                self.r = self.set_r()
                # Set each wi
                for i in range(self.n):
                        self.w.append(self.set_w())

                # Sh' = Sh XOR Ext(wi, s)
                for i in range(self.n):
                        self.Ext = self.get_inner_product(self.w[i], self.s, self.modulus)
                        cipher_bytes = json.dumps(cipher_list[i]).encode('utf-8')
                        share_pri.append(self.xor(cipher_bytes, self.Ext))
                
                # obtain S1 to Sn
                sr = self.s + self.r # 128*3+128 = 512 bits

                S_list = self.genarate_shares(self.k, self.n, sr)
                
                # Shuffle the order of parameter s and r
                random.shuffle(S_list)
                S1 = S_list[: len(S_list)//3]
                S2 = S_list[len(S_list)//3: 2*len(S_list)//3]
                S3 = S_list[2*len(S_list)//3: ]

                S1 = json.dumps(S1).encode('utf-8')
                S2 = json.dumps(S2).encode('utf-8')
                S3 = json.dumps(S3).encode('utf-8')
                S_bytes = [S1, S2, S3]

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
        
        def leakage_resilient_recovery(self, shares_list:list):
                
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

                return secret

if __name__ == "__main__":
        pass