import random
import json
import random
import base64
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer

class LeakageResilientSecretSharing(ShamirSecretSharingBytesStreamer):
        """
        Leakage Resilient Secret Sharing
        Author: NCYU ISlab
        This class inherits from ShamirSecretSharingBytesStreamer.
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
                self.sr_shares_ciphertext = dict()
        
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

        def genarate_shares(self, k: int, n: int, data: bytes) -> list:
                return super().genarate_shares(k, n, data)

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
        
        def save_chunk_shares(self, wi:str, sh_xor_r:str, S:str):
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
                result = bytes()
                padding_null_bytes_number:int = 0
                #Count and check chunks number
                chunk_number = self.count_chunks_amount()
                for i in range(1,chunk_number+1):
                        chunk_result = Shamir.combine(self.chunks_shares_ciphertext[i])
                        result += chunk_result
                return result

        def combine_sr(self, ):
                temp

        def leakage_resilient_recovery(self, shares_list:list):
                
                chunk_sr_list = []
                # Get two shares to recover (s,r)
                #share_list_rec = [shares_list[0], shares_list[1]]

                # Decode S to [chunk id, share id, share data]
                chunks_sr_1 = base64.b64decode(shares_list[0][0]['S'])
                chunks_sr_2 = base64.b64decode(shares_list[1][0]['S'])

                # Combine two 
                chunk_sr_list = [chunks_sr_1, chunks_sr_2]

                # test
                print('chunk_sr_list:', chunk_sr_list)

                sr_rec = self.combine_shares(chunk_sr_list)
                
                # test
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