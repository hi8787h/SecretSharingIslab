import random
import json
import random
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
                self.n = 3
                self.w = []
                self.S_list = []
                self.Ext = bytes()
                self.share_list_rec = []
        
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

                self.S_list = self.genarate_shares(2,self.n, sr)
                
                # Shuffle the order of parameter s and r
                random.shuffle(self.S_list)
                S1 = self.S_list[: len(self.S_list)//3]
                S2 = self.S_list[len(self.S_list)//3: 2*len(self.S_list)//3]
                S3 = self.S_list[2*len(self.S_list)//3: ]

                S1 = json.dumps(S1).encode('utf-8')
                S2 = json.dumps(S2).encode('utf-8')
                S3 = json.dumps(S3).encode('utf-8')
                S_bytes = [S1, S2, S3]

                # Output share
                for i in range(self.n):
                        sh_xor_r = self.xor(share_pri[i], self.r)
                        
                        # Combine (wi, sh' xor r, si) to a list
                        lr_share_list.append([self.w[i], sh_xor_r, S_bytes[i]])

                return lr_share_list
        
        def leakage_resilient_recovery(self, shares_list:list):
                self.share_list_rec.append([shares_list[0][2], shares_list[1][2]])
                sr_rec = self.combine_shares(self.share_list_rec)# recover s r 512
                s_rec = sr_rec[0: 3*self.bin_len] # 3*128 
                r_rec = sr_rec[3*self.bin_len: ] # 128

                recovered_secret = []
                share_pri = []

                for i in self.share_list_rec :
                        #計算sh'i
                        Sh0i = self.xor(self.share_list_rec[i][1], r_rec)

                        #計算shi
                        self.Ext = self.get_inner_product(self.share_list_rec[i][0], self.s, self.modulus)

                        Shi = self.xor(Sh0i, self.Ext)

                        recovered_secret.append(Shi)

                # 運行 Shamir 的恢復函數
                secret = Shamir.combine(recovered_secret)

                return secret


if __name__ == "__main__":
        pass