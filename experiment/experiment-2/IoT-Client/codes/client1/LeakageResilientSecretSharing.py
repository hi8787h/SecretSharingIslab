import random
import json
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
                self.LRshare = []
                self.LRshare_list = []
                self.S_list = []
        
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
        def get_inner_product(self, byte1:bytes, byte2:bytes, modulus) -> bytes:
                if len(byte1) != len(byte2):
                        raise ValueError("Vectors must have the same length.")
                
                # Change datatype from bytes to int, and compute inner product
                int_1 = int.from_bytes(byte1, byteorder='big')
                int_2 = int.from_bytes(byte2, byteorder='big')

                inner_product = int_1 * int_2
                inner_mod = inner_product % modulus

                inner_bin:bytes = bin(inner_mod)[2:].zfill(128)
                return inner_bin

        # XOR
        # (Need modify)
        def xor(self, byte1, byte2) -> bytes :
                if len(byte1) != len(byte2):
                        raise ValueError("Bytes objects must have the same length.")
                
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
                        self.w.append(self.set_w)

                # Sh' = Sh XOR Ext(wi, s)
                for i in range(self.n):
                        Ext = self.get_inner_product(self.w[i], self.s, self.modulus)
                        cipher_bytes = json.dumps(cipher_list).encode('utf-8')
                        share_pri.append(self.xor(cipher_bytes, Ext))
                
                # obtain S1 to Sn
                sr = self.s + self.r # 128*3+128 = 512 bits

                self.S_list = self.genarate_shares(2,3, sr)

                # Output share
                for i in range(len(self.S_list)):
                        sh_xor_r = self.xor(share_pri[i], self.r)
                        lr_share_list.append(self.combine_share(self.w[i], sh_xor_r, self.S_list[i]))

                return lr_share_list

        # Combine (wi, sh' xor r, si) to a list
        def combine_share(self, byteW:bytes, sh_pri:bytes, shareSR:bytes) -> list:
                combined_sh_pri = []
                combined_sh_pri.append([byteW, sh_pri, shareSR])

                return combined_sh_pri

if __name__ == "__main__":
        pass