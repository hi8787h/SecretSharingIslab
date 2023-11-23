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
                self.LRshare = []
                self.LRshare_list = []
                self.S_list = []
        
        def set_s(self) -> list :
                s = random.choices("01",k=self.bin_len)
                return s

        def set_r(self) -> list :
                r = random.choices("01",k=self.bin_len)
                return r

        def set_w(self) -> list :
                w = random.choices("01",k=self.bin_len)
                return w
        
        # Compute inner product
        # (Need modify)
        def get_inner_product(self, vec1:list, vec2:list, modulus) -> str:
                if len(vec1) != len(vec2):
                        raise ValueError("Vectors must have the same length.")
                
                int_v1 = []
                int_v2 = []
                for i in range(len(vec1)):
                        int_v1.append(int(vec1[i]))
                        int_v2.append(int(vec2[i]))

                inner = sum(x * y for x, y in zip(int_v1, int_v2))
                result_mod = inner % modulus
                result_bin = bin(result_mod)[2:].zfill(128)

                return result_bin

        # XOR
        def xor(self, str1, str2) -> list :
                xor_bin = []

                for i in range(self.bin_len):
                        int1 = int(str1[i],2)
                        int2 = int(str2[i],2)
                        xor_int = int1^int2
                        xor_bin.append(str(xor_int))

                return xor_bin

        def genarate_shares(self, k: int, n: int, data: bytes) -> list:
                return super().genarate_shares(k, n, data)

        def leakage_resilient(self, cbytes):
                share_pri = []
                sr = self.s + self.r
                
                # Set s, r
                self.s = self.set_s()
                self.r = self.set_r()

                # Set each wi
                for i in range(self.n):
                        self.w.append(self.set_w)

                # Sh' = Sh XOR Ext(wi, s)
                for i in range(self.n):
                        Ext = self.get_inner_product(self.w[i], self.s, self.modulus)
                        share_pri.append(self.xor(cbytes, Ext))
                
                # obtain S1 to Sn
                self.S_list = self.genarate_shares(2,3, sr)

                # Output share
                

if __name__ == "__main__":
        pass