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
                self.s = []
                self.n = 3
                self.w = []
                self.LRshare = []
                self.LRshare_list = []
                self.S_list = []
        
        # Set parameters
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
                sr = [] # temp
                
                # Set s, r
                self.s = self.set_s()
                self.r = self.set_r()

                # Set each wi
                for i in range(self.n):
                        self.w.append(self.set_w)

                # Sh' = Sh XOR Ext(wi, s)
                for i in range(self.n):
                        Ext = self.xor(self.w[i], self.s)
                        share_pri.append(self.xor(cbytes, Ext))
                
                # obtain S1-Sn
                self.S_list = self.genarate_shares(2,3, sr) # temp

if __name__ == "__main__":
        pass