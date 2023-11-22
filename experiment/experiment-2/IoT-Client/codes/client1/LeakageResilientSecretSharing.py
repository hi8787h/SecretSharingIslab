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
                self.Ext = [] 

        #LRshare

        #set parameters
        def set_s(self) -> list :
                s = random.choices("01",k=self.bin_len)
    
                return s

        def set_r(self) -> list :
                r = random.choices("01",k=self.bin_len)

                return r

        def set_w(self) -> list :
                w = random.choices("01",k=self.bin_len)
    
                return w
        
        #compute inner product
        def xor(self, str1, str2) -> list :
                xor_bin = []

                for i in range(self.bin_len):
                        int1 = int(str1[i],2)
                        int2 = int(str2[i],2)
                        xor_int = int1^int2
                        xor_bin.append(str(xor_int))

                return xor_bin

        def genarate_shares(self, k: int, n: int, data: bytes) -> list:
                super().genarate_shares(k, n, data)

                self.s = self.set_s()
                self.r = self.set_r()
                for i in range(n):
                        self.w.append(self.set_w)

                # Do Ext(wi, s)
                for i in range(n):
                        self.Ext.append(self.xor(self.w[i], self.s))

if __name__ == "__main__":
        pass