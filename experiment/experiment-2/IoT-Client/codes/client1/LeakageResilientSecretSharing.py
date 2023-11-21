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
                super().__init__(self)
                self.bin_len = 128
                self.n = 3
                self.w = []
                self.Ext = [] 

        #LRshare

        #set parameters
        def set_s(self):
                s = random.choices("01",k=self.bin_len)
    
                #return a binary list
                return s

        def set_r(self):
                r = random.choices("01",k=self.bin_len)

                #return a binary list
                return r

        def set_w(self):
                binW = random.choices("01",k=self.bin_len)
    
                #return a binary list
                return binW
        
        #compute inner product
        def xor(self, str1, str2):
                xor_bin = []

                for i in range(self.bin_len):
                        int1 = int(str1[i],2)
                        int2 = int(str2[i],2)
                        xor_int = int1^int2
                        xor_bin.append(str(xor_int))

                #return a binary list
                return xor_bin

        #LRrecover

if __name__ == "__main__":
        pass