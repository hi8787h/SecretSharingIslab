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
                #self.s = 

        #LRshare
        def choose_para(self):
                bin_len = 128
                n = 3
                w = [] 
                
                #parameters s, r, w
                s = random.choices("01",k=bin_len)
                r = random.choices("01",k=bin_len)
                for i in range(n):
                        w.append(random.choices("01",k=bin_len))
        
        def get_Sh(self):
                lrss = LeakageResilientSecretSharing()
                lrss.genarate_shares()


        #LRrecover

if __name__ == "__main__":
        pass