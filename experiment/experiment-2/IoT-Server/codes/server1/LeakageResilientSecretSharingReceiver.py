from Crypto.Protocol.SecretSharing import Shamir
import json
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer

class LeakageResilientSecretSharingReceiver:

    def __init__(self):
        self.w = []  
        self.s = []  
        self.r = []  
        self.n=3
        self.shares_list=[]
        self.modulus = 2 ** 128 
        self.Ext=bytes()



    
    def xor(byte1, byte2) -> bytes:
        if len(byte1) != len(byte2):
            raise ValueError("Bytes objects must have the same length.")
        xor_bytes = bytes(x ^ y for x, y in zip(byte1, byte2))
        return xor_bytes

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



    def leakage_resilient_recovery(self, shares_list:list):
        #parsed_shares = [self.parse_share(share) for share in shares_list]#回傳wi  Sh0i  Si 
        
        self.shares_list = shares_list[0][2] 

        sr = ShamirSecretSharingBytesStreamer().combine_shares(self.shares_list)# recover s r 512

        self.s = sr[0:384] # s 為128*3 
        self.r = sr[384: ] # r 128z
        #self.s_r_shares = [(share[2][0], share[2][1]) for share in parsed_shares]
        #self.s , self.r = ShamirSecretSharingBytesStreamer().combine_shares(self.s_r_shares)# recover s r

        recovered_secret = []
        share_pri = []

        for i in self.shares_list :
            #計算sh0i
            Sh0i = self.xor(self.shares_list[i][1], self.r)

            #計算shi
            self.Ext = self.get_inner_product(self.shares_list[i][0], self.s, self.modulus)

            Shi = self.xor(Sh0i, self.Ext)

            recovered_secret.append(Shi)


        # 運行 Shamir 的恢復函數
        secret = Shamir.combine(recovered_secret)

        return secret



if __name__ == "__main__":
    pass
