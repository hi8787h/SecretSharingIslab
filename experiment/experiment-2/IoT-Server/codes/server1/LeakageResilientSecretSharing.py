from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import base64
import json
import random

import ShamirSecretSharingBytesStreamer

class LeakageResilientSecretSharing(ShamirSecretSharingBytesStreamer):
        """
        Leakage Resilient Secret Sharing
        Author: NCYU ISlab
        This class inherits from ShamirSecretSharingBytesStreamer.
        That will improve secure of system!
        """

        def __init__(self):
                super().__init__(self)


        #LRshare
        def chosing_s_and_r(self):
                bin_len = 128
                s = random.choices("01",k=bin_len)
                print(s)
                r = random.choices("01",k=bin_len)
                print(r)

        #LRrecover
