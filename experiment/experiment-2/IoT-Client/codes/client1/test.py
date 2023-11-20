import os
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer
import json
import random
import datetime
import time
from SocketConnection import SocketConnection
from HashFunction import HashFunction
from LeakageResilientSecretSharing import LeakageResilientSecretSharing

if __name__ == "__main__":
    lrss = LeakageResilientSecretSharing()

    lrss.chosing_para()