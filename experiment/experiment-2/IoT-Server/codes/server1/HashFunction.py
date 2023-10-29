from hashlib import sha256

class HashFunction:
    @staticmethod
    def print_sha256(input:bytes):
        print(sha256(input).hexdigest())