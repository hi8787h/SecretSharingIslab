import random
from Crypto.Protocol.SecretSharing import Shamir
from ShamirSecretSharingBytesStreamer import ShamirSecretSharingBytesStreamer


class LRShare:
    @staticmethod
    def lr_share_procedure(streamer, secret, n, eta, d):
        # Step 1: Run standard Shamir Secret Sharing to obtain shares (Sh1, ..., Shn) for the secret m.
        shares = Shamir.split(2, n, secret)

        # Step 2: Choose a random seed s and a masking string r
        s = random.getrandbits(d)
        r = random.getrandbits(eta)

        lr_shares = []
        for share in shares:
            # Step 3: Processing Each Share
            # (a) Choose a random value wi from {0, 1}η
            wi = random.getrandbits(eta)

            # (b) Compute a new value Sh0i as the XOR of Shi and the output of the extractor Ext applied to (wi, s)
            shi = share[1]
            sh0i = shi ^ streamer.strong_seeded_extractor(wi, s)

            # Step 4: Run 2-out-of-n Shamir Secret Sharing on (s, r) to obtain new shares S1, ..., Sn.
            second_level_shares = Shamir.split(2, n, (s, r))

            # Step 5: Output each sharei as a triple (wi, Sh0i ⊕ r, Si)
            for second_level_share in second_level_shares:
                share_i = {
                    "wi": wi,
                    "Sh0i_xor_r": sh0i ^ r,
                    "Si": second_level_share[1]
                }
                lr_shares.append(share_i)

        return lr_shares

# Example Usage
if __name__ == "__main__":
    secret = b"YourSecretDataHere"
    n = 5
    eta = 128
    d = 256

    shamir_streamer = ShamirSecretSharingBytesStreamer()
    lr_shares = LRShare.lr_share_procedure(shamir_streamer, secret, n, eta, d)

    # Print the generated LR shares
    for i, share in enumerate(lr_shares, 1):
        print(f"Share {i}: {share}")