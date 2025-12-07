"""
Example: ElGamal encryption using the Charm-Crypto pairing library.

This script:
  - Initializes a pairing group
  - Generates a public/secret key pair
  - Encrypts a random group element
  - Decrypts it and verifies correctness
"""

from charm.toolbox.pairinggroup import PairingGroup, G1, ZR


class ElGamal:

    def __init__(self, group_obj: PairingGroup):
        self.group = group_obj
        # Generator of G1
        self.g = self.group.random(G1)

    def keygen(self):
        x = self.group.random(ZR)
        pk = self.g ** x
        sk = x
        return pk, sk

    def encrypt(self, pk, message):
        """
        Encrypt a message element in G1 using the public key.

        Inputs:
            pk      : public key element in G1
            message : group element in G1 (the plaintext)

        Output:
            ciphertext: dict with components c1, c2 in G1

        Scheme:
            Choose random y ∈ ZR
            c1 = g^y
            s  = pk^y
            c2 = message * s
        """
        y = self.group.random(ZR)
        c1 = self.g ** y
        s = pk ** y
        c2 = message * s
        return {"c1": c1, "c2": c2}

    def decrypt(self, sk, ciphertext):
        """
        Scheme:
            s = c1^x
            message = c2 / s
        """
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]
        s = c1 ** sk
        message = c2 / s
        return message


def main():
    # Initialize a pairing group. "SS512" is a common built-in parameter set.
    group = PairingGroup("SS512")

    print("Using pairing group:", group.groupType())

    # Instantiate the ElGamal scheme
    scheme = ElGamal(group)

    # Key generation
    pk, sk = scheme.keygen()
    print("[*] Key generation complete.")
    print("\n    Public key (pk) type:", type(pk), "=", pk)
    print("\n    Secret key (sk) type:", type(sk), "=", sk)

    # Create a random message in G1
    message = group.random(G1)
    print("\n[*] Random message element generated in G1: ",message)

    # Encrypt
    ciphertext = scheme.encrypt(pk, message)
    print("\n[*] Encryption complete: ", ciphertext)

    # Decrypt
    decrypted = scheme.decrypt(sk, ciphertext)
    print("\n[*] Decryption complete:", decrypted)

    # Verify
    if decrypted == message:
        print("\n[+] Success: decrypted message equals original message.")
    else:
        print("\n[-] Failure: decrypted message does not match original.")

if __name__ == "__main__":
    main()
