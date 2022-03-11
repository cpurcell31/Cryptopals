from hashlib import sha256
from random import randint
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Set5.challenge39 import rsa_encrypt, rsa_decrypt, rsa_keygen
from Set6.utils import mod_exp


# Challenge 41

class RSA_Server:
    def __init__(self):
        # Let's assume our e is not 3 for now
        self.n, self.e, self.d = rsa_keygen()
        self.prev_hashes = None
        self.ciphers = None
        self.encrypt_plaintexts()

    def encrypt_plaintexts(self):
        p1 = b'This is the secret message'
        p2 = b'YELLOW SUBMARINE'
        p3 = b"Don't trust the gardener"
        p4 = b'Attack at dawn'
        p5 = b'My password is teacup123'
        plaintexts = [p1, p2, p3, p4, p5]
        self.ciphers = list()
        for p in plaintexts:
            self.ciphers.append(rsa_encrypt(self.n, self.e, p))
        return

    def get_ciphers(self):
        return self.ciphers

    def get_public_exponent(self):
        return self.n, self.e

    def decrypt_msg(self, cipher):
        h = sha256(str(cipher).encode()).hexdigest()
        if self.prev_hashes is not None and h in self.prev_hashes:
            # Error same as prev messages
            return None
        self.add_hash_to_list(h)
        return rsa_decrypt(self.n, self.d, cipher)

    def add_hash_to_list(self, h):
        if self.prev_hashes is None:
            self.prev_hashes = list()
            self.prev_hashes.append(h)
            return
        if len(self.prev_hashes) >= 3:
            temp = self.prev_hashes[1:]
            temp.append(h)
            self.prev_hashes = temp
            return
        self.prev_hashes.append(h)
        return


def rsa_oracle_attack():
    server = RSA_Server()
    ciphers = server.get_ciphers()
    n, e = server.get_public_exponent()
    s = randint(2, n-1)
    for i in range(len(ciphers)):
        c_prime = (mod_exp(n, e, s) * ciphers[i]) % n
        p_prime = server.decrypt_msg(c_prime)

        p = (bytes_to_long(p_prime) * pow(s, -1, n)) % n

        print("Decrypted Message " + str(i+1) + ": " + long_to_bytes(p).decode())
    return

