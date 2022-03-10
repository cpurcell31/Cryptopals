from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
from Set5.utils import mod_exp


# Challenge 39

def rsa_keygen():
    while True:
        p = getPrime(2048)
        q = getPrime(2048)
        n = p * q
        et = (p-1)*(q-1)
        e = 3
        d = None
        try:
            d = pow(e, -1, et)
        except ValueError as e:
            pass

        if d is not None:
            return n, e, d


def rsa_encrypt(n, e, byte_str):
    m = bytes_to_long(byte_str)
    return mod_exp(n, e, m)


def rsa_decrypt(n, d, c):
    m = mod_exp(n, d, c)
    return long_to_bytes(m)
