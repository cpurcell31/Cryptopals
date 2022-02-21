from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Hash import SHA256

from Set5.utils import p, g, mod_exp


# Challenge 33

def diffie_hellman_generate():
    # p is 1536 bits in length
    a = getPrime(1536) % p
    big_a = mod_exp(p, a, g)

    b = getPrime(1536) % p
    big_b = mod_exp(p, b, g)

    s1 = mod_exp(p, a, big_b)
    s2 = mod_exp(p, b, big_a)

    assert s1 == s2

    s = long_to_bytes(s1)
    hasher = SHA256.new(s)
    s_key = hasher.digest()

    return s_key
