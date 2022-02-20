from Crypto.Util.number import getPrime
from Crypto.Hash import SHA256

from Set5.utils import p, g, mod_exp


# Challenge 33

def diffie_hellman_generate():
    # p is 1536 bits in length
    a = getPrime(1536) % p
    big_a = mod_exp(g, a, p)

    b = getPrime(1536) % p
    big_b = mod_exp(g, b, p)

    s1 = mod_exp(big_b, a, p)
    s2 = mod_exp(big_a, b, p)

    assert s1 == s2

    s = s1
    hasher = SHA256.new(s)
    s_key = hasher.digest()

    return s_key
