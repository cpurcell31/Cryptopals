import asyncio
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Random import get_random_bytes
from Set5.utils import p, g, mod_exp
from Set4.challenge28 import sha1
from Set2.challenge10 import cbc_encrypt, cbc_decrypt
from Set2.challenge15 import strip_pkcs_padding


# Challenge 34

class User:
    def __init__(self):
        self.p = p
        self.g = g
        self.a = None
        self.big_a = None
        self.s = None
        self.msg = b'YELLOW SUBMARINE'
        self.cipher = None

    def compute_big_a(self):
        self.a = getPrime(1536) % self.p
        self.big_a = mod_exp(self.g, self.a, self.p)
        return self.p, self.g, self.big_a

    def compute_s(self, big_b):
        self.s = mod_exp(big_b, self.a, self.p)

    def create_msg(self):
        iv = get_random_bytes(16)
        self.cipher = cbc_encrypt(self.msg, sha1(long_to_bytes(self.s))[:16], iv=iv) + iv
        return self.cipher

    def verify_response(self, response):
        iv = response[-16:]
        plain = strip_pkcs_padding(cbc_decrypt(response[:-16], sha1(long_to_bytes(self.s))[:16], iv=iv), 16)
        assert plain == self.msg
        return True


class Server:
    def __init__(self, pp, gg, big_a):
        self.p = pp
        self.g = gg
        self.big_a = big_a
        self.b = None
        self.big_b = None
        self.s = None

    def compute_big_b(self):
        self.b = getPrime(1536) % self.p
        self.big_b = mod_exp(self.g, self.b, self.p)
        self.compute_s()
        return self.big_b

    def compute_s(self):
        self.s = mod_exp(self.big_a, self.b, self.p)

    def create_response(self, cipher_a):
        iv = cipher_a[-16:]
        msg_a = strip_pkcs_padding(cbc_decrypt(cipher_a[:-16], sha1(long_to_bytes(self.s))[:16], iv=iv), 16)
        return cbc_encrypt(msg_a, sha1(long_to_bytes(self.s))[:16], iv=iv) + iv


def attacker():
    # Initialize user and eavesdrop to steal "A"
    user = User()
    pp, gg, big_a = user.compute_big_a()

    # Forward modified diffie variables to the server and steal "B"
    server = Server(pp, gg, pp)
    big_b = server.compute_big_b()

    # Forward similar variables back to the user and eavesdrop
    user.compute_s(pp)
    cipher_a = user.create_msg()

    # Decrypt cipher_a
    s = mod_exp(pp, gg, pp)
    assert s == user.s
    iv = cipher_a[-16:]
    msg_a = strip_pkcs_padding(cbc_decrypt(cipher_a[:-16], sha1(long_to_bytes(s))[:16], iv=iv), 16)

    # Forward cipher to the server and eavesdrop on response
    response = server.create_response(cipher_a)

    # Decrypt response
    msg_b = strip_pkcs_padding(cbc_decrypt(response[:-16], sha1(long_to_bytes(s))[:16], iv=iv), 16)

    # Forward response to user so they can verify
    user.verify_response(response)
    return msg_a, msg_b


def diffie_mitm():
    return attacker()
