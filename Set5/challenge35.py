from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Random import get_random_bytes
from Set5.utils import p, g, mod_exp
from Set4.challenge28 import sha1
from Set2.challenge10 import cbc_encrypt, cbc_decrypt
from Set2.challenge15 import strip_pkcs_padding


# Challenge 35

class User:
    def __init__(self):
        self.p = None
        self.g = None
        self.a = None
        self.big_a = None
        self.s = None
        self.msg = b'YELLOW SUBMARINE'

    def create_p_g(self):
        self.p = p
        self.g = g
        return p, g

    def acknowledge_p_g(self, pp, gg):
        if self.p == pp and self.g == gg:
            return 'ACK'
        else:
            self.p = pp
            self.g = gg
            return 'ACK'

    def compute_big_a(self):
        self.a = getPrime(1536) % self.p
        self.big_a = mod_exp(self.p, self.a, self.g)
        return self.big_a

    def compute_s(self, big_b):
        self.s = mod_exp(self.p, self.a, big_b)

    def create_msg(self):
        iv = get_random_bytes(16)
        cipher = cbc_encrypt(self.msg, sha1(long_to_bytes(self.s))[:16], iv=iv) + iv
        return cipher

    def verify_response(self, response):
        iv = response[-16:]
        plain = strip_pkcs_padding(cbc_decrypt(response[:-16], sha1(long_to_bytes(self.s))[:16], iv=iv), 16)
        assert plain == self.msg
        return True


class Server:
    def __init__(self):
        self.p = None
        self.g = None
        self.b = None
        self.big_b = None
        self.s = None

    def acknowledge_p_g(self, pp, gg):
        self.p = pp
        self.g = gg
        return pp, gg

    def compute_big_b(self):
        self.b = getPrime(1536) % self.p
        self.big_b = mod_exp(self.p, self.b, self.g)
        return self.big_b

    def compute_s(self, big_a):
        self.s = mod_exp(self.p, self.b, big_a)

    def create_response(self, cipher_a):
        iv = cipher_a[-16:]
        msg_a = strip_pkcs_padding(cbc_decrypt(cipher_a[:-16], sha1(long_to_bytes(self.s))[:16], iv=iv), 16)
        return cbc_encrypt(msg_a, sha1(long_to_bytes(self.s))[:16], iv=iv) + iv


def attacker(g_val):
    user = User()
    server = Server()

    pp, gg = user.create_p_g()

    if g_val == 1:
        # g = 1
        # S will always be 1
        gg = 1
    elif g_val == 2:
        # g = p
        # S will always be 0
        gg = pp
    elif g_val == 3:
        # g = p-1
        # S will be either 1 or p-1 but since a and b are prime S is always p-1
        gg = pp-1

    pp, gg = server.acknowledge_p_g(pp, gg)
    user.acknowledge_p_g(pp, gg)

    big_a = user.compute_big_a()
    big_b = server.compute_big_b()

    server.compute_s(big_a)
    user.compute_s(big_b)

    cipher_a = user.create_msg()

    # Decrypt cipher_a
    msg_a = b''
    if g_val == 1:
        msg_a = decrypt_modified_g(cipher_a, 1)
    elif g_val == 2:
        msg_a = decrypt_modified_g(cipher_a, 0)
    elif g_val == 3:
        msg_a = decrypt_modified_g(cipher_a, pp-1)

    response = server.create_response(cipher_a)

    # Decrypt response
    msg_b = b''
    if g_val == 1:
        msg_b = decrypt_modified_g(cipher_a, 1)
    elif g_val == 2:
        msg_b = decrypt_modified_g(cipher_a, 0)
    elif g_val == 3:
        msg_b = decrypt_modified_g(cipher_a, pp - 1)

    user.verify_response(response)
    return msg_a, msg_b


def decrypt_modified_g(cipher, s):
    iv = cipher[-16:]
    msg = strip_pkcs_padding(cbc_decrypt(cipher[:-16], sha1(long_to_bytes(s))[:16], iv=iv), 16)
    return msg


def negotiated_groups_mitm():
    msg_a, msg_b = attacker(1)
    assert msg_a == b'YELLOW SUBMARINE'
    msg_a, msg_b = attacker(2)
    assert msg_a == b'YELLOW SUBMARINE'
    msg_a, msg_b = attacker(3)
    assert msg_a == b'YELLOW SUBMARINE'
    return
