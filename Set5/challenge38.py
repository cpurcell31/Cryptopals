import hashlib
import hmac
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
from Set5.utils import mod_exp, p192


# Challenge 38

class SimplifiedClient:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.a = getPrime(196)

        self.n = None
        self.g = None
        self.big_a = None

    def set_values(self, n, g):
        self.n = n
        self.g = g

    def calculate_big_a(self):
        self.big_a = mod_exp(self.n, self.a, self.g)
        return self.big_a, self.email

    def calculate_s(self, salt, big_b, u):
        x = int(hashlib.sha256(salt + self.password).hexdigest(), 16)
        s = mod_exp(self.n, self.a + u * x, big_b)
        return self.create_hmac(s, salt)

    @staticmethod
    def create_hmac(s, salt):
        big_k = hashlib.sha256(str(s).encode()).hexdigest().encode()
        h = hmac.new(big_k, msg=salt, digestmod='sha256')
        return h.hexdigest()


class SimplifiedServer:
    def __init__(self):
        self.users = {'bigboy@web.com': b'1234567890'}
        self.n = p192
        self.g = 2
        self.b = getPrime(196)

        self.big_a = None
        self.big_b = None
        self.salt = None
        self.v = None
        self.u = getPrime(128)
        self.hmac = None

    def send_values(self):
        return self.n, self.g

    def calculate_v_and_big_b(self, email, big_a):
        self.salt = get_random_bytes(16)
        x = int(hashlib.sha256(self.salt + self.users[email]).hexdigest(), 16)
        self.v = mod_exp(self.n, x, self.g)

        self.big_a = big_a
        self.big_b = mod_exp(self.n, self.b, self.g)
        return self.salt, self.big_b, self.u

    def calculate_big_k(self):
        s = mod_exp(self.n, self.b, self.big_a * mod_exp(self.n, self.u, self.v))
        big_k = hashlib.sha256(str(s).encode()).hexdigest().encode()
        self.create_hmac(big_k)

    def create_hmac(self, big_k):
        h = hmac.new(big_k, msg=self.salt, digestmod='sha256')
        self.hmac = h.hexdigest()

    def validate_hmac(self, c_hmac):
        if self.hmac == c_hmac:
            return b'Authenticated'
        else:
            return b'Authentication Failed'


def simplified_srp_controller():
    server = SimplifiedServer()
    client = SimplifiedClient('bigboy@web.com', b'1234567890')

    n, g = server.send_values()
    client.set_values(n, g)

    big_a, email = client.calculate_big_a()
    salt, big_b, u = server.calculate_v_and_big_b(email, big_a)

    c_hmac = client.calculate_s(salt, big_b, u)
    server.calculate_big_k()
    result = server.validate_hmac(c_hmac)

    if result == b'Authenticated':
        print(result)
        return True
    else:
        print(result)
        return False


def mitm_simplified_srp():
    server = SimplifiedServer()
    client = SimplifiedClient('bigboy@web.com', b'1234567890')

    n, g = server.send_values()
    client.set_values(n, g)

    big_a, email = client.calculate_big_a()
    salt, big_b, u = server.calculate_v_and_big_b(email, big_a)

    b = 23
    fake_big_b = mod_exp(n, b, g)

    c_hmac = client.calculate_s(salt, fake_big_b, u)
    server.calculate_big_k()

    result = dictionary_attack(c_hmac, n, g, b, big_a, salt, u)

    print("Password: " + result)
    return


def dictionary_attack(c_hmac, n, g, b, big_a, salt, u):
    with open('Set5/password_dictionary.txt', 'r') as f:
        words = f.readlines()

    result = None
    for word in words:
        x = int(hashlib.sha256(salt + word.encode().strip()).hexdigest(), 16)
        v = mod_exp(n, x, g)
        s = str(mod_exp(n, b, big_a * mod_exp(n, u, v))).encode()
        big_k = hashlib.sha256(s).hexdigest().encode()
        r_hmac = hmac.new(big_k, msg=salt, digestmod='sha256').hexdigest()
        if c_hmac == r_hmac:
            result = word
            break
    return result




