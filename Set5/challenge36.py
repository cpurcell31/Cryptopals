from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
import hashlib
import hmac
from Set5.utils import p192, mod_exp


# Challenge 36

class Client:
    def __init__(self, email, password):
        self.n = None
        self.g = None
        self.k = None
        self.a = None
        self.big_a = None
        self.big_b = None
        self.big_k = None
        self.u_h = None
        self.u = None
        self.email = email
        self.password = password

    def confirm_server_values(self, n, g, k):
        self.n = n
        self.g = g
        self.k = k
        return self.email

    def calculate_big_a(self):
        self.a = getPrime(196)
        self.big_a = mod_exp(self.n, self.a, self.g)
        return self.big_a

    def calculate_u_h(self, big_b):
        self.big_b = big_b
        h = hashlib.sha256(str(self.big_a).encode() + str(self.big_b).encode())
        self.u_h = h.hexdigest()
        self.u = int(self.u_h, 16)
        return

    def calculate_s(self, salt):
        h = hashlib.sha256(salt + self.password)
        x_h = h.hexdigest()
        x = int(x_h, 16)
        s = mod_exp(self.n, self.a + self.u * x, self.big_b - self.k * mod_exp(self.n, x, self.g))
        self.calculate_big_k(s)
        return self.create_hmac(salt)

    def calculate_big_k(self, s):
        h = hashlib.sha256(str(s).encode())
        self.big_k = h.hexdigest().encode()

    def create_hmac(self, salt):
        h2 = hmac.new(self.big_k, msg=salt, digestmod='sha256')
        return h2.hexdigest()


class Server:
    def __init__(self):
        self.n = None
        self.g = None
        self.k = None
        self.v = None
        self.salt = None
        self.b = None
        self.big_a = None
        self.big_b = None
        self.big_k = None
        self.u_h = None
        self.u = None
        self.hmac = None

        self.users = {'bigboy@web.com': b'123456789'}

    def suggest_values(self):
        self.n = p192
        self.g = 2
        self.k = 3
        return self.n, self.g, self.k

    def generate_v(self, email):
        self.salt = get_random_bytes(16)
        h = hashlib.sha256(self.salt + self.users[email.decode()])
        x_h = h.hexdigest()
        x = int(x_h, 16)
        self.v = mod_exp(self.n, x, self.g)
        return

    def calculate_big_b(self):
        self.b = getPrime(196)
        self.big_b = ((self.k * self.v) + mod_exp(self.n, self.b, self.g)) % self.n
        return self.big_b, self.salt

    def calculate_u_h(self, big_a):
        self.big_a = big_a
        h = hashlib.sha256(str(self.big_a).encode() + str(self.big_b).encode())
        self.u_h = h.hexdigest()
        self.u = int(self.u_h, 16)
        return

    def calculate_big_k(self):
        s = mod_exp(self.n, self.b, self.big_a * mod_exp(self.n, self.u, self.v))
        h = hashlib.sha256(str(s).encode())
        self.big_k = h.hexdigest().encode()
        self.create_hmac()

    def create_hmac(self):
        h2 = hmac.new(self.big_k, msg=self.salt, digestmod='sha256')
        self.hmac = h2.hexdigest()

    def validate_hmac(self, c_hmac):
        assert self.hmac == c_hmac
        return


def controller():
    client = Client(b'bigboy@web.com', b'123456789')
    server = Server()

    n, g, k = server.suggest_values()
    email = client.confirm_server_values(n, g, k)
    server.generate_v(email)

    big_a = client.calculate_big_a()
    big_b, salt = server.calculate_big_b()

    server.calculate_u_h(big_a)
    client.calculate_u_h(big_b)

    c_hmac = client.calculate_s(salt)
    server.calculate_big_k()
    server.validate_hmac(c_hmac)




