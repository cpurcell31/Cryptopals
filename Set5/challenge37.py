from Crypto.Util.number import getPrime
from Set5.challenge36 import Server, Client
from Set5.utils import mod_exp


# Challenge 37


class FakeClient(Client):
    def calculate_big_a(self, x=0, y=1):
        self.big_a = mod_exp(self.n, y, x)
        return self.big_a

    def calculate_s(self, salt):
        self.calculate_big_k(0)
        return self.create_hmac(salt)


def srp_zero_key_attack():
    server = Server()
    client = FakeClient(b'bigboy@web.com', b'notthepassword')

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


def srp_n_key_attack():
    server = Server()
    client = FakeClient(b'bigboy@web.com', b'notthepassword')

    n, g, k = server.suggest_values()
    email = client.confirm_server_values(n, g, k)
    server.generate_v(email)

    # works for any power of n because - n mod n = 0
    big_a = client.calculate_big_a(x=n)
    big_b, salt = server.calculate_big_b()

    server.calculate_u_h(big_a)
    client.calculate_u_h(big_b)

    c_hmac = client.calculate_s(salt)
    server.calculate_big_k()
    server.validate_hmac(c_hmac)
