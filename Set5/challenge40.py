from Crypto.Util.number import long_to_bytes
from Set5.challenge39 import rsa_keygen, rsa_encrypt
from Set5.utils import find_inv_pow


# Challenge 40

def rsa_secret_message_broadcast():
    byte_str = b'This is the secret message'
    n_list = list()
    c_list = list()
    for i in range(3):
        n, e, d = rsa_keygen()
        c = rsa_encrypt(n, e, byte_str)
        n_list.append(n)
        c_list.append(c)
    return n_list, c_list


def crt(n_list, c_list):
    m_list = list()
    for index, current in enumerate(n_list):
        prod = 1
        for n in (n_list[:index] + n_list[index+1:]):
            prod *= n
        m_list.append(prod)
    total = 0
    modulus = 1
    for n, c, m in zip(n_list, c_list, m_list):
        total += c * m * pow(m, -1, n)
        modulus *= n

    return total % modulus


def rsa_broadcast_attack():
    n_list, c_list = rsa_secret_message_broadcast()
    result = crt(n_list, c_list)
    print(long_to_bytes(find_inv_pow(result, len(n_list))))


