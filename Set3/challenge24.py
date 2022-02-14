from time import time
from Set3.challenge21 import MTRng19937


# Challenge 24

def create_mt19937_key_stream(key, msg_len):
    rng = MTRng19937(seed=key)
    key_stream = b''
    while len(key_stream) < msg_len:
        key_stream += (rng.get_random_number() & 0xFF).to_bytes(2, byteorder='big')
    return key_stream


def mt19937_encrypt_decrypt(byte_str, key):
    key_stream = create_mt19937_key_stream(key, len(byte_str))
    result = bytes([x ^ y for x, y in zip(key_stream, byte_str)])
    return result


def recover_mt19937_key_16bit(cipher_str, known_str):
    for i in range(pow(2, 16)):
        result = mt19937_encrypt_decrypt(cipher_str, i)
        if known_str in result:
            return i
    return None


def gen_password_reset_token():
    seed = int(time())
    key_stream = create_mt19937_key_stream(seed, 16)
    return key_stream


def check_token_is_mt19937(token):
    for i in range(pow(2, 32), 1, -1):
        key_stream = create_mt19937_key_stream(i, 16)
        if key_stream == token:
            return True
    return False
