from base64 import b64decode
from Crypto.Random import get_random_bytes
from time import time

from Set3.challenge17 import cbc_oracle_attack, cbc_encrypt_random_iv
from Set3.challenge18 import ctr_encrypt_decrypt
from Set3.challenge20 import fixed_nonce_ctr, fixed_nonce_attack
from Set3.challenge21 import MTRng19937
from Set3.challenge22 import find_timestamp_rng_seed, gen_random_and_wait
from Set3.challenge23 import mt19937_cloner
from Set3.challenge24 import mt19937_encrypt_decrypt

from Set3.data import b64_lines


def test_challenge17():
    key = get_random_bytes(16)
    cipher_str = b64decode("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=")
    cipher_str, iv = cbc_encrypt_random_iv(cipher_str, key)
    result = cbc_oracle_attack(cipher_str, iv, key)
    assert result == b"000007I'm on a roll, it's time to go solo"


def test_challenge18():
    test_str = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    assert ctr_encrypt_decrypt(test_str, b'YELLOW SUBMARINE') == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


def test_challenge20():
    key = get_random_bytes(16)
    ciphers = list()
    for line in b64_lines:
        line = b64decode(line)
        ciphers.append(fixed_nonce_ctr(line, key))
    assert fixed_nonce_attack(ciphers)[0] == b'I have met them at c'


def test_challenge21():
    rng = MTRng19937(seed=123)
    assert rng.get_random_number() == 2991312382


def test_challenge22():
    rng, t = gen_random_and_wait()
    assert find_timestamp_rng_seed(rng) == t


def test_challenge23():
    cloned_rng = mt19937_cloner()
    assert cloned_rng is not None


def test_challenge24():
    key = int.from_bytes(get_random_bytes(4), 'big')
    random_str = get_random_bytes(16)
    cipher_str = mt19937_encrypt_decrypt(random_str, key)
    plain_str = mt19937_encrypt_decrypt(cipher_str, key)
    assert plain_str == random_str


