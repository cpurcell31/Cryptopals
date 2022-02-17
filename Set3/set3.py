from Crypto.Random import get_random_bytes
from base64 import b64decode
from random import randint
from Set3.challenge17 import select_random_string_and_encrypt, cbc_oracle_attack
from Set3.challenge18 import ctr_encrypt_decrypt
from Set3.challenge20 import fixed_nonce_ctr, fixed_nonce_attack
from Set3.challenge21 import MTRng19937
from Set3.challenge22 import gen_random_and_wait, find_timestamp_rng_seed
from Set3.challenge23 import mt19937_cloner
from Set3.challenge24 import mt19937_encrypt_decrypt, gen_password_reset_token, check_token_is_mt19937, \
    recover_mt19937_key_16bit


def set3_solutions():
    lines = list()
    with open('Data/data6.txt', 'r') as f:
        lines = f.readlines()
    key = get_random_bytes(16)
    cipher_str, iv = select_random_string_and_encrypt(lines, key)
    print(cbc_oracle_attack(cipher_str, iv, key))
    test_str = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    print(ctr_encrypt_decrypt(test_str, b'YELLOW SUBMARINE'))
    with open('Data/data7.txt', 'r') as f:
        lines = f.readlines()
    ciphers = list()
    for line in lines:
        line = b64decode(line)
        ciphers.append(fixed_nonce_ctr(line, key))
    print(fixed_nonce_attack(ciphers))
    rng = MTRng19937(seed=123)
    print(rng.get_random_number())
    random_num = gen_random_and_wait()
    print(find_timestamp_rng_seed(random_num))
    cloned_rng = mt19937_cloner()
    if cloned_rng is not None:
        print("RNG Cloning Success!")
    key = int.from_bytes(get_random_bytes(2), 'big')
    cipher_str = mt19937_encrypt_decrypt(b'testmessagelmfaoxdxd', key)
    print(cipher_str)
    plain_str = mt19937_encrypt_decrypt(cipher_str, key)
    print(plain_str)
    known_str = b'A'*14
    random_str = get_random_bytes(randint(2, 24))
    cipher_str = mt19937_encrypt_decrypt(random_str+known_str, key)
    print(recover_mt19937_key_16bit(cipher_str, known_str))
    token = gen_password_reset_token()
    print(check_token_is_mt19937(token))
    return








