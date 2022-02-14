from Set2.challenge9 import pkcs_padding
from Set2.challenge10 import cbc_decrypt, cbc_encrypt
from Set2.challenge12 import ecb_oracle_attack
from Set2.challenge13 import make_profile_admin
from Set2.challenge14 import prefixed_ecb_oracle
from Set2.challenge15 import strip_pkcs_padding
from Set2.challenge16 import prepend_append_nonsense, decrypt_and_check_admin, cbc_bit_flip_attack
from Crypto.Random import get_random_bytes
from base64 import b64decode


def set2_solutions():
    print(pkcs_padding(b'\x01\x01\x01\x01', 16))
    with open('Data/data5.txt', 'r') as f:
        lines = f.readlines()
        line = ''
        for x in lines:
            line += x.strip()
        line = b64decode(line)
        print(cbc_decrypt(line, b'YELLOW SUBMARINE'))
    input_str = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzd' \
                'GFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK '
    byte_str = b64decode(input_str)
    ecb_oracle_attack(byte_str)
    profile = make_profile_admin("          foo@bar.com     admin              ")
    print(profile)
    prefixed_ecb_oracle(byte_str)
    print(strip_pkcs_padding(b'abcdefghikl\x05\x05\x05\x05\x05', 16))
    key = get_random_bytes(16)
    cipher_str = cbc_encrypt(prepend_append_nonsense("&admin.true&").encode(), key)
    print(decrypt_and_check_admin(cipher_str, key))
    print(decrypt_and_check_admin(cbc_bit_flip_attack(cipher_str), key))
    print("Set 2 Complete")
    return





















