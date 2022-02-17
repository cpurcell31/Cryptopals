from Crypto.Random import get_random_bytes

from Set2.challenge9 import pkcs_padding
from Set2.challenge10 import cbc_decrypt, cbc_encrypt
from Set2.challenge12 import ecb_oracle_attack
from Set2.challenge13 import make_profile_admin
from Set2.challenge14 import prefixed_ecb_oracle
from Set2.challenge15 import strip_pkcs_padding
from Set2.challenge16 import prepend_append_nonsense, decrypt_and_check_admin, cbc_bit_flip_attack

from Set2.data import data_decoded, cbc_decrypted, byte_str, ecb_decrypted


def test_challenge9():
    assert pkcs_padding(b'YELLOW SUBMARINE', 16) == b'YELLOW SUBMARINE'+b'\x10'*16


def test_challenge10():
    result = cbc_decrypt(data_decoded, b'YELLOW SUBMARINE')
    assert result == cbc_decrypted


def test_challenge12():
    result = ecb_oracle_attack(byte_str)
    assert result == ecb_decrypted


def test_challenge13():
    profile = make_profile_admin("          foo@bar.com     admin              ")
    assert profile['role'] == 'admin'


def test_challenge14():
    result = prefixed_ecb_oracle(byte_str)
    assert result in ecb_decrypted


def test_challenge15():
    text = strip_pkcs_padding(b'abcdefghikl\x05\x05\x05\x05\x05', 16)
    assert text == b'abcdefghikl'


def test_challenge16():
    key = get_random_bytes(16)
    cipher_str = cbc_encrypt(prepend_append_nonsense("&admin.true&").encode(), key)
    new_cipher = cbc_bit_flip_attack(cipher_str)
    assert decrypt_and_check_admin(new_cipher, key)
