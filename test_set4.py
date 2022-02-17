from base64 import b64decode
from Crypto.Random import get_random_bytes
from Set3.challenge18 import ctr_encrypt_decrypt

from Set4.challenge25 import crack_edit_ctr
from Set4.challenge26 import ctr_bit_flip_attack
from Set4.challenge27 import mitm_cbc_attack
from Set4.challenge28 import sha1_mac
from Set4.challenge29 import sha1_length_extension_attack
from Set4.challenge30 import md4_mac, md4_length_extension_attack


def test_challenge25():
    key = get_random_bytes(16)
    cipher = ctr_encrypt_decrypt(b64decode('CRIwqt4+szDbqkNY+I0qbNXPg1XLaCM5etQ5Bt9DRFV/xIN2k8Go7jtArLIy'), key)
    assert crack_edit_ctr(cipher, key) == b'\t\x120\xaa\xde>\xb30\xdb\xaaCX\xf8\x8d*l\xd5\xcf\x83U\xcbh#9z\xd49\x06' \
                                          b'\xdfCDU\x7f\xc4\x83v\x93\xc1\xa8\xee;@\xac\xb22'


def test_challenge26():
    key = get_random_bytes(16)
    cipher = ctr_encrypt_decrypt(b64decode('CRIwqt4+szDbqkNY+I0qbNXPg1XLaCM5etQ5Bt9DRFV/xIN2k8Go7jtArLIy'), key)
    result = ctr_bit_flip_attack(cipher, crack_edit_ctr(cipher, key), key, 5)
    assert b'admin=true' in result


def test_challenge27():
    key = get_random_bytes(16)
    assert mitm_cbc_attack(b'WE ALL LIVE IN A YELLOW SUBMARINE A YELLOW SUBMARINE', key)


def test_challenge28():
    key = b'WE ALL LIVE IN A'
    result = sha1_mac(b'YELLOW SUBMARINE', key)
    assert result == b'\xe2\xa5\x90yt\xeb\x9c~I7\xd8\xb5(Ks\x91uo7\xda'


def test_challenge29():
    key = get_random_bytes(16)
    result = sha1_mac(b'YELLOW SUBMARINE', key)
    adjusted_msg, injected_hash = sha1_length_extension_attack(result, b'YELLOW SUBMARINE')
    assert sha1_mac(adjusted_msg, key) == injected_hash


def test_challenge30_md4():
    result = md4_mac(b'WE ALL LIVE IN A', b'YELLOW SUBMARINE')
    assert result == b'X\xae \xd4\xacR\xa3\x06\xe0\xd9\x8bv\x84\x05\x13\x92'


def test_challenge30_attack():
    key = get_random_bytes(16)
    result = md4_mac(key, b'YELLOW SUBMARINE')
    adjusted_msg, injected_md4 = md4_length_extension_attack(result, b'YELLOW SUBMARINE')
    assert md4_mac(key, adjusted_msg) == injected_md4
