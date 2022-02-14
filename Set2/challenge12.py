from Set2.challenge9 import pkcs_padding
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# Challenge 12

def ecb_encrypt_unknown_key(byte_str, supplied_str, unknown_key):
    full_str = pkcs_padding((supplied_str + byte_str), 16)
    cipher = AES.new(unknown_key, AES.MODE_ECB)
    cipher_str = cipher.encrypt(full_str)
    return cipher_str


def find_block_size(byte_str, ct_length, key):
    block_size = -1
    supplied_str = b''
    for i in range(256):
        supplied_str += b'A'
        cipher_txt = ecb_encrypt_unknown_key(byte_str, supplied_str, key)
        if len(cipher_txt) != ct_length:
            block_size = len(cipher_txt) - ct_length
            break
    return block_size


def ecb_oracle_attack(byte_str):
    key = get_random_bytes(16)
    cipher_str = ecb_encrypt_unknown_key(byte_str, b'', key)
    ct_length = len(cipher_str)
    block_size = find_block_size(byte_str, ct_length, key)
    if block_size == -1:
        return -1
    num_blocks = ct_length // block_size
    result = b''
    for x in range(num_blocks):
        for i in range(block_size, 0, -1):
            test_input = b'A' * (i-1)
            test_cipher = ecb_encrypt_unknown_key(byte_str, test_input, key)
            for j in range(256):
                oracle_block = test_input + result + j.to_bytes(1, byteorder='big')
                cipher_txt = ecb_encrypt_unknown_key(byte_str, oracle_block, key)
                if cipher_txt[:block_size*(x+1)] == test_cipher[:block_size*(x+1)]:
                    result += j.to_bytes(1, byteorder='big')
                    break
    print(result)
    return

