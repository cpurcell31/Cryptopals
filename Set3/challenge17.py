from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes
from random import randint
from base64 import b64decode
from Set2.challenge9 import pkcs_padding
from Set2.challenge15 import validate_pkcs_padding, strip_pkcs_padding
from Set2.utils import byte_str_xor
from Set1.challenge7 import ecb_encrypt, ecb_decrypt


# Challenge 17

def cbc_encrypt_random_iv(byte_str, key):
    iv = get_random_bytes(16)
    padded_str = pkcs_padding(byte_str, 16)
    num_blocks = len(padded_str) // 16
    blocks = [padded_str[i*16:(i+1)*16] for i in range(num_blocks)]
    cipher_blocks = list()
    for i in range(num_blocks):
        if i == 0:
            cipher_blocks.append(ecb_encrypt(byte_str_xor(blocks[i], iv), key))
        else:
            cipher_blocks.append(ecb_encrypt(byte_str_xor(blocks[i], cipher_blocks[i-1]), key))
    result = b''
    for block in cipher_blocks:
        result += block
    return result, iv


def cbc_decrypt_check_padding(cipher_str, iv, key):
    num_blocks = len(cipher_str) // 16
    blocks = [cipher_str[i*16:(i+1)*16] for i in range(num_blocks)]
    plain_blocks = list()
    for i in range(num_blocks):
        if i == 0:
            plain_blocks.append(byte_str_xor(ecb_decrypt(blocks[i], key), iv))
        else:
            plain_blocks.append(byte_str_xor(ecb_decrypt(blocks[i], key), blocks[i-1]))
    result = b''
    for block in plain_blocks:
        result += block
    return validate_pkcs_padding(result, len(key))


def select_random_string_and_encrypt(string_list, key):
    chosen_str = string_list[randint(0, len(string_list)-1)]
    chosen_str = b64decode(chosen_str)
    return cbc_encrypt_random_iv(chosen_str, key)


def cbc_single_block_attack(cipher_block, key):
    zero_iv = b''
    if len(cipher_block) != len(key):
        return None

    for i in range(len(key)):
        result_xor = b''
        iv = b'\x00'*(len(key)-(i+1))

        for x in range(len(zero_iv)):
            xor_val = zero_iv[x] ^ (i + 1)
            result_xor += long_to_bytes(xor_val)

        for j in range(256):
            test_iv = iv + long_to_bytes(j) + result_xor
            if cbc_decrypt_check_padding(cipher_block, test_iv, key):
                test_iv2 = iv + long_to_bytes(j + 1) + result_xor
                if not cbc_decrypt_check_padding(cipher_block, test_iv2, key):
                    zero_iv = long_to_bytes(j ^ (i+1)) + zero_iv
                    break
    return zero_iv


def cbc_oracle_attack(cipher_str, iv, key):
    # Separate cipher_str into blocks
    block_size = len(key)
    num_blocks = len(cipher_str) // block_size
    cipher_blocks = [cipher_str[i*block_size:(i+1)*block_size] for i in range(num_blocks)]
    result = b''
    block_iv = iv
    for block in cipher_blocks:
        zero_iv = cbc_single_block_attack(block, key)
        plain = byte_str_xor(zero_iv, block_iv)
        result += plain
        block_iv = block
    return strip_pkcs_padding(result, block_size)
