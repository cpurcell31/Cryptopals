from Set2.challenge9 import pkcs_padding
from Set2.utils import byte_str_xor
from Set1.challenge7 import ecb_encrypt, ecb_decrypt


# Challenge 10

def cbc_encrypt(byte_str, key):
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
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
    return result


def cbc_decrypt(cipher_str, key):
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
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
    return result
