from math import ceil
from Set1.challenge7 import ecb_encrypt


# Challenge 18

def create_nonce_str(nonce, block_size):
    nonce_str = nonce.to_bytes(8, byteorder='little')
    nonce_len = block_size - len(nonce_str)
    return (b"\x00" * nonce_len) + nonce_str


def ctr_encrypt_decrypt(byte_str, key, nonce=0):
    block_size = len(key)
    nonce_str = create_nonce_str(nonce, block_size)
    num_blocks = ceil(len(byte_str) / block_size)
    byte_blocks = [byte_str[i*block_size:(i+1)*block_size] for i in range(num_blocks)]
    cipher_blocks = list()
    for block in byte_blocks:
        key_stream = ecb_encrypt(nonce_str, key)
        cipher_blocks.append(bytes([stream_byte ^ block_byte for stream_byte, block_byte in zip(key_stream, block)]))
        nonce += 1
        nonce_str = create_nonce_str(nonce, block_size)
    cipher_str = b''
    for block in cipher_blocks:
        cipher_str += block
    return cipher_str
