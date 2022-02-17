from math import ceil
from Set3.challenge18 import create_nonce_str
from Set1.challenge6 import repeating_xor_solver
from Set1.challenge7 import ecb_encrypt


# Challenge 20

def fixed_nonce_ctr(byte_str, key, nonce=0):
    block_size = len(key)
    nonce_str = create_nonce_str(nonce, block_size)
    num_blocks = ceil(len(byte_str) / block_size)
    byte_blocks = [byte_str[i * block_size:(i + 1) * block_size] for i in range(num_blocks)]
    cipher_blocks = list()
    for block in byte_blocks:
        key_stream = ecb_encrypt(nonce_str, key)
        cipher_blocks.append(bytes([stream_byte ^ block_byte for stream_byte, block_byte in zip(key_stream, block)]))
    cipher_str = b''
    for block in cipher_blocks:
        cipher_str += block
    return cipher_str


def fixed_nonce_attack(cipher_list):
    # Divide into columns
    min_len = len(min(cipher_list, key=len))
    truncated_ciphers = [cipher[:min_len] for cipher in cipher_list]
    concatenated_ciphers = b''.join(truncated_ciphers)

    # Repeated XOR key attack this concatenation
    key_stream = repeating_xor_solver(concatenated_ciphers, min_len)
    plain_list = list()
    for i in range(len(truncated_ciphers)):
        result = b''.join([(key_byte ^ trunc_byte).to_bytes(1, 'big')
                           for key_byte, trunc_byte in zip(key_stream[0], truncated_ciphers[i])])
        plain_list.append(result)
    return plain_list
