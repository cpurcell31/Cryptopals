from math import ceil
from Set3.challenge18 import create_nonce_str
from Set1.challenge7 import ecb_encrypt


# Challenge 25

def ctr_key_stream_generator(key, nonce, length):
    num_blocks = ceil(length / len(key))
    key_stream = b''
    for i in range(num_blocks):
        nonce_str = create_nonce_str(nonce, len(key))
        key_stream += ecb_encrypt(nonce_str, key)
        nonce += 1
    return key_stream


def edit_cipher_ctr(cipher_str, key, nonce, offset, new_str):
    key_stream = ctr_key_stream_generator(key, nonce, len(cipher_str)+len(new_str))
    new_cipher_bytes = [new_byte ^ stream_byte for new_byte, stream_byte in zip(new_str, key_stream[offset:])]
    new_cipher = b''
    for x in new_cipher_bytes:
        new_cipher += x.to_bytes(1, 'big')
    result_cipher = cipher_str[:offset] + new_cipher
    if len(new_str)+offset < len(cipher_str):
        result_cipher += cipher_str[offset+len(new_cipher):]
    return result_cipher


def crack_edit_ctr(cipher_str, key):
    input_str = b'\x00'*len(cipher_str)
    key_stream = edit_cipher_ctr(cipher_str, key, 0, 0, input_str)
    plain_bytes = [cipher_byte ^ stream_byte for cipher_byte, stream_byte in zip(cipher_str, key_stream)]
    plain_str = b''
    for x in plain_bytes:
        plain_str += x.to_bytes(1, 'big')
    return plain_str

