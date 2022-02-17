from Set2.challenge9 import pkcs_padding
from Set2.utils import byte_str_xor
from Set1.challenge7 import ecb_decrypt, ecb_encrypt


# Challenge 27

def cbc_encrypt_iv_is_key(byte_str, key):
    iv = key
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


def cbc_decrypt_iv_is_key(cipher_str, key):
    iv = key
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


def check_message_ascii(byte_str):
    for char in byte_str:
        if char < 32 or char > 127:
            raise ValueError(byte_str)
    return


def mitm_cbc_attack(byte_str, key):
    # Sender Side Command
    cipher_str = cbc_encrypt_iv_is_key(byte_str, key)

    # Attack intercepts (assumed 16 byte block size) and forwards new cipher
    num_blocks = len(cipher_str) // 16
    cipher_blocks = [cipher_str[i*16:(i+1)*16] for i in range(num_blocks)]
    new_cipher = cipher_blocks[0] + (b"\x00" * 16) + cipher_blocks[0]

    # Attack forwards new cipher to recipient and they decrypt it
    error = None
    try:
        plain_str = cbc_decrypt_iv_is_key(new_cipher, key)
        check_message_ascii(plain_str)
    except ValueError as e:
        error = e.args[0]

    # Attacker intercepts error message and uses it to find the key
    if error is not None:
        plain_blocks = [error[i*16:(i+1)*16] for i in range(num_blocks)]
        test_key = b''.join([(plain1 ^ plain3).to_bytes(1, 'big') for plain1, plain3 in zip(
            plain_blocks[0], plain_blocks[2])])
        print(cbc_decrypt_iv_is_key(cipher_str, test_key))
        return True
    return False
