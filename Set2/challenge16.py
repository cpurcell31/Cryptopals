from Set2.challenge10 import cbc_decrypt
from Crypto.Util.number import long_to_bytes


# Challenge 16

def prepend_append_nonsense(input_str):
    prepend = "comment1=cooking%20MCs;userdata="
    append = ";comment2=%20like%20a%20pound%20of%20bacon"
    return prepend + input_str.replace(";", "%3B").replace("=", "%3D") + append


def decrypt_and_check_admin(cipher_str, key):
    plain_txt = cbc_decrypt(cipher_str, key)
    if b'admin=true' in plain_txt:
        return True
    return False


def cbc_bit_flip_attack(cipher_str):
    num_blocks = len(cipher_str) // 16
    cipher_blocks = [cipher_str[j*16:(j+1)*16] for j in range(num_blocks)]
    block = cipher_blocks[1]
    block = block[:6] + long_to_bytes(cipher_blocks[1][6] ^ 19) + block[7:]
    cipher_blocks[1] = block
    cipher_str = b''
    for block in cipher_blocks:
        cipher_str += block
    return cipher_str
