from Set2.challenge9 import pkcs_padding
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from random import randint


# Challenge 14

def prefixed_ecb_encrypter(byte_str, supplied_str, key):
    prefix_length = randint(16, 128)
    prefix = get_random_bytes(prefix_length)
    full_str = pkcs_padding(prefix+supplied_str+byte_str, 16)
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.encrypt(full_str)


def find_repeated_block(byte_str, key):
    repeat = False
    i = 1
    repeated_str = b''
    while not repeat:
        supplied_str = b'A' * i
        test_str = prefixed_ecb_encrypter(byte_str, supplied_str, key)
        num_blocks = len(test_str) // 16
        blocks = [test_str[j*16:(j+1)*16] for j in range(num_blocks)]
        if len(set(blocks)) != num_blocks:
            repeat = True
            block_list = list()
            for block in blocks:
                if block not in block_list:
                    block_list.append(block)
                else:
                    repeated_str = block
        i += 1
    return repeated_str


def remove_pre_signature(byte_str, oracle_str, repeated_block, key):
    signature = repeated_block*3
    while True:
        cipher_txt = prefixed_ecb_encrypter(byte_str, oracle_str, key)
        if signature in cipher_txt:
            known_blocks = [cipher_txt[y * 16:(y + 1) * 16] for y in range(len(cipher_txt) // 16)]
            cipher_txt = b''
            for block in known_blocks[known_blocks.index(repeated_block) + 3:]:
                cipher_txt += block
            return cipher_txt


def prefixed_ecb_oracle(byte_str):
    key = get_random_bytes(16)
    block_size = 16

    # Find what the block we have control of looks like and make a signature
    repeated_block = find_repeated_block(byte_str, key)
    signature = repeated_block*3

    # Making a test string to find the number of blocks in the message
    cipher_txt = remove_pre_signature(byte_str, b'A'*len(signature) + b'B'*block_size, repeated_block, key)
    num_blocks = len(cipher_txt) // block_size

    # Crack the cipher text
    result = b''
    for i in range(num_blocks):
        for j in range(block_size, 0, -1):
            supplied_str = b'A'*(len(signature)) + b'B' * (j-1)
            # Make a test string to get a baseline before we attack the individual byte
            cipher_txt = remove_pre_signature(byte_str, supplied_str, repeated_block, key)
            for x in range(256):
                oracle_block = supplied_str + result + x.to_bytes(1, byteorder='big')
                oracle_txt = remove_pre_signature(byte_str, oracle_block, repeated_block, key)
                if oracle_txt[:block_size * (i + 1)] == cipher_txt[:block_size * (i + 1)]:
                    result += x.to_bytes(1, byteorder='big')
                    break
    print(result)
    return
