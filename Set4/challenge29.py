from Crypto.Random import get_random_bytes
from math import ceil
from Set4.utils import rotate_left


# Challenge 29

def sha1_padding_generator(byte_msg):
    msg_len = len(byte_msg)*8
    m = -(msg_len + 1 + 64) % 512
    adjusted_msg = (byte_msg + bytes([0b10000000]) + b'\x00' * (m // 8) + msg_len.to_bytes(8, 'big'))
    return adjusted_msg


def divide_mac_into_registers(sha_hash):
    blocks = [int.from_bytes(sha_hash[i*4:(i+1)*4], 'big') for i in range(5)]
    return blocks[0], blocks[1], blocks[2], blocks[3], blocks[4]


def sha1_extra_params(byte_msg, registers_tuple, extra_length):
    h0, h1, h2, h3, h4 = registers_tuple
    msg_len = (len(byte_msg) + extra_length)*8
    m = -(msg_len + 1 + 64) % 512
    adjusted_msg = (byte_msg + bytes([0b10000000]) + b'\x00' * (m // 8) + msg_len.to_bytes(8, 'big'))

    num_chunks = ceil(len(adjusted_msg) / 64)
    chunks = [adjusted_msg[i * 64:(i + 1) * 64] for i in range(num_chunks)]
    for chunk in chunks:
        words = [int.from_bytes(chunk[i * 4:(i + 1) * 4], 'big') for i in range(16)]
        for i in range(16, 80):
            words.append(rotate_left((words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]), 1))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (rotate_left(a, 5) + f + e + k + words[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = rotate_left(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    hh = b''.join(H.to_bytes(4, 'big') for H in [h0, h1, h2, h3, h4])
    return hh


def sha1_length_extension_attack(sha_hash, msg):
    # Create a "replacement key" with the guessed length
    random_key = get_random_bytes(16)

    # Divide the hash into its registers to recreate the state
    state = divide_mac_into_registers(sha_hash)

    # Recreate the padding of the original message
    glue_padding = sha1_padding_generator(random_key + msg)[len(random_key)+len(msg):]

    # Create our injection and our control message
    injection = b';admin=true'
    extra_length = len(random_key) + len(msg) + len(glue_padding)
    return msg + glue_padding + injection, sha1_extra_params(injection, state, extra_length)

