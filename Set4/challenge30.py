from Crypto.Random import get_random_bytes
from Set4.utils import rotate_left


# Challenge 30

def f(x, y, z):
    return (x & y) | (~x & z)


def g(x, y, z):
    return (x & y) | (x & z) | (y & z)


def h(x, y, z):
    return x ^ y ^ z


def md4(byte_msg):
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    msg_len = len(byte_msg)*8
    m = (-(len(byte_msg) + 8) % 64)
    adjusted_msg = (byte_msg + b'\x80' + (b"\x00" * (m-1)) + msg_len.to_bytes(8, 'little'))

    num_chunks = len(adjusted_msg) // 64
    chunks = [adjusted_msg[i*64:(i+1)*64] for i in range(num_chunks)]

    for chunk in chunks:
        words = [int.from_bytes(chunk[i * 4:(i + 1) * 4], 'little') for i in range(16)]

        aa = a
        bb = b
        cc = c
        dd = d

        # Round 1
        a = rotate_left(a + f(b, c, d) + words[0] & 0xFFFFFFFF, 3)
        d = rotate_left(d + f(a, b, c) + words[1] & 0xFFFFFFFF, 7)
        c = rotate_left(c + f(d, a, b) + words[2] & 0xFFFFFFFF, 11)
        b = rotate_left(b + f(c, d, a) + words[3] & 0xFFFFFFFF, 19)

        a = rotate_left(a + f(b, c, d) + words[4] & 0xFFFFFFFF, 3)
        d = rotate_left(d + f(a, b, c) + words[5] & 0xFFFFFFFF, 7)
        c = rotate_left(c + f(d, a, b) + words[6] & 0xFFFFFFFF, 11)
        b = rotate_left(b + f(c, d, a) + words[7] & 0xFFFFFFFF, 19)

        a = rotate_left(a + f(b, c, d) + words[8] & 0xFFFFFFFF, 3)
        d = rotate_left(d + f(a, b, c) + words[9] & 0xFFFFFFFF, 7)
        c = rotate_left(c + f(d, a, b) + words[10] & 0xFFFFFFFF, 11)
        b = rotate_left(b + f(c, d, a) + words[11] & 0xFFFFFFFF, 19)

        a = rotate_left(a + f(b, c, d) + words[12] & 0xFFFFFFFF, 3)
        d = rotate_left(d + f(a, b, c) + words[13] & 0xFFFFFFFF, 7)
        c = rotate_left(c + f(d, a, b) + words[14] & 0xFFFFFFFF, 11)
        b = rotate_left(b + f(c, d, a) + words[15] & 0xFFFFFFFF, 19)

        # Round 2
        a = rotate_left((a + g(b, c, d) + words[0] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = rotate_left((d + g(a, b, c) + words[4] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = rotate_left((c + g(d, a, b) + words[8] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = rotate_left((b + g(c, d, a) + words[12] + 0x5A827999) & 0xFFFFFFFF, 13)

        a = rotate_left((a + g(b, c, d) + words[1] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = rotate_left((d + g(a, b, c) + words[5] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = rotate_left((c + g(d, a, b) + words[9] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = rotate_left((b + g(c, d, a) + words[13] + 0x5A827999) & 0xFFFFFFFF, 13)

        a = rotate_left((a + g(b, c, d) + words[2] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = rotate_left((d + g(a, b, c) + words[6] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = rotate_left((c + g(d, a, b) + words[10] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = rotate_left((b + g(c, d, a) + words[14] + 0x5A827999) & 0xFFFFFFFF, 13)

        a = rotate_left((a + g(b, c, d) + words[3] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = rotate_left((d + g(a, b, c) + words[7] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = rotate_left((c + g(d, a, b) + words[11] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = rotate_left((b + g(c, d, a) + words[15] + 0x5A827999) & 0xFFFFFFFF, 13)

        # Round 3
        a = rotate_left((a + h(b, c, d) + words[0] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = rotate_left((d + h(a, b, c) + words[8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = rotate_left((c + h(d, a, b) + words[4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = rotate_left((b + h(c, d, a) + words[12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = rotate_left((a + h(b, c, d) + words[2] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = rotate_left((d + h(a, b, c) + words[10] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = rotate_left((c + h(d, a, b) + words[6] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = rotate_left((b + h(c, d, a) + words[14] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = rotate_left((a + h(b, c, d) + words[1] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = rotate_left((d + h(a, b, c) + words[9] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = rotate_left((c + h(d, a, b) + words[5] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = rotate_left((b + h(c, d, a) + words[13] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = rotate_left((a + h(b, c, d) + words[3] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = rotate_left((d + h(a, b, c) + words[11] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = rotate_left((c + h(d, a, b) + words[7] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = rotate_left((b + h(c, d, a) + words[15] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    h0 = a.to_bytes(4, 'little')
    h1 = b.to_bytes(4, 'little')
    h2 = c.to_bytes(4, 'little')
    h3 = d.to_bytes(4, 'little')

    return h0 + h1 + h2 + h3


def md4_extra_params(byte_msg, state, extra_length):
    a, b, c, d = state

    msg_len = (len(byte_msg)+extra_length) * 8
    m = (-(len(byte_msg) + 8) % 64)
    adjusted_msg = (byte_msg + b'\x80' + (b"\x00" * (m - 1)) + msg_len.to_bytes(8, 'little'))

    num_chunks = len(adjusted_msg) // 64
    chunks = [adjusted_msg[i * 64:(i + 1) * 64] for i in range(num_chunks)]

    for chunk in chunks:
        words = [int.from_bytes(chunk[i * 4:(i + 1) * 4], 'little') for i in range(16)]

        aa = a
        bb = b
        cc = c
        dd = d

        # Round 1
        a = rotate_left(a + f(b, c, d) + words[0] & 0xFFFFFFFF, 3)
        d = rotate_left(d + f(a, b, c) + words[1] & 0xFFFFFFFF, 7)
        c = rotate_left(c + f(d, a, b) + words[2] & 0xFFFFFFFF, 11)
        b = rotate_left(b + f(c, d, a) + words[3] & 0xFFFFFFFF, 19)

        a = rotate_left(a + f(b, c, d) + words[4] & 0xFFFFFFFF, 3)
        d = rotate_left(d + f(a, b, c) + words[5] & 0xFFFFFFFF, 7)
        c = rotate_left(c + f(d, a, b) + words[6] & 0xFFFFFFFF, 11)
        b = rotate_left(b + f(c, d, a) + words[7] & 0xFFFFFFFF, 19)

        a = rotate_left(a + f(b, c, d) + words[8] & 0xFFFFFFFF, 3)
        d = rotate_left(d + f(a, b, c) + words[9] & 0xFFFFFFFF, 7)
        c = rotate_left(c + f(d, a, b) + words[10] & 0xFFFFFFFF, 11)
        b = rotate_left(b + f(c, d, a) + words[11] & 0xFFFFFFFF, 19)

        a = rotate_left(a + f(b, c, d) + words[12] & 0xFFFFFFFF, 3)
        d = rotate_left(d + f(a, b, c) + words[13] & 0xFFFFFFFF, 7)
        c = rotate_left(c + f(d, a, b) + words[14] & 0xFFFFFFFF, 11)
        b = rotate_left(b + f(c, d, a) + words[15] & 0xFFFFFFFF, 19)

        # Round 2
        a = rotate_left((a + g(b, c, d) + words[0] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = rotate_left((d + g(a, b, c) + words[4] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = rotate_left((c + g(d, a, b) + words[8] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = rotate_left((b + g(c, d, a) + words[12] + 0x5A827999) & 0xFFFFFFFF, 13)

        a = rotate_left((a + g(b, c, d) + words[1] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = rotate_left((d + g(a, b, c) + words[5] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = rotate_left((c + g(d, a, b) + words[9] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = rotate_left((b + g(c, d, a) + words[13] + 0x5A827999) & 0xFFFFFFFF, 13)

        a = rotate_left((a + g(b, c, d) + words[2] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = rotate_left((d + g(a, b, c) + words[6] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = rotate_left((c + g(d, a, b) + words[10] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = rotate_left((b + g(c, d, a) + words[14] + 0x5A827999) & 0xFFFFFFFF, 13)

        a = rotate_left((a + g(b, c, d) + words[3] + 0x5A827999) & 0xFFFFFFFF, 3)
        d = rotate_left((d + g(a, b, c) + words[7] + 0x5A827999) & 0xFFFFFFFF, 5)
        c = rotate_left((c + g(d, a, b) + words[11] + 0x5A827999) & 0xFFFFFFFF, 9)
        b = rotate_left((b + g(c, d, a) + words[15] + 0x5A827999) & 0xFFFFFFFF, 13)

        # Round 3
        a = rotate_left((a + h(b, c, d) + words[0] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = rotate_left((d + h(a, b, c) + words[8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = rotate_left((c + h(d, a, b) + words[4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = rotate_left((b + h(c, d, a) + words[12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = rotate_left((a + h(b, c, d) + words[2] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = rotate_left((d + h(a, b, c) + words[10] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = rotate_left((c + h(d, a, b) + words[6] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = rotate_left((b + h(c, d, a) + words[14] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = rotate_left((a + h(b, c, d) + words[1] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = rotate_left((d + h(a, b, c) + words[9] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = rotate_left((c + h(d, a, b) + words[5] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = rotate_left((b + h(c, d, a) + words[13] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = rotate_left((a + h(b, c, d) + words[3] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        d = rotate_left((d + h(a, b, c) + words[11] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        c = rotate_left((c + h(d, a, b) + words[7] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        b = rotate_left((b + h(c, d, a) + words[15] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    h0 = a.to_bytes(4, 'little')
    h1 = b.to_bytes(4, 'little')
    h2 = c.to_bytes(4, 'little')
    h3 = d.to_bytes(4, 'little')

    return h0 + h1 + h2 + h3


def md4_mac(key, byte_msg):
    return md4(key + byte_msg)


def md4_padding_generator(byte_msg):
    msg_len = len(byte_msg) * 8
    m = (-(len(byte_msg) + 8) % 64)
    adjusted_msg = (byte_msg + b'\x80' + (b"\x00" * (m - 1)) + msg_len.to_bytes(8, 'little'))
    return adjusted_msg


def divide_md4_into_registers(md4_hash):
    blocks = [int.from_bytes(md4_hash[i*4:(i+1)*4], 'little') for i in range(5)]
    return blocks[0], blocks[1], blocks[2], blocks[3]


def md4_length_extension_attack(md4_hash, msg):
    # Create a "replacement key" with the guessed length
    random_key = get_random_bytes(16)

    # Divide the hash into its registers to recreate the state
    state = divide_md4_into_registers(md4_hash)

    # Recreate the padding of the original message
    glue_padding = md4_padding_generator(random_key + msg)[len(random_key) + len(msg):]

    # Create our injection and our control message
    injection = b';admin=true'
    extra_length = len(random_key) + len(msg) + len(glue_padding)
    return msg + glue_padding + injection, md4_extra_params(injection, state, extra_length)
