from binascii import unhexlify
from base64 import b64encode


# Challenge 1

def hex_to_b64(hex_str):
    plain = unhexlify(hex_str)
    return b64encode(plain)
