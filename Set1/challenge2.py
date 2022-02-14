from binascii import unhexlify, hexlify
from Crypto.Util.number import bytes_to_long, long_to_bytes


# Challenge 2

def fixed_xor(hex_str1, hex_str2):
    if len(hex_str1) != len(hex_str2):
        return "-1"
    bytes1 = bytes_to_long(unhexlify(hex_str1))
    bytes2 = bytes_to_long(unhexlify(hex_str2))
    result = long_to_bytes(bytes1 ^ bytes2)
    return hexlify(result)
