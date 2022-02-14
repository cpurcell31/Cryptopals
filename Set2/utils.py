from Crypto.Util.number import long_to_bytes


def byte_str_xor(byte_str1, byte_str2):
    result = b''
    for i in range(len(byte_str1)):
        result += long_to_bytes(byte_str1[i] ^ byte_str2[i])
    return result
