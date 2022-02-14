from Crypto.Util.number import long_to_bytes


# Challenge 5

def encrypt_repeating_xor(byte_input, key):
    result = b''
    key_index = 0
    for i in range(len(byte_input)):
        result += long_to_bytes(byte_input[i] ^ key[key_index])
        key_index += 1
        if key_index >= len(key):
            key_index = 0
    return result
