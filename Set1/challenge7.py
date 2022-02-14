from Crypto.Cipher import AES


# Challenge 7

def ecb_decrypt(cipher_str, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(cipher_str)
    return plaintext


def ecb_encrypt(byte_str, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(byte_str)
    return ciphertext
