from Set3.challenge18 import ctr_encrypt_decrypt


# Challenge 26

def ctr_bit_flip_attack(cipher_str, known_plain, key, inject_offset):
    inject_str = b';admin=true;'
    # XOR our injection with the spot we want to insert it in the known plaintext
    inject_bytes = b''.join([(known_byte ^ result_byte).to_bytes(1, 'big') for known_byte, result_byte in zip(
        known_plain[inject_offset:], inject_str)])

    # XOR the previous result with the cipher string to adjust the required cipher bytes
    new_cipher_bytes = b''.join([(inject_byte ^ cipher_byte).to_bytes(1, 'big') for inject_byte, cipher_byte in zip(
        inject_bytes, cipher_str[inject_offset:])])

    # Concatenate everything to create our proper cipher_str
    new_cipher = cipher_str[:inject_offset] + new_cipher_bytes + cipher_str[inject_offset+len(new_cipher_bytes):]
    new_plain = ctr_encrypt_decrypt(new_cipher, key)
    return new_plain
