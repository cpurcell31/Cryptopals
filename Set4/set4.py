from Crypto.Random import get_random_bytes
from base64 import b64decode
from Set4.challenge25 import crack_edit_ctr
from Set4.challenge26 import ctr_bit_flip_attack
from Set4.challenge27 import mitm_cbc_attack
from Set4.challenge28 import sha1_mac
from Set4.challenge29 import sha1_length_extension_attack
from Set3.challenge18 import ctr_encrypt_decrypt


def set4_solutions():
    cipher_lines = list()
    key = get_random_bytes(16)
    with open("Data/data5.txt", 'r') as f:
        lines = f.readlines()
        for line in lines:
            cipher_lines.append(ctr_encrypt_decrypt(b64decode(line.strip()), key))
    print(crack_edit_ctr(cipher_lines[0], key))
    result = ctr_bit_flip_attack(cipher_lines[0], crack_edit_ctr(cipher_lines[0], key), key, 5)
    if b'admin=true' in result:
        print(result)
        print("Success!")
    mitm_cbc_attack(b'WE ALL LIVE IN A YELLOW SUBMARINE A YELLOW SUBMARINE', key)
    result = sha1_mac(b'YELLOW SUBMARINE', key)
    print(result)
    adjusted_msg, injected_hash = sha1_length_extension_attack(result, b'YELLOW SUBMARINE')
    if sha1_mac(adjusted_msg, key) == injected_hash:
        print(injected_hash)
        print("Successful Injection!")
    return
