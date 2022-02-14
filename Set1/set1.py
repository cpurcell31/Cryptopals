from binascii import unhexlify
from base64 import b64decode

from Set1.challenge1 import hex_to_b64
from Set1.challenge2 import fixed_xor
from Set1.challenge3 import single_byte_xor_solver
from Set1.challenge4 import detect_single_byte_xor
from Set1.challenge5 import encrypt_repeating_xor
from Set1.challenge6 import repeating_xor_solver, find_xor_key_size
from Set1.challenge7 import ecb_decrypt
from Set1.challenge8 import detect_ecb


def set1_solutions():
    result = hex_to_b64(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    print(result)
    result = fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
    print(result)
    byte_str = unhexlify("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    result, key, score = single_byte_xor_solver(byte_str)
    print(result)
    with open('Data/data.txt', 'r') as f:
        cipher_lines = list()
        lines = f.readlines()
        print(lines)
        for line in lines:
            cipher_lines.append(unhexlify(line.strip()))
        detect_single_byte_xor(cipher_lines)
    phrase = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    result = encrypt_repeating_xor(phrase, b'ICE')
    print(result)
    with open('Data/data2.txt', 'r') as f:
        lines = f.readlines()
        line = ''
        for x in lines:
            line += x.strip()

        # Find Key size
        key_size = find_xor_key_size(b64decode(line))
        key = repeating_xor_solver(b64decode(line), key_size)
        print(key)
    with open('Data/data3.txt', 'r') as f:
        lines = f.readlines()
        line = b''
        for x in lines:
            line += b64decode(x.strip())
        print(ecb_decrypt(line, b'YELLOW SUBMARINE'))
    with open('Data/data4.txt', 'r') as f:
        lines = f.readlines()
        index, result = detect_ecb(lines)
        print(index)
        print(result)
    print("Set 1 Complete")
    return










