from Set1.challenge1 import hex_to_b64
from Set1.challenge2 import fixed_xor
from Set1.challenge3 import single_byte_xor_solver
from Set1.challenge4 import detect_single_byte_xor
from Set1.challenge5 import encrypt_repeating_xor
from Set1.challenge6 import compute_hamming_distance, find_xor_key_size, repeating_xor_solver
from Set1.challenge7 import ecb_decrypt
from Set1.challenge8 import detect_ecb
from Set1.data import data_decoded, ecb_result, ecb_decoded


def test_challenge1():
    assert hex_to_b64("49276d206b696c6c696e6720796f757220627261696e206c6"
                      "96b65206120706f69736f6e6f7573206d757368726f6f6d")\
           == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


def test_challenge2():
    assert fixed_xor("1c0111001f010100061a024b53535009181c",
                     "686974207468652062756c6c277320657965") == b'746865206b696420646f6e277420706c6179'


def test_challenge3():
    result, a, b = single_byte_xor_solver(b'\x1b77316?x\x15\x1b\x7f+x413=x9x(7-6<x7>x:9;76')
    assert result == b"Cooking MC's like a pound of bacon"


def test_challenge4():
    cipher_lines = [b'{ZB\x15A]TA\x15A]P\x15ETGAL\x15\\F\x15_@XE\\[R?']
    result = detect_single_byte_xor(cipher_lines)
    assert result == b'Now that the party is jumping\n'


def test_challenge5():
    phrase = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    result = encrypt_repeating_xor(phrase, b'ICE')
    assert result == b'\x0b67\'*+.cb,.ii*#i:*<c$ -b=c4<*&"c$\'\'e\'*(+/ C\ne.,e*1$3:e>+ \'c\x0ci+ (1e(c&0.\'(/'


def test_challenge6_hamming():
    b1 = b'this is a test'
    b2 = b'wokka wokka!!!'
    assert compute_hamming_distance(b1, b2) == 37


def test_challenge6():
    key_size = find_xor_key_size(data_decoded)
    key, result = repeating_xor_solver(data_decoded, key_size)
    assert key == b'Terminator X: Bring the noise'


def test_challenge7():
    result = ecb_decrypt(ecb_decoded, b'YELLOW SUBMARINE')
    assert result == ecb_result


def test_challenge8():
    ecb_str = ["d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641d"
                        "bf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82b"
                        "f5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06"
                        "f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"]
    index, result = detect_ecb(ecb_str)
    assert index == 0
