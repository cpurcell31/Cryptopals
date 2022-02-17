from Crypto.Util.number import long_to_bytes, bytes_to_long
from Set1.challenge4 import single_byte_xor_solver
from Set1.challenge5 import encrypt_repeating_xor


# Challenge 6

def repeating_xor_solver(bytes_str, key_size):
    # Break up ciphertext into key_size blocks
    blocks = [bytes_str[i:i+key_size] for i in range(0, len(bytes_str), key_size)]
    # Transpose key_size blocks into blocks ordered by byte
    ordered_blocks = [b'']*key_size
    for i in range(len(ordered_blocks)):
        for j in range(len(blocks)):
            if i >= len(blocks[j]):
                break
            ordered_blocks[i] += blocks[j][i].to_bytes(1, 'big')

    # Solve each block with single character xor solver
    key = b""
    for i in range(len(ordered_blocks)):
        result, key_part, score = single_byte_xor_solver(ordered_blocks[i])
        key += key_part.to_bytes(1, byteorder='big')
    # Decrypt
    result = encrypt_repeating_xor(bytes_str, key)
    return key, result


def find_xor_key_size(bytes_str):
    distances = list()
    key_sizes = list()
    dist_key = dict()
    for i in range(2, 40):
        # why does +1 work better here?????
        b1 = bytes_str[0:i+1]
        b2 = bytes_str[i:i*2+1]
        b3 = bytes_str[i*2:i*3+1]
        b4 = bytes_str[i*3:i*4+1]

        # Average the distances from the 4 blocks of bytes
        distances.append(
            (compute_hamming_distance(b1, b2) / i) +
            (compute_hamming_distance(b1, b3) / i) +
            (compute_hamming_distance(b1, b4) / i) +
            (compute_hamming_distance(b2, b3) / i) +
            (compute_hamming_distance(b2, b4) / i) +
            (compute_hamming_distance(b3, b4) / i) / 6
        )
        key_sizes.append(i)
    return key_sizes[distances.index(min(distances))]


def compute_hamming_distance(b1, b2):
    distance_result_str = bytes_to_long(b1) ^ bytes_to_long(b2)
    binary_rep = bin(distance_result_str)[2:]
    distance = 0
    for char in binary_rep:
        if char == '1':
            distance += 1
    return distance



