from Crypto.Util.number import long_to_bytes
from Set1.utils import expected_freq


# Challenge 3

def single_byte_xor_solver(byte_str):
    score_list = list()
    result_list = list()
    for i in range(256):
        result = b''
        for j in range(len(byte_str)):
            result += long_to_bytes(byte_str[j] ^ i)
        result_list.append(result)
        score_list.append(char_frequency_scorer(result.lower()))
    score_index = score_list.index(min(score_list))
    result = result_list[score_index]
    return result, score_index, min(score_list)


def char_frequency_scorer(plain_str):
    # Manipulate bytes to find only possible strings
    char_count = {i: plain_str.count(i) for i in set(plain_str)}

    # Find character frequency of the string if it is a possible solution
    char_freq = char_frequency(char_count, len(plain_str))

    # Score the frequency
    freq_diff = 0
    for key in char_freq.keys():
        if key in expected_freq.keys():
            freq_diff += abs(expected_freq[key]-char_freq[key])/26
        elif key == chr(32):
            freq_diff += 1
        else:
            if char_freq[key] > 0:
                freq_diff += 10
    return freq_diff


def char_frequency(char_dict, length):
    result_dict = {chr(i): 0 for i in range(256)}
    for key in char_dict.keys():
        result_dict[chr(key)] = char_dict[key] / length
    return result_dict
