from Set1.challenge3 import single_byte_xor_solver


# Challenge 4

def detect_single_byte_xor(cipher_strings):
    results_list = list()
    score_list = list()
    for cipher_str in cipher_strings:
        result, key, score = single_byte_xor_solver(cipher_str)
        results_list.append(result)
        score_list.append(score)
    # print(results_list[score_list.index(min(score_list))])
    return results_list[score_list.index(min(score_list))]
