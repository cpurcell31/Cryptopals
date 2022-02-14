from binascii import unhexlify


# Challenge 8

def detect_ecb(hex_list):
    # Turn hex ciphers into byte form
    cipher_list = list()
    if isinstance(hex_list, type(list())):
        for line in hex_list:
            cipher_list.append(unhexlify(line.strip()))
    else:
        cipher_list.append(hex_list)

    ecb_cipher = None
    repeat_index = -1
    for cipher in cipher_list:
        # Divide cipher into blocks of 16
        num_blocks = len(cipher)//16
        blocks = [cipher[i*16:(i+1)*16] for i in range(num_blocks)]

        # Check for repeating blocks
        if len(set(blocks)) != num_blocks:
            ecb_cipher = cipher
    if ecb_cipher is not None:
        repeat_index = cipher_list.index(ecb_cipher)
    return repeat_index, ecb_cipher
