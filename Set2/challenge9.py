# Challenge 9

def pkcs_padding(byte_str, block_size):
    # find needed length
    padded_str = byte_str
    pad_size = block_size - (len(byte_str) % block_size)

    # Pad with bytes
    padded_str += pad_size.to_bytes(1, byteorder='big')*pad_size
    return padded_str
