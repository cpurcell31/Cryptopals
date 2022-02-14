# Challenge 15

def validate_pkcs_padding(byte_str, block_size):
    final_value = byte_str[-1]
    if final_value > block_size:
        return False
    for i in byte_str[-final_value:]:
        if i != final_value:
            return False
    return True


def strip_pkcs_padding(byte_str, block_size):
    if not validate_pkcs_padding(byte_str, block_size):
        return byte_str
    num_strip = byte_str[-1]
    return byte_str[:-num_strip]