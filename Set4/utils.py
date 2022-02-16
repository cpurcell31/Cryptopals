# Utils

def rotate_left(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))
