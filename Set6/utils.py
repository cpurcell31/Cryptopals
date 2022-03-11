def mod_exp(m, a, g):
    ''' This function computes g**a mod m using an efficient modexp algorithm'''
    A = 1
    powers = g
    while a != 0:
        if a & 0x1 != 0:
            A = (powers * A) % m
        powers = (powers * powers) % m
        a = a >> 1
    return A