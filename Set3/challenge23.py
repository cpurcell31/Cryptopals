from Set3.challenge21 import MTRng19937
from Set3.utils import int_32


# Challenge 23

def un_temper(random_num):
    u = 11
    s = 7
    b = 0x9D2C5680
    t = 15
    c = 0xEFC60000
    l = 18

    x_a = random_num
    y3 = x_a ^ (x_a >> l)
    y3 = y3 ^ ((y3 << t) & c)
    y1 = y3
    mask = 0x7f
    for i in range(4):
        b_a = b & int_32(mask << int_32(7 * (int_32(i) + 1)))
        y1 = y1 ^ ((y1 << s) & b_a)
    y = y1
    for i in range(3):
        y = y ^ (y >> u)
    return y


def mt19937_cloner():
    rng = MTRng19937()
    state = [un_temper(rng.get_random_number()) for _ in range(624)]
    cloned_rng = MTRng19937(state=state)

    for i in range(15):
        if cloned_rng.get_random_number() != rng.get_random_number():
            cloned_rng = None
    return cloned_rng

