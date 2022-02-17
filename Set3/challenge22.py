from random import randint
from time import time, sleep
from Set3.challenge21 import MTRng19937


# Challenge 22

def gen_random_and_wait():
    sleep(randint(3, 100))
    t = int(time())
    rng = MTRng19937(seed=int(time()))
    sleep(randint(3, 100))
    return rng.get_random_number(), t


def find_timestamp_rng_seed(random_num):
    now = int(time())
    for i in range(3, 200):
        rng = MTRng19937(seed=now-i)
        test_num = rng.get_random_number()
        if test_num == random_num:
            return now-i
    return -1

