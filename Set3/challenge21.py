from Set3.utils import int_32


# Challenge 21

class MTRng19937:
    def __init__(self, state=None, seed=5489):
        self.n = 624
        self.state = [0]*self.n
        self.f = 1812433253
        self.a = 0x9908B0DF
        self.m = 397
        self.u = 11
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
        self.d = 0xFFFFFFFF
        self.index = 624
        self.lower_mask = (1 << 31) - 1
        self.upper_mask = 1 << 31
        if state is None:
            self.seed_state(seed)
        else:
            self.state = state
        return

    def seed_state(self, seed):
        self.state[0] = seed
        for i in range(1, self.n):
            self.state[i] = int_32(self.f * (self.state[i - 1] ^ (self.state[i - 1] >> 30)) + i)
        return

    def get_random_number(self):
        if self.index >= self.n:
            self.twist()
        y = self.state[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += 1
        return int_32(y)

    def twist(self):
        for i in range(self.n):
            x = (self.state[i] & self.upper_mask) + (self.state[(i+1) % self.n] & self.lower_mask)
            x_a = x >> 1
            if x % 2 != 0:
                x_a = x_a ^ self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ x_a
        self.index = 0
        return
