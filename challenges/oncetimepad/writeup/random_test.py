#!/usr/bin/env python3

import random
SEED = 1737144000

print("randint")
random.seed(SEED)
for i in range(10):
    print(repr(random.randint(0, 255)))

print("randbytes")
random.seed(SEED)
l = list(random.randbytes(10))
for b in l:
    print(repr(b))

print("getrandbits")
random.seed(SEED)
for i in range(10):
    print(repr(int(random.getrandbits(8))))

print("random")
random.seed(SEED)
for i in range(10):
    print(repr(int(random.random() * 256)))

