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

print(repr(l))   