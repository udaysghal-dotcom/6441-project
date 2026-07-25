import math
from rsa_core.weakkeys import (
    close_prime_key,
    shared_prime_keys,
    small_d_key,
    small_e_keys,
)

def test_close_prime_key():
    pub, priv = close_prime_key(bits=256, gap=500)
    assert priv.p * priv.q == pub.n
    assert abs(priv.p - priv.q) <= 1000
    phi = (priv.p - 1) * (priv.q - 1)
    assert (pub.e * priv.d) % phi == 1

def test_small_d_key():
    pub, priv = small_d_key(bits=256, d_bits=32)
    assert priv.p * priv.q == pub.n
    assert priv.d.bit_length() <= 32
    phi = (priv.p - 1) * (priv.q - 1)
    assert (pub.e * priv.d) % phi == 1

def test_small_e_keys():
    e = 3
    count = 4
    keys = small_e_keys(bits=256, e=e, count=count)
    assert len(keys) == count
    moduli = [pub.n for pub, _ in keys]
    for pub, priv in keys:
        assert pub.e == e
        assert priv.p * priv.q == pub.n
    for i in range(count):
        for j in range(i + 1, count):
            assert math.gcd(moduli[i], moduli[j]) == 1

def test_shared_prime_keys():
    num_keys = 5
    num_shared = 2
    corpus = shared_prime_keys(bits=256, num_keys=num_keys, num_shared=num_shared)
    assert len(corpus) == num_keys
    shared_pairs = 0
    for i in range(num_keys):
        for j in range(i + 1, num_keys):
            if math.gcd(corpus[i], corpus[j]) > 1:
                shared_pairs += 1
    assert shared_pairs >= 1
