import secrets
from math import gcd
from .modmath import modinv
from .primes import generate_prime, is_probable_prime
from .keygen import PublicKey, PrivateKey, PUBLIC_EXPONENT


def close_prime_key(bits=1024, gap=1000, e=PUBLIC_EXPONENT):
    half = bits // 2
    while True:
        p = generate_prime(half)
        candidate = p + gap
        if candidate % 2 == 0:
            candidate += 1
        while not is_probable_prime(candidate):
            candidate += 2
        q = candidate
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        try:
            d = modinv(e, phi)
        except ValueError:
            continue
        return PublicKey(n, e), PrivateKey(n, d, p, q)


def small_d_key(bits=1024, d_bits=None):
    half = bits // 2
    if d_bits is None:
        d_bits = max(16, bits // 4 - 4)
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        d = generate_prime(d_bits)
        if gcd(d, phi) != 1:
            continue
        try:
            e = modinv(d, phi)
        except ValueError:
            continue
        return PublicKey(n, e), PrivateKey(n, d, p, q)


def small_e_keys(bits=1024, e=3, count=3):
    keys = []
    moduli = set()
    half = bits // 2
    while len(keys) < count:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        if n in moduli:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue
        try:
            d = modinv(e, phi)
        except ValueError:
            continue
        moduli.add(n)
        keys.append((PublicKey(n, e), PrivateKey(n, d, p, q)))
    return keys


def shared_prime_keys(bits=1024, num_keys=10, num_shared=2):
    half = bits // 2
    shared_primes = [generate_prime(half) for _ in range(num_shared)]
    moduli = []
    for i in range(num_keys):
        if i < num_shared + 1 and len(shared_primes) > 0:
            p = shared_primes[i % len(shared_primes)]
        else:
            p = generate_prime(half)
        while True:
            q = generate_prime(half)
            if q != p:
                break
        moduli.append(p * q)
    return moduli
