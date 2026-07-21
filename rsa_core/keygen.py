from .modmath import modinv
from .primes import generate_prime

PUBLIC_EXPONENT = 65537


class PublicKey:
    def __init__(self, n, e):
        self.n = n
        self.e = e


class PrivateKey:
    def __init__(self, n, d, p, q):
        self.n = n
        self.d = d
        self.p = p
        self.q = q


def generate_keypair(bits=2048, e=PUBLIC_EXPONENT):
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # try:
        #     d = modinv(e, phi)
        # except ValueError:
        #     continue
        return PublicKey(n, e), PrivateKey(n, d, p, q)


def encrypt_int(m, pub):
    if m >= pub.n:
        raise ValueError("message integer must be lesser than n")
    return pow(m, pub.e, pub.n)


def decrypt_int(c, priv):
    return pow(c, priv.d, priv.n)
