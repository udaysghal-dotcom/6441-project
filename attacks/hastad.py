import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from math import gcd

from rsa_core.modmath import crt, integer_nth_root, mod_exp, modinv
from rsa_core.keygen import generate_keypair
from rsa_core.primes import generate_prime


def hastad_broadcast(ciphertexts, moduli, e):
    # need at least e ciphertext/modulus pairs
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError(f"need at least {e} ciphertext/modulus pairs")

    combined = crt(ciphertexts[:e], moduli[:e])

    root, exact = integer_nth_root(combined, e)
    if not exact:
        return None
    return root


if __name__ == "__main__":
    e = 3
    m_original = 42424242

    # generate 3 keypairs with e=3 and pairwise coprime moduli
    keys = []
    for _ in range(e):
        half = 256
        while True:
            p = generate_prime(half)
            q = generate_prime(half)
            if p != q:
                n = p * q
                phi = (p - 1) * (q - 1)
                # e must be coprime with phi
                if gcd(e, phi) == 1:
                    d = modinv(e, phi)
                    keys.append((n, d))
                    break

    moduli = [k[0] for k in keys]
    ciphertexts = [mod_exp(m_original, e, n) for n in moduli]

    m_recovered = hastad_broadcast(ciphertexts, moduli, e)
    assert m_recovered == m_original
    print(f"hastad broadcast attack succeeded: recovered m = {m_recovered}")
