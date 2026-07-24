import sys, os
import math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rsa_core.modmath import modinv, mod_exp
from rsa_core.primes import generate_prime


def _continued_fraction(num, den):
    # yields the coefficients of the continued fraction of num/den
    while den:
        q = num // den
        yield q
        num, den = den, num - q * den


def _convergents(cf):
    # yields (numerator, denominator) convergents from cf coefficients
    p_prev, p_curr = 0, 1
    q_prev, q_curr = 1, 0
    for a in cf:
        p_prev, p_curr = p_curr, a * p_curr + p_prev
        q_prev, q_curr = q_curr, a * q_curr + q_prev
        yield p_curr, q_curr


def wiener_attack(n, e):
    for k, d in _convergents(_continued_fraction(e, n)):
        if k == 0 or d == 0:
            continue

        # ed - 1 must be divisible by k
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # p + q = n - phi + 1, p * q = n
        s = n - phi + 1
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue

        sqrt_disc = math.isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue

        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2
        if p * q == n:
            return d, p, q

    return None


if __name__ == "__main__":
    bits = 512
    half = bits // 2

    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)

        # pick a small d that is coprime with phi
        d_small = generate_prime(bits // 8)
        from math import gcd
        if gcd(d_small, phi) != 1:
            continue

        e_big = modinv(d_small, phi)
        break

    result = wiener_attack(n, e_big)
    assert result is not None
    d_recovered, p_recovered, q_recovered = result
    assert d_recovered == d_small
    assert {p_recovered, q_recovered} == {p, q}
    print(f"wiener attack succeeded: recovered d = {d_recovered}")
