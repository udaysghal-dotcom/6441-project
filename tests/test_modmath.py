import random
import math

from rsa_core.modmath import crt, egcd, integer_nth_root, mod_exp, modinv

def test_egcd_matches_math_gcd():
    for _ in range(200):
        a = random.randint(1, 10**6)
        b = random.randint(1, 10**6)
        g, x, y = egcd(a, b)

        # math.gcd()
        assert g == math.gcd(a, b)

        # bezout identity 
        assert a * x + b * y == g

def test_modinv_roundtrip():
    for _ in range(200):
        m = random.randint(3, 10**6)
        a = random.randint(1, m - 1)
        try:
            inv = modinv(a, m)
        except ValueError:
            continue  # not invertible, fine
        assert (a * inv) % m == 1

def test_mod_exp_matches_builtin():
    for _ in range(200):
        base = random.randint(0, 10**9)
        exp = random.randint(0, 10**4)
        mod = random.randint(2, 10**9)
        assert mod_exp(base, exp, mod) == pow(base, exp, mod)

def test_integer_nth_root_exact_and_inexact():
    assert integer_nth_root(27, 3) == (3, True)
    assert integer_nth_root(1000, 3) == (10, True)
    root, exact = integer_nth_root(1001, 3)
    assert exact is False
    assert root == 10

def test_modinv_raises_when_not_coprime():
    try:
        modinv(4, 8)
        assert False
    except ValueError:
        pass

def test_crt_coprime_case():
    assert crt([2, 3, 2], [3, 5, 7]) == 23
