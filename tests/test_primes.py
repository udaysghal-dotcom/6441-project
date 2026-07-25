from rsa_core.primes import generate_prime, is_probable_prime

def test_is_probable_prime_known_values():
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 97, 1000000007]
    for p in primes:
        assert is_probable_prime(p) is True

    composites = [-5, 0, 1, 4, 6, 9, 15, 25, 100, 1000000008]
    for c in composites:
        assert is_probable_prime(c) is False

def test_generate_prime_bit_length_and_primality():
    for bits in [16, 32, 64, 128]:
        p = generate_prime(bits)
        assert p.bit_length() == bits
        assert is_probable_prime(p) is True

def test_generate_prime_too_small():
    try:
        generate_prime(10)
        assert False
    except ValueError:
        pass
