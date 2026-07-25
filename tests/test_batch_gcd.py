from attacks.batch_gcd import batch_gcd, naive_pairwise, product_tree, remainder_tree
from rsa_core.primes import generate_prime
from rsa_core.weakkeys import shared_prime_keys

# positive: a set of keys with planted shared primes yields real factors
def test_batch_gcd_recovers_shared_primes():
    corpus = shared_prime_keys(bits=256, num_keys=8, num_shared=2)
    factors = batch_gcd(corpus)
    found = [f for f in factors if f is not None]
    assert len(found) >= 2
    for n, f in zip(corpus, factors):
        if f is not None:
            assert 1 < f < n
            assert n % f == 0

# equivalence: batch-GCD agrees with the quadratic reference
def test_batch_gcd_matches_naive():
    corpus = shared_prime_keys(bits=256, num_keys=8, num_shared=2)
    assert batch_gcd(corpus) == naive_pairwise(corpus)

# negative: independently generated keys share nothing
def test_batch_gcd_finds_nothing_in_good_corpus():
    primes = [generate_prime(128) for _ in range(8)]
    moduli = [primes[i] * generate_prime(128) for i in range(len(primes))]
    assert all(f is None for f in batch_gcd(moduli))

# testing product and remainder tree validity
def test_product_and_remainder_tree_shape():
    moduli = [15, 21, 35, 11]
    tree = product_tree(moduli)
    assert tree[-1][0] == 15 * 21 * 35 * 11
    assert len(remainder_tree(tree)) == len(moduli)
