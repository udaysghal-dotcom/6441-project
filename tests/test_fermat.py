from attacks.fermat import fermat_factor
from rsa_core.keygen import generate_keypair
from rsa_core.weakkeys import close_prime_key

# close primes factor quickly
def test_fermat_recovers_close_primes():
    pub, priv = close_prime_key(bits=256, gap=1000)
    result = fermat_factor(pub.n)
    assert result is not None
    fp, fq = result
    assert {fp, fq} == {priv.p, priv.q}
    assert fp * fq == pub.n

# a proper key has a large prime gap so a bounded run gives up
def test_fermat_fails_on_correct_key():
    pub, _ = generate_keypair(bits=512)
    assert fermat_factor(pub.n, max_iterations=2000) is None
