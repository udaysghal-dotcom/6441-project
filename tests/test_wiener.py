from attacks.wiener import wiener_attack
from rsa_core.keygen import generate_keypair
from rsa_core.weakkeys import small_d_key

# positive: a small private exponent is recovered from the public key
def test_wiener_recovers_small_d():
    pub, priv = small_d_key(bits=512)
    result = wiener_attack(pub.n, pub.e)
    assert result is not None
    d_recovered, p_recovered, q_recovered = result
    assert d_recovered == priv.d
    assert {p_recovered, q_recovered} == {priv.p, priv.q}

# negative: a proper key has a full-size private exponent
def test_wiener_fails_on_correct_key():
    pub, _ = generate_keypair(bits=512)
    assert wiener_attack(pub.n, pub.e) is None
