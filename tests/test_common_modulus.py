import pytest
from attacks.common_modulus import common_modulus_attack
from rsa_core.keygen import PublicKey, generate_keypair
from rsa_core.modmath import egcd, mod_exp
from rsa_core.oaep import OAEPError, encrypt, oaep_decode

def _second_exponent(phi, e1):
    e2 = e1 + 2
    while True:
        g, _, _ = egcd(e2, phi)
        if g == 1 and e2 != e1:
            return e2
        e2 += 2

# positive: same textbook plaintext under two coprime exponents reveals secret
def test_common_modulus_recovers_shared_plaintext():
    pub, priv = generate_keypair(bits=512)
    n, e1 = pub.n, pub.e
    phi = (priv.p - 1) * (priv.q - 1)
    e2 = _second_exponent(phi, e1)

    m = 123456789
    c1 = mod_exp(m, e1, n)
    c2 = mod_exp(m, e2, n)
    assert common_modulus_attack(n, e1, e2, c1, c2) == m

# negative: oaep randomises each encryption
def test_common_modulus_fails_against_oaep():
    pub, priv = generate_keypair(bits=1024)
    n, e1 = pub.n, pub.e
    phi = (priv.p - 1) * (priv.q - 1)
    e2 = _second_exponent(phi, e1)
    pub2 = PublicKey(n, e2)

    k = (n.bit_length() + 7) // 8
    msg = b"reused modulus"
    c1 = int.from_bytes(encrypt(pub, msg), "big")
    c2 = int.from_bytes(encrypt(pub2, msg), "big")

    recovered = common_modulus_attack(n, e1, e2, c1, c2)
    with pytest.raises(OAEPError):
        oaep_decode(recovered.to_bytes(k, "big"), k)
