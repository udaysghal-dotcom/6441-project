import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rsa_core.modmath import egcd, modinv, mod_exp
from rsa_core.keygen import generate_keypair, encrypt_int



def common_modulus_attack(n, e1, e2, c1, c2):
    g, u, v = egcd(e1, e2)
    if g != 1:
        raise ValueError(
            f"e1 and e2 must be coprime for the attack to work (gcd={g})"
        )

    if u < 0:
        c1 = modinv(c1, n)
        u = -u
    if v < 0:
        c2 = modinv(c2, n)
        v = -v

    m = (mod_exp(c1, u, n) * mod_exp(c2, v, n)) % n
    return m


if __name__ == "__main__":
    # generate a single key pair, then calc a second public exponent
    pub, priv = generate_keypair(bits=512)
    n = pub.n
    e1 = pub.e  # 65537

    # pick a second exponent coprime to phi(n)
    phi = (priv.p - 1) * (priv.q - 1)
    e2 = 65539
    while True:
        g, _, _ = egcd(e2, phi)
        if g == 1 and e2 != e1:
            break
        e2 += 2

    # encrypt the same message with both exponents
    m_original = 123456789
    c1 = mod_exp(m_original, e1, n)
    c2 = mod_exp(m_original, e2, n)

    m_recovered = common_modulus_attack(n, e1, e2, c1, c2)
    assert m_recovered == m_original
    print(f"common-modulus attack succeeded: recovered m = {m_recovered}")
