import secrets
from math import gcd
from rsa_core.modmath import mod_exp, modinv
from rsa_core.keygen import generate_keypair, encrypt_int, decrypt_int

# textbook RSA vs padded RSA
def malleability_attack(pub, target_ciphertext, decrypt_oracle):
    n, e = pub.n, pub.e

    # blinding factor must be invertible mod n
    while True:
        r = secrets.randbelow(n - 2) + 2
        if gcd(r, n) == 1:
            break

    blinded = (target_ciphertext * mod_exp(r, e, n)) % n
    m_blinded = decrypt_oracle(blinded)
    return (m_blinded * modinv(r, n)) % n


if __name__ == "__main__":
    pub, priv = generate_keypair(bits=512)
    m_original = 987654321
    c = encrypt_int(m_original, pub)

    oracle = lambda blinded: decrypt_int(blinded, priv)
    recovered = malleability_attack(pub, c, oracle)
    assert recovered == m_original
    print(f"malleability attack succeeded: recovered m = {recovered}")
