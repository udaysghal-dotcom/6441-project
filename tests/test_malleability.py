import pytest
from attacks.malleability import malleability_attack
from rsa_core.keygen import generate_keypair, encrypt_int, decrypt_int
from rsa_core.oaep import OAEPError, decrypt, encrypt

# positive: a textbook decryption oracle lets us unblind the target message
def test_malleability_breaks_textbook_rsa():
    pub, priv = generate_keypair(bits=512)
    m = 987654321
    c = encrypt_int(m, pub)
    oracle = lambda blinded: decrypt_int(blinded, priv)
    assert malleability_attack(pub, c, oracle) == m

# negative: an oaep oracle rejects the blinded ciphertext so blinding leaks nothing
def test_malleability_fails_against_oaep():
    pub, priv = generate_keypair(bits=1024)
    k = (pub.n.bit_length() + 7) // 8
    target = int.from_bytes(encrypt(pub, b"secret"), "big")

    def oracle(blinded):
        return int.from_bytes(decrypt(priv, blinded.to_bytes(k, "big")), "big")

    with pytest.raises(OAEPError):
        malleability_attack(pub, target, oracle)
