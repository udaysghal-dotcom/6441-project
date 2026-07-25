from rsa_core.keygen import PublicKey, PrivateKey, decrypt_int, encrypt_int, generate_keypair

def test_generate_keypair():
    pub, priv = generate_keypair(bits=256)
    assert isinstance(pub, PublicKey)
    assert isinstance(priv, PrivateKey)
    assert priv.p * priv.q == pub.n
    phi = (priv.p - 1) * (priv.q - 1)
    assert (pub.e * priv.d) % phi == 1


def test_encrypt_decrypt_int_roundtrip():
    pub, priv = generate_keypair(bits=256)
    message = 123456789
    ciphertext = encrypt_int(message, pub)
    decrypted = decrypt_int(ciphertext, priv)
    assert decrypted == message


def test_encrypt_int_exceeds_modulus():
    pub, priv = generate_keypair(bits=256)
    try:
        encrypt_int(pub.n + 1, pub)
        assert False
    except ValueError:
        pass
