import secrets
import pytest
from rsa_core.keygen import generate_keypair
from rsa_core.oaep import encrypt, decrypt, oaep_encode, oaep_decode, OAEPError

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

KEY_BITS = 1024

# generate once per test suite run for performance
@pytest.fixture(scope="module")
def keypair():
    return generate_keypair(KEY_BITS)

@pytest.mark.parametrize("length", [0, 1, 16, 62])
def test_round_trip_varying_length(keypair, length):
    pub, priv = keypair
    msg = secrets.token_bytes(length)
    ct = encrypt(pub, msg)
    assert decrypt(priv, ct) == msg

def test_encode_decode_directly():
    k = 128
    msg = b"hello oaep"
    encoded = oaep_encode(msg, k)
    assert len(encoded) == k
    assert oaep_decode(encoded, k) == msg

# tamper detection by flipping bit in the middle of cipher text
def test_ciphertext_bit_flip_rejected(keypair):
    pub, priv = keypair
    ct = bytearray(encrypt(pub, b"top secret"))
    ct[len(ct) // 2] ^= 0x01
    with pytest.raises(OAEPError):
        decrypt(priv, bytes(ct))

def test_wrong_label_rejected(keypair):
    pub, priv = keypair
    ct = encrypt(pub, b"labelled", label=b"A")
    with pytest.raises(OAEPError):
        decrypt(priv, ct, label=b"B")

def test_message_too_long_rejected(keypair):
    pub, _ = keypair
    # max is k - 2*hLen - 2 = 128 - 66 = 62 bytes
    with pytest.raises(OAEPError):
        encrypt(pub, secrets.token_bytes(63))

def _reference_key(pub, priv):
    return RSA.construct((pub.n, pub.e, priv.d, priv.p, priv.q))

def test_cross_check_ours_encrypt_reference_decrypt(keypair):
    pub, priv = keypair
    ref = PKCS1_OAEP.new(_reference_key(pub, priv), hashAlgo=SHA256)
    msg = b"hello 6441 tutor"
    ct = encrypt(pub, msg)
    assert ref.decrypt(ct) == msg

def test_cross_check_reference_encrypt_ours_decrypt(keypair):
    pub, priv = keypair
    ref = PKCS1_OAEP.new(_reference_key(pub, priv), hashAlgo=SHA256)
    msg = b"hello 6441 tutor"
    ct = ref.encrypt(msg)
    assert decrypt(priv, ct) == msg
