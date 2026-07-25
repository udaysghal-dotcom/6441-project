import pytest
from attacks.hastad import hastad_broadcast
from rsa_core.modmath import mod_exp
from rsa_core.oaep import encrypt
from rsa_core.weakkeys import small_e_keys

# positive: same textbook message broadcast to e recipients under e=3 is recovered
def test_hastad_recovers_broadcast_message():
    e = 3
    m = 42424242
    keys = small_e_keys(bits=512, e=e, count=e)
    moduli = [pub.n for pub, _ in keys]
    ciphertexts = [mod_exp(m, e, n) for n in moduli]
    assert hastad_broadcast(ciphertexts, moduli, e) == m

# negative: fewer than e recipients cannot be attacked
def test_hastad_requires_enough_recipients():
    e = 3
    keys = small_e_keys(bits=512, e=e, count=e)
    moduli = [pub.n for pub, _ in keys]
    ciphertexts = [mod_exp(42, e, n) for n in moduli]
    with pytest.raises(ValueError):
        hastad_broadcast(ciphertexts[:2], moduli[:2], e)

# negative: oaep gives each recipient a different padded plaintext
def test_hastad_fails_against_oaep():
    e = 3
    msg = b"spain one zero"
    keys = small_e_keys(bits=1024, e=e, count=e)
    moduli = [pub.n for pub, _ in keys]
    ciphertexts = [int.from_bytes(encrypt(pub, msg), "big") for pub, _ in keys]
    assert hastad_broadcast(ciphertexts, moduli, e) is None
