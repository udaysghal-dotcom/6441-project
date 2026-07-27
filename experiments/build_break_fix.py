import os
import sys
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rsa_core.modmath import egcd, mod_exp
from rsa_core.keygen import PublicKey, generate_keypair, encrypt_int, decrypt_int
from rsa_core.oaep import OAEPError, encrypt, decrypt, oaep_decode
from rsa_core.weakkeys import (
    close_prime_key, small_d_key, small_e_keys, shared_prime_keys,
)
from rsa_core.primes import generate_prime
from attacks.fermat import fermat_factor
from attacks.common_modulus import common_modulus_attack
from attacks.hastad import hastad_broadcast
from attacks.wiener import wiener_attack
from attacks.malleability import malleability_attack
from attacks.batch_gcd import batch_gcd

random.seed(6441)

# Helper function to get second co-prime exponent e2
def get_second_e(phi, e1):
    e2 = e1 + 2
    while True:
        g, _, _ = egcd(e2, phi)
        if g == 1 and e2 != e1:
            return e2
        e2 += 2

def check_fermat():
    pub, _ = close_prime_key(bits=256, gap=1000)
    weak_breaks = fermat_factor(pub.n) is not None
    
    pub_h, _ = generate_keypair(bits=1024)
    hardened_breaks = fermat_factor(pub_h.n, max_iterations=20000) is not None
    return weak_breaks, hardened_breaks

def check_common_modulus():
    # weak textbook attack
    pub, priv = generate_keypair(bits=512)
    phi = (priv.p - 1) * (priv.q - 1)
    e2 = get_second_e(phi, pub.e)
    m = 123456789
    weak_breaks = common_modulus_attack(pub.n, pub.e, e2, mod_exp(m, pub.e, pub.n), mod_exp(m, e2, pub.n)) == m

    # oaep structure
    hpub, hpriv = generate_keypair(bits=1024)
    hphi = (hpriv.p - 1) * (hpriv.q - 1)
    he2 = get_second_e(hphi, hpub.e)
    hpub2 = PublicKey(hpub.n, he2)
    k = (hpub.n.bit_length() + 7) // 8
    c1 = int.from_bytes(encrypt(hpub, b"reused"), "big")
    c2 = int.from_bytes(encrypt(hpub2, b"reused"), "big")
    recovered = common_modulus_attack(hpub.n, hpub.e, he2, c1, c2)
    try:
        oaep_decode(recovered.to_bytes(k, "big"), k)
        hardened_breaks = True
    except OAEPError:
        hardened_breaks = False
    return weak_breaks, hardened_breaks

def check_hastad():
    e = 3
    m = 42424242
    keys = small_e_keys(bits=512, e=e, count=e)
    weak_breaks = hastad_broadcast([mod_exp(m, e, k[0].n) for k in keys], [k[0].n for k in keys], e) == m

    keys_h = small_e_keys(bits=1024, e=e, count=e)
    cts_h = [int.from_bytes(encrypt(k[0], b"broadcast"), "big") for k in keys_h]
    hardened_breaks = hastad_broadcast(cts_h, [k[0].n for k in keys_h], e) is not None
    return weak_breaks, hardened_breaks

def check_wiener():
    pub, priv = small_d_key(bits=512)
    res = wiener_attack(pub.n, pub.e)
    weak_breaks = res is not None and res[0] == priv.d

    pub_h, _ = generate_keypair(bits=512)
    hardened_breaks = wiener_attack(pub_h.n, pub_h.e) is not None
    return weak_breaks, hardened_breaks

def check_malleability():
    pub, priv = generate_keypair(bits=512)
    m = 987654321
    weak_breaks = malleability_attack(pub, encrypt_int(m, pub), lambda b: decrypt_int(b, priv)) == m

    pub_h, priv_h = generate_keypair(bits=1024)
    k = (pub_h.n.bit_length() + 7) // 8
    target = int.from_bytes(encrypt(pub_h, b"secret"), "big")
    try:
        malleability_attack(pub_h, target, lambda b: int.from_bytes(decrypt(priv_h, b.to_bytes(k, "big")), "big"))
        hardened_breaks = True
    except OAEPError:
        hardened_breaks = False
    return weak_breaks, hardened_breaks

def check_batch_gcd():
    corpus = shared_prime_keys(bits=256, num_keys=8, num_shared=2)
    weak_breaks = any(f is not None for f in batch_gcd(corpus))

    good_corpus = [generate_prime(128) * generate_prime(128) for _ in range(8)]
    hardened_breaks = any(f is not None for f in batch_gcd(good_corpus))
    return weak_breaks, hardened_breaks

def run_experiment():
    print("=== RSA BUILD / BREAK / FIX MATRIX ===")
    print("Attack_Name\tWeak_Key_Result\tHardened_Key_Result")
    
    attacks = [
        ("Fermat Factorisation", check_fermat),
        ("Common-Modulus", check_common_modulus),
        ("Hastad Broadcast", check_hastad),
        ("Wiener Attack", check_wiener),
        ("Textbook Malleability", check_malleability),
        ("Batch-GCD", check_batch_gcd),
    ]
    
    for name, fn in attacks:
        weak, hardened = fn()
        weak_str = "breaks" if weak else "blocked"
        hardened_str = "breaks" if hardened else "blocked"
        print(f"{name}\t{weak_str}\t{hardened_str}")

if __name__ == "__main__":
    run_experiment()
