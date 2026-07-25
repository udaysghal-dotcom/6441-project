from rsa_core.modmath import crt, integer_nth_root, mod_exp
from rsa_core.weakkeys import small_e_keys

def hastad_broadcast(ciphertexts, moduli, e):
    # need at least e ciphertext/modulus pairs
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError(f"need at least {e} ciphertext/modulus pairs")

    combined = crt(ciphertexts[:e], moduli[:e])

    root, exact = integer_nth_root(combined, e)
    if not exact:
        return None
    return root

if __name__ == "__main__":
    e = 3
    m_original = 42424242

    # e keypairs sharing the small public exponent e, pairwise coprime moduli
    keys = small_e_keys(bits=512, e=e, count=e)
    moduli = [pub.n for pub, _ in keys]
    ciphertexts = [mod_exp(m_original, e, n) for n in moduli]

    m_recovered = hastad_broadcast(ciphertexts, moduli, e)
    assert m_recovered == m_original
    print(f"hastad broadcast attack succeeded: recovered m = {m_recovered}")
