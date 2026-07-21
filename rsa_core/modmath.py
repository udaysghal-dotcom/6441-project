
# mod arithmetic math helpers for proj


# extended ecludian algo
def egcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no modular inverse for {a} mod {m} (gcd={g})")
    return x % m


def mod_exp(base, exp, mod):
    if mod == 1:
        return 0
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def integer_nth_root(x, n):
    if x < 0:
        raise ValueError("negative root value not accepted")
    if x in (0, 1):
        return x, True
    lo, hi = 1, 1 << ((x.bit_length() // n) + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n < x:
            lo = mid + 1
        else:
            hi = mid
    for candidate in (lo, lo - 1):
        if candidate ** n == x:
            return candidate, True
    return lo - 1, False

# chinese remainder theorem
def crt(residues, moduli):
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must be the same length")
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for r_i, m_i in zip(residues, moduli):
        N_i = N // m_i
        x += r_i * N_i * modinv(N_i, m_i)
    return x % N
