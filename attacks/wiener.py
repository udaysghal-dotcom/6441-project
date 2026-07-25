import math
from rsa_core.weakkeys import small_d_key

def _continued_fraction(num, den):
    while den:
        q = num // den
        yield q
        num, den = den, num - q * den

def _convergents(cf):
    p_prev, p_curr = 0, 1
    q_prev, q_curr = 1, 0
    for a in cf:
        p_prev, p_curr = p_curr, a * p_curr + p_prev
        q_prev, q_curr = q_curr, a * q_curr + q_prev
        yield p_curr, q_curr

def wiener_attack(n, e):
    for k, d in _convergents(_continued_fraction(e, n)):
        if k == 0 or d == 0:
            continue

        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # p + q = n - phi + 1, p * q = n
        s = n - phi + 1
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue

        sqrt_disc = math.isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue

        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2
        if p * q == n:
            return d, p, q

    return None

if __name__ == "__main__":
    pub, priv = small_d_key(bits=512)

    result = wiener_attack(pub.n, pub.e)
    assert result is not None
    d_recovered, p_recovered, q_recovered = result
    assert d_recovered == priv.d
    assert {p_recovered, q_recovered} == {priv.p, priv.q}
    print(f"wiener attack succeeded: recovered d = {d_recovered}")
