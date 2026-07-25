import math

from rsa_core.weakkeys import close_prime_key

def fermat_factor(n, max_iterations=None):
    if n <= 0:
        raise ValueError("n must be a positive integer")
    if n == 1:
        return 1, 1
    if n % 2 == 0:
        return 2, n // 2

    a = math.isqrt(n)
    if a * a < n:
        a += 1

    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a + b, a - b
        a += 1
        iterations += 1

    return None

if __name__ == "__main__":
    # weak key with a small gap between p and q
    pub, priv = close_prime_key(bits=512, gap=1000)
    result = fermat_factor(pub.n)
    assert result is not None
    fp, fq = result
    assert {fp, fq} == {priv.p, priv.q}, (fp, fq)
    print(f"recovered factors: {fp} * {fq} == {pub.n}")
