from math import gcd
from rsa_core.weakkeys import shared_prime_keys

def product_tree(moduli):
    tree = [list(moduli)]
    while len(tree[-1]) > 1:
        cur = tree[-1]
        nxt = [cur[i] * cur[i + 1] for i in range(0, len(cur) - 1, 2)]
        if len(cur) % 2 == 1:
            nxt.append(cur[-1])
        tree.append(nxt)
    return tree

def remainder_tree(tree):
    remainders = [tree[-1][0]]
    for level in range(len(tree) - 1, 0, -1):
        children = tree[level - 1]
        remainders = [remainders[i // 2] % (val * val)
                      for i, val in enumerate(children)]
    return remainders

# for each modulus return a shared factor or none if independent
def batch_gcd(moduli):
    if not moduli:
        return []
    tree = product_tree(moduli)
    remainders = remainder_tree(tree)
    factors = []
    for n, r in zip(moduli, remainders):
        g = gcd(n, r // n)
        factors.append(g if 1 < g < n else None)
    return factors

def naive_pairwise(moduli):
    factors = [None] * len(moduli)
    for i in range(len(moduli)):
        for j in range(len(moduli)):
            if i == j:
                continue
            g = gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                factors[i] = g
                break
    return factors

if __name__ == "__main__":
    corpus = shared_prime_keys(bits=256, num_keys=8, num_shared=2)
    factors = batch_gcd(corpus)
    recovered = [i for i, f in enumerate(factors) if f is not None]
    print(f"batch-GCD factored moduli at indices: {recovered}")

    naive = naive_pairwise(corpus)
    assert factors == naive
    for i, f in enumerate(factors):
        if f is not None:
            assert corpus[i] % f == 0
    print("batch result matches naive pairwise result")
