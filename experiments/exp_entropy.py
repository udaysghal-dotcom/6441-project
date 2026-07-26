import os
import sys
import random
from math import log2

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rsa_core.primes import generate_prime
from attacks.batch_gcd import batch_gcd

random.seed(6441)

PRIME_BITS = 32  
NUM_KEYS = 200
POOL_SIZES = [50, 100, 200, 500, 1000, 2000, 5000]

def factored_fraction(pool_primes, num_keys):
    moduli = []
    for _ in range(num_keys):
        p = random.choice(pool_primes)
        q = generate_prime(PRIME_BITS)
        moduli.append(p * q)
    factors = batch_gcd(moduli)
    hit = sum(1 for f in factors if f is not None)
    return hit / num_keys

def sharing_estimate(pool, num_keys):
    return 1.0 - ((pool - 1) / pool) ** (num_keys - 1)

def run_experiment():
    print("=== RNG ENTROPY VS SHARED-PRIME FACTORIZATION RATE ===")
    print("Pool_Size\tEntropy_Bits\tFactored_Fraction\tSharing_Estimate")
    
    for pool in POOL_SIZES:
        primes = [generate_prime(PRIME_BITS) for _ in range(pool)]
        frac = factored_fraction(primes, NUM_KEYS)
        entropy = log2(pool)
        est = sharing_estimate(pool, NUM_KEYS)
        print(f"{pool}\t{entropy:.2f}\t{frac:.4f}\t{est:.4f}")

if __name__ == "__main__":
    run_experiment()
