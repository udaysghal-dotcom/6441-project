import os
import sys
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rsa_core.primes import generate_prime
from attacks.batch_gcd import batch_gcd, naive_pairwise

random.seed(6441)

PRIME_BITS = 64   
SIZES = [64, 128, 256, 512, 1024, 2048]

def run_experiment():
    print("=== BATCH-GCD VS NAIVE PAIRWISE SCALING ===")
    print("Corpus_Size\tNaive_Time_Sec\tBatch_Time_Sec\tSpeedup")
    
    corpus = [generate_prime(PRIME_BITS) * generate_prime(PRIME_BITS) for _ in range(max(SIZES))]
    
    for k in SIZES:
        prefix = corpus[:k]
        
        start = time.perf_counter()
        naive_pairwise(prefix)
        t_naive = time.perf_counter() - start
        
        start = time.perf_counter()
        batch_gcd(prefix)
        t_batch = time.perf_counter() - start
        
        speedup = t_naive / t_batch if t_batch > 0 else 0
        print(f"{k}\t{t_naive:.6f}\t{t_batch:.6f}\t{speedup:.2f}x")
    
    print("\n=== WEAK PRNG YIELD EXPERIMENT ===")
    pool = [generate_prime(128) for _ in range(12)]
    weak_corpus = [random.choice(pool) * generate_prime(128) for _ in range(50)]
    
    factors = batch_gcd(weak_corpus)
    factored_count = sum(1 for f in factors if f is not None)
    pct = (factored_count / len(weak_corpus)) * 100
    
    print(f"Total_Moduli\tFactored_Moduli\tFactored_Percent")
    print(f"{len(weak_corpus)}\t{factored_count}\t{pct:.1f}%")

if __name__ == "__main__":
    run_experiment()
