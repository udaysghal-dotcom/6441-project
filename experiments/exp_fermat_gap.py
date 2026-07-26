import os
import sys
import random
from math import isqrt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rsa_core.weakkeys import close_prime_key

random.seed(6441)

BITS = 256
# experiment stops past these many iterations
CAP = 5_000_000

def fermat_iterations(n, cap):
    a = isqrt(n)
    if a * a < n:
        a += 1
    for i in range(cap):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return i + 1
        a += 1
    return None

def run_experiment():
    print(f"=== FERMAT FACTORIZATION COST VS PRIME GAP ({BITS}-bit n) ===")
    print("Gap_Exponent_Target\tActual_Gap_Bits\tIterations\tFeasible")
    
    gap_exponents = list(range(60, 80))
    for g in gap_exponents:
        pub, priv = close_prime_key(bits=BITS, gap=2 ** g)
        real_gap = abs(priv.p - priv.q)
        iters = fermat_iterations(pub.n, CAP)
        
        actual_bits = real_gap.bit_length()
        if iters is not None:
            print(f"2^{g}\t{actual_bits}\t{iters}\tTrue")
        else:
            print(f"2^{g}\t{actual_bits}\t>{CAP}\tFalse")

if __name__ == "__main__":
    run_experiment()
