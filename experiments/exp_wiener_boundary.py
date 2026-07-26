import os
import sys
import random
from math import log2

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rsa_core.weakkeys import small_d_key
from attacks.wiener import wiener_attack

random.seed(6441)

# n^(1/4) = 128 bits
BITS = 512
TRIALS = 6    

def run_experiment():
    bound_bits = BITS / 4 - log2(3)
    print(f"=== WIENER ATTACK SUCCESS BOUNDARY ({BITS}-bit n) ===")
    print("d_Bits\tSuccesses\tTotal_Trials\tSuccess_Rate\tUnder_Theoretical_Bound")
    
    d_bit_sizes = list(range(108, 145, 3))
    for d_bits in d_bit_sizes:
        successes = 0
        for _ in range(TRIALS):
            pub, priv = small_d_key(bits=BITS, d_bits=d_bits)
            result = wiener_attack(pub.n, pub.e)
            if result is not None and result[0] == priv.d:
                successes += 1
        
        rate = successes / TRIALS
        under_bound = d_bits <= bound_bits
        print(f"{d_bits}\t{successes}\t{TRIALS}\t{rate:.4f}\t{under_bound}")

if __name__ == "__main__":
    run_experiment()
