import os
import sys
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rsa_core.modmath import mod_exp
from rsa_core.weakkeys import small_e_keys
from attacks.hastad import hastad_broadcast

random.seed(6441)

BITS = 512
MESSAGE = 42424242

def try_recovery(e, recipients):
    keys = small_e_keys(bits=BITS, e=e, count=recipients)
    moduli = [pub.n for pub, _ in keys]
    ciphertexts = [mod_exp(MESSAGE, e, n) for n in moduli]
    try:
        recovered = hastad_broadcast(ciphertexts, moduli, e)
    except ValueError:
        return False
    return recovered == MESSAGE

def run_experiment():
    print("=== HÅSTAD BROADCAST RECOVERY THRESHOLD ===")
    print("Exponent_e\tNum_Recipients\tRecovery_Success\tThreshold_Met")
    
    exponents = [3, 5]
    for e in exponents:
        for r in range(1, e + 2):
            ok = try_recovery(e, r)
            threshold_met = r >= e
            print(f"{e}\t{r}\t{1 if ok else 0}\t{threshold_met}")

if __name__ == "__main__":
    run_experiment()
