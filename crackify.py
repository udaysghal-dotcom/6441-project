import argparse
from math import gcd

from rsa_core.modmath import egcd, modinv
from rsa_core.keygen import generate_keypair, encrypt_int
from rsa_core.weakkeys import (
    close_prime_key,
    small_d_key,
    small_e_keys,
    shared_prime_keys,
)
from attacks.fermat import fermat_factor
from attacks.wiener import wiener_attack
from attacks.hastad import hastad_broadcast
from attacks.common_modulus import common_modulus_attack
from attacks.batch_gcd import batch_gcd

SMALL_E = 17

class CrackResult:
    def __init__(self, attack, factors=None, d=None, message=None):
        self.attack = attack
        self.factors = factors
        self.d = d
        self.message = message

    def __repr__(self):
        return f"CrackResult(attack={self.attack}, d={self.d}, message={self.message})"

def _solve_from_factors(n, e, p, q, ciphertext):
    if e is None:
        return None, None
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    message = pow(ciphertext, d, n) if ciphertext is not None else None
    return d, message


def _provided_param_labels(args):
    labels = []
    if args.modulus is not None:
        labels.append("-n")
    if args.exponent is not None:
        labels.append("-e")
    if args.ciphertext is not None:
        labels.append("-c")
    if args.e2 is not None:
        labels.append("--e2")
    if args.c1 is not None:
        labels.append("--c1")
    if args.c2 is not None:
        labels.append("--c2")
    if args.broadcast is not None:
        labels.append("--broadcast")
    if args.corpus is not None:
        labels.append("--corpus")
    return labels


def _validate_fermat(args):
    if args.modulus is None:
        print(
            "[Error] Insufficient information for Fermat attack. "
            "Please supply the public modulus using -n <modulus>."
        )
        return False
    return True


def _validate_wiener(args):
    if args.modulus is None or args.exponent is None:
        print("[Error] Insufficient information for Wiener attack.")
        print(
            "Wiener attack requires both the public modulus (-n) "
            "and the public exponent (-e)."
        )
        print(
            "Please rerun with: python3 crackify.py --attack wiener "
            "-n <modulus> -e <exponent>"
        )
        return False
    return True


def _common_modulus_params(args):
    """Resolve e1/c1 aliases: -e for e1, -c for c1."""
    e1 = args.exponent
    c1 = args.c1 if args.c1 is not None else args.ciphertext
    return args.modulus, e1, args.e2, c1, args.c2


def _validate_common_modulus(args):
    n, e1, e2, c1, c2 = _common_modulus_params(args)
    if None in (n, e1, e2, c1, c2):
        print(
            "[Error] Insufficient information for Common Modulus attack. "
            "Requires -n, -e1, -e2, -c1, and -c2."
        )
        print(
            "Please rerun with: python3 crackify.py --attack common_modulus "
            "-n <modulus> -e <e1> --e2 <e2> --c1 <c1> --c2 <c2>"
        )
        print("(-e may be used for e1; -c may be used for c1.)")
        return False
    return True


def _validate_hastad(args):
    if args.broadcast is None:
        print(
            "[Error] Insufficient information for Håstad attack. "
            "Please supply broadcast pairs using --broadcast."
        )
        return False
    if args.exponent is None:
        print(
            "[Error] Insufficient information for Håstad attack. "
            "Please supply the public exponent using -e <exponent>."
        )
        return False
    if len(args.broadcast) < args.exponent:
        print(
            f"[Error] Insufficient information for Håstad attack. "
            f"Need at least e={args.exponent} broadcast pairs (n:c); "
            f"got {len(args.broadcast)}."
        )
        return False
    return True


def _batch_gcd_pool(args):
    pool = list(args.corpus) if args.corpus is not None else []
    if args.modulus is not None and args.modulus not in pool:
        pool.append(args.modulus)
    return pool


def _validate_batch_gcd(args):
    if args.corpus is None:
        print(
            "[Error] Insufficient information for Batch GCD attack. "
            "Please supply a list of moduli via --corpus."
        )
        return False
    pool = _batch_gcd_pool(args)
    if len(pool) < 2:
        print(
            "[Error] Insufficient information for Batch GCD attack. "
            "Need at least 2 moduli (via --corpus, or -n plus --corpus)."
        )
        return False
    return True


ATTACK_DISPLAY = {
    "fermat": "Fermat",
    "wiener": "Wiener",
    "hastad": "Håstad",
    "common_modulus": "Common Modulus",
    "batch_gcd": "Batch GCD",
}

AUTO_ATTACK_PRIORITY = [
    "fermat",
    "wiener",
    "common_modulus",
    "hastad",
    "batch_gcd",
]


def _print_attack_success(name, factors=None, d=None, message=None):
    print(f"[+] Attack Successful ({name})!")
    if factors is not None:
        p, q = factors
        print(f"  p: {p}")
        print(f"  q: {q}")
    if d is not None:
        print(f"  d: {d}")
    if message is not None:
        print(f"  m: {message}")


def _print_attack_header(mode, args):
    labels = _provided_param_labels(args)
    print(f"[*] Attack Mode: {mode}")
    print(f"[*] Parameters provided: [{', '.join(labels)}].")


def _print_result(res):
    _print_attack_success(
        ATTACK_DISPLAY[res.attack],
        factors=res.factors,
        d=res.d,
        message=res.message,
    )


def _attempt_fermat(args, max_fermat_iterations=100000):
    factored = fermat_factor(args.modulus, max_iterations=max_fermat_iterations)
    if factored is None:
        return None
    p, q = factored
    d, message = _solve_from_factors(
        args.modulus, args.exponent, p, q, args.ciphertext
    )
    return CrackResult("fermat", factors=(p, q), d=d, message=message)


def _attempt_wiener(args):
    result = wiener_attack(args.modulus, args.exponent)
    if result is None:
        return None
    d, p, q = result
    message = (
        pow(args.ciphertext, d, args.modulus)
        if args.ciphertext is not None
        else None
    )
    return CrackResult("wiener", factors=(p, q), d=d, message=message)


def _attempt_common_modulus(args):
    n, e1, e2, c1, c2 = _common_modulus_params(args)
    try:
        message = common_modulus_attack(n, e1, e2, c1, c2)
    except ValueError:
        return None
    return CrackResult("common_modulus", message=message)


def _attempt_hastad(args):
    moduli = [n for n, _ in args.broadcast]
    ciphertexts = [c for _, c in args.broadcast]
    try:
        message = hastad_broadcast(ciphertexts, moduli, args.exponent)
    except ValueError:
        return None
    if message is None:
        return None
    return CrackResult("hastad", message=message)


def _attempt_batch_gcd(args):
    pool = _batch_gcd_pool(args)
    factors = batch_gcd(pool)

    if args.modulus is not None:
        f = factors[pool.index(args.modulus)]
        if f is None:
            return None
        p, q = f, args.modulus // f
        d, message = _solve_from_factors(
            args.modulus, args.exponent, p, q, args.ciphertext
        )
        return CrackResult("batch_gcd", factors=(p, q), d=d, message=message)

    recovered = [(n, f, n // f) for n, f in zip(pool, factors) if f is not None]
    if not recovered:
        return None

    _, p, q = recovered[0]
    return CrackResult("batch_gcd", factors=(p, q), d=None, message=None)


ATTACK_ATTEMPTS = {
    "fermat": _attempt_fermat,
    "wiener": _attempt_wiener,
    "common_modulus": _attempt_common_modulus,
    "hastad": _attempt_hastad,
    "batch_gcd": _attempt_batch_gcd,
}


def _eligible_attacks(args):
    eligible = []
    if args.modulus is not None:
        eligible.append("fermat")
    if args.modulus is not None and args.exponent is not None:
        eligible.append("wiener")
    n, e1, e2, c1, c2 = _common_modulus_params(args)
    if None not in (n, e1, e2, c1, c2):
        eligible.append("common_modulus")
    if (
        args.broadcast is not None
        and args.exponent is not None
        and len(args.broadcast) >= args.exponent
    ):
        eligible.append("hastad")
    if args.corpus is not None and len(_batch_gcd_pool(args)) >= 2:
        eligible.append("batch_gcd")
    return [name for name in AUTO_ATTACK_PRIORITY if name in eligible]


def _validate_auto(args):
    labels = _provided_param_labels(args)
    actionable = (
        args.modulus is not None
        or args.broadcast is not None
        or args.corpus is not None
    )
    if not actionable:
        print("[Error] Insufficient information for auto mode.")
        if labels == ["-e"]:
            print(
                "Providing only the public exponent (-e) is not enough to run any attack."
            )
        elif not labels:
            print("No attack parameters were provided.")
        else:
            print(
                f"Parameters provided [{', '.join(labels)}] are not enough "
                "to run any attack."
            )
        print(
            "Please supply at least a public modulus (-n), broadcast set "
            "(--broadcast), or corpus (--corpus)."
        )
        return False
    return True


def _run_fermat_cli(args, max_fermat_iterations=100000):
    _print_attack_header("fermat", args)
    print("[*] Running Fermat attack...")
    res = _attempt_fermat(args, max_fermat_iterations=max_fermat_iterations)
    if res is None:
        print("[-] Fermat attack failed for the given inputs.")
        return 1
    _print_result(res)
    return 0


def _run_wiener_cli(args):
    _print_attack_header("wiener", args)
    print("[*] Running Wiener attack...")
    res = _attempt_wiener(args)
    if res is None:
        print("[-] Wiener attack failed for the given inputs.")
        return 1
    _print_result(res)
    return 0


def _run_common_modulus_cli(args):
    _print_attack_header("common_modulus", args)
    print("[*] Running Common Modulus attack...")
    res = _attempt_common_modulus(args)
    if res is None:
        print("[-] Common Modulus attack failed for the given inputs.")
        return 1
    _print_result(res)
    return 0


def _run_hastad_cli(args):
    _print_attack_header("hastad", args)
    print("[*] Running Håstad attack...")
    res = _attempt_hastad(args)
    if res is None:
        print("[-] Håstad attack failed for the given inputs.")
        return 1
    _print_result(res)
    return 0


def _run_batch_gcd_cli(args):
    _print_attack_header("batch_gcd", args)
    print("[*] Running Batch GCD attack...")

    pool = _batch_gcd_pool(args)
    factors = batch_gcd(pool)

    if args.modulus is not None:
        res = _attempt_batch_gcd(args)
        if res is None:
            print("[-] Batch GCD attack failed for the given inputs.")
            return 1
        _print_result(res)
        return 0

    recovered = [(n, f, n // f) for n, f in zip(pool, factors) if f is not None]
    if not recovered:
        print("[-] Batch GCD attack failed for the given inputs.")
        return 1

    print(f"[+] Attack Successful (Batch GCD)! Factored {len(recovered)} modulus(i).")
    for i, (n, p, q) in enumerate(recovered):
        print(f"  n[{i}]: {n}")
        print(f"    p: {p}")
        print(f"    q: {q}")
    return 0


def _run_auto_cli(args):
    if not _validate_auto(args):
        return 1

    labels = _provided_param_labels(args)
    eligible = _eligible_attacks(args)
    if not eligible:
        print("[Error] Insufficient information for auto mode.")
        print(
            f"Parameters provided [{', '.join(labels)}] do not satisfy "
            "requirements for any known attack."
        )
        print(
            "Please supply at least a public modulus (-n), broadcast set "
            "(--broadcast), or corpus (--corpus)."
        )
        return 1

    print(f"[*] Auto Mode: Parameters provided [{', '.join(labels)}].")
    print(f"[*] Eligible attacks: [{', '.join(eligible)}]")

    saw_failure = False
    for name in eligible:
        display = ATTACK_DISPLAY[name]
        res = ATTACK_ATTEMPTS[name](args)
        if res is None:
            print(f"[*] Running {display} attack... (failed)")
            saw_failure = True
            continue

        if saw_failure:
            print(f"[*] Running {display} attack... (succeeded)")
        else:
            print(f"[*] Running {display} attack...")
        _print_result(res)
        return 0

    print("[-] All eligible attacks failed for the given inputs.")
    return 1


def _run_attack_cli(args):
    if args.attack == "auto":
        return _run_auto_cli(args)

    if args.attack == "fermat":
        if not _validate_fermat(args):
            return 1
        return _run_fermat_cli(args)

    if args.attack == "wiener":
        if not _validate_wiener(args):
            return 1
        return _run_wiener_cli(args)

    if args.attack == "common_modulus":
        if not _validate_common_modulus(args):
            return 1
        return _run_common_modulus_cli(args)

    if args.attack == "hastad":
        if not _validate_hastad(args):
            return 1
        return _run_hastad_cli(args)

    if args.attack == "batch_gcd":
        if not _validate_batch_gcd(args):
            return 1
        return _run_batch_gcd_cli(args)

    print(f"[Error] Unknown attack mode '{args.attack}'.")
    return 1


def _has_attack_inputs(args):
    return any(
        value is not None
        for value in (
            args.attack,
            args.modulus,
            args.exponent,
            args.ciphertext,
            args.e2,
            args.c1,
            args.c2,
            args.broadcast,
            args.corpus,
        )
    )

def crack(n, e, ciphertext=None, broadcast=None, common=None, corpus=None,
          max_fermat_iterations=100000):

    if e <= SMALL_E and broadcast and len(broadcast) >= e:
        moduli = [bn for bn, _ in broadcast]
        cts = [bc for _, bc in broadcast]
        m = hastad_broadcast(cts, moduli, e)
        if m is not None:
            return CrackResult("hastad", message=m)

    factored = fermat_factor(n, max_iterations=max_fermat_iterations)
    if factored is not None:
        p, q = factored
        d, message = _solve_from_factors(n, e, p, q, ciphertext)
        return CrackResult("fermat", factors=(p, q), d=d, message=message)

    wiener = wiener_attack(n, e)
    if wiener is not None:
        d, p, q = wiener
        message = pow(ciphertext, d, n) if ciphertext is not None else None
        return CrackResult("wiener", factors=(p, q), d=d, message=message)

    if common is not None:
        e2, c1, c2 = common
        if gcd(e, e2) == 1:
            m = common_modulus_attack(n, e, e2, c1, c2)
            return CrackResult("common_modulus", message=m)

    if corpus:
        pool = list(corpus)
        if n not in pool:
            pool.append(n)
        factors = batch_gcd(pool)
        f = factors[pool.index(n)]
        if f is not None:
            p, q = f, n // f
            d, message = _solve_from_factors(n, e, p, q, ciphertext)
            return CrackResult("batch_gcd", factors=(p, q), d=d, message=message)

    return CrackResult(None)

def _second_exponent(phi, e1):
    e2 = e1 + 2
    while True:
        g, _, _ = egcd(e2, phi)
        if g == 1 and e2 != e1:
            return e2
        e2 += 2

def _report(kind, res, secret=None, message=None):
    print(f"[{kind}] attack chosen: {res.attack}")
    if res.factors:
        print(f"  factors: {res.factors[0]} * {res.factors[1]}")
    if res.d is not None:
        tag = "" if secret is None else (" (matches key)" if res.d == secret else " (MISMATCH)")
        print(f"  recovered d: {res.d}{tag}")
    if res.message is not None:
        tag = "" if message is None else (" (matches)" if res.message == message else " (MISMATCH)")
        print(f"  recovered message: {res.message}{tag}")
    if res.attack is None:
        print("  no weakness detected -- key resists these attacks")

def _run_demo(kind, bits):
    if kind == "fermat":
        pub, priv = close_prime_key(bits=bits, gap=1000)
        m = 67
        print(f"[{kind}] target setup:")
        print(f"  original n: {pub.n}")
        print(f"  original e: {pub.e}")
        print(f"  original factors (p * q): {priv.p} * {priv.q}")
        print(f"  original secret d: {priv.d}")
        print(f"  original message m: {m}")
        print()
        res = crack(pub.n, pub.e, ciphertext=encrypt_int(m, pub))
        print(f"[{kind}] attack execution:")
        print(f"  attack chosen: {res.attack}")
        if res.factors:
            expected = {priv.p, priv.q}
            recovered = {res.factors[0], res.factors[1]}
            tag = " (matches)" if recovered == expected else " (MISMATCH)"
            print(f"  recovered factors: {res.factors[0]} * {res.factors[1]}{tag}")
        if res.d is not None:
            tag = " (matches key)" if res.d == priv.d else " (MISMATCH)"
            print(f"  recovered d: {res.d}{tag}")
        if res.message is not None:
            tag = " (matches)" if res.message == m else " (MISMATCH)"
            print(f"  recovered message: {res.message}{tag}")
    elif kind == "wiener":
        pub, priv = small_d_key(bits=bits)
        m = 1234567
        print(f"[{kind}] target setup:")
        print(f"  original n: {pub.n}")
        print(f"  original e: {pub.e}")
        print(f"  original factors (p * q): {priv.p} * {priv.q}")
        print(f"  original secret d: {priv.d} (small private exponent)")
        print(f"  original message m: {m}")
        print()
        res = crack(pub.n, pub.e, ciphertext=encrypt_int(m, pub))
        print(f"[{kind}] attack execution:")
        print(f"  attack chosen: {res.attack}")
        if res.factors:
            expected = {priv.p, priv.q}
            recovered = {res.factors[0], res.factors[1]}
            tag = " (matches)" if recovered == expected else " (MISMATCH)"
            print(f"  recovered factors: {res.factors[0]} * {res.factors[1]}{tag}")
        if res.d is not None:
            tag = " (matches key)" if res.d == priv.d else " (MISMATCH)"
            print(f"  recovered d: {res.d}{tag}")
        if res.message is not None:
            tag = " (matches)" if res.message == m else " (MISMATCH)"
            print(f"  recovered message: {res.message}{tag}")
    elif kind == "hastad":
        e = 3
        keys = small_e_keys(bits=bits, e=e, count=e)
        m = 42424242
        broadcast = [(pub.n, pow(m, e, pub.n)) for pub, _ in keys]
        moduli_str = ", ".join(f"n{i+1}={n}" for i, (n, _) in enumerate(broadcast))
        cts_str = ", ".join(f"c{i+1}={c}" for i, (_, c) in enumerate(broadcast))
        print(f"[{kind}] target setup:")
        print(f"  exponent e: {e}")
        print(f"  broadcast count: {len(broadcast)}")
        print(f"  original message m: {m}")
        print(f"  target moduli: [{moduli_str}]")
        print(f"  ciphertexts:   [{cts_str}]")
        print()
        n0 = keys[0][0].n
        res = crack(n0, e, broadcast=broadcast)
        print(f"[{kind}] attack execution:")
        print(f"  attack chosen: {res.attack}")
        if res.message is not None:
            tag = " (matches)" if res.message == m else " (MISMATCH)"
            print(f"  recovered message: {res.message}{tag}")
    elif kind == "common_modulus":
        pub, priv = generate_keypair(bits=bits)
        phi = (priv.p - 1) * (priv.q - 1)
        e2 = _second_exponent(phi, pub.e)
        m = 123456789
        c1 = pow(m, pub.e, pub.n)
        c2 = pow(m, e2, pub.n)
        print(f"[{kind}] target setup:")
        print(f"  modulus n: {pub.n}")
        print(f"  exponent e1: {pub.e}")
        print(f"  exponent e2: {e2}")
        print(f"  original message m: {m}")
        print(f"  ciphertext c1: {c1}")
        print(f"  ciphertext c2: {c2}")
        print()
        res = crack(pub.n, pub.e, common=(e2, c1, c2))
        print(f"[{kind}] attack execution:")
        print(f"  attack chosen: {res.attack}")
        if res.message is not None:
            tag = " (matches)" if res.message == m else " (MISMATCH)"
            print(f"  recovered message: {res.message}{tag}")
    elif kind == "batch_gcd":
        corpus = shared_prime_keys(bits=bits, num_keys=8, num_shared=2)
        n0 = corpus[0]
        shared = []
        for i in range(len(corpus)):
            for j in range(i + 1, len(corpus)):
                g = gcd(corpus[i], corpus[j])
                if g > 1 and g not in shared:
                    shared.append(g)
        shared_str = ", ".join(f"shared_p{i+1}={p}" for i, p in enumerate(shared))
        shared_label = "unknown"
        for i, sp in enumerate(shared):
            if n0 % sp == 0:
                shared_label = f"shared_p{i+1}"
                break
        print(f"[{kind}] target setup:")
        print(f"  corpus size: {len(corpus)} moduli")
        print(f"  shared prime pool: [{shared_str}]")
        print(f"  target modulus n0: {n0} (shares prime {shared_label})")
        print()
        res = crack(n0, 65537, corpus=corpus)
        print(f"[{kind}] attack execution:")
        print(f"  attack chosen: {res.attack}")
        if res.factors:
            p, q = res.factors
            tag = " (matches)" if p * q == n0 else " (MISMATCH)"
            print(f"  recovered factors for n0: {p} * {q}{tag}")
        if res.d is not None:
            print(f"  recovered d for n0: {res.d}")
    elif kind == "correct":
        pub, priv = generate_keypair(bits=bits)
        print(f"[{kind}] target setup:")
        print(f"  original n: {pub.n}")
        print(f"  original e: {pub.e}")
        print(f"  original factors (p * q): {priv.p} * {priv.q}")
        print(f"  original secret d: {priv.d}")
        print()
        res = crack(pub.n, pub.e)
        print(f"[{kind}] attack execution:")
        print(f"  attack chosen: {res.attack}")
        if res.attack is None:
            print("  no weakness detected -- key resists these attacks")

def _parse_broadcast(values):
    if values is None:
        return None
    pairs = []
    for item in values:
        if ":" not in item:
            raise argparse.ArgumentTypeError(
                f"broadcast entry must be n:c, got {item!r}"
            )
        n_str, c_str = item.split(":", 1)
        pairs.append((int(n_str), int(c_str)))
    return pairs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RSA weakness orchestrator")
    parser.add_argument(
        "--attack",
        choices=["auto", "fermat", "wiener", "hastad", "common_modulus", "batch_gcd"],
        default=None,
        help="attack to run against user-supplied parameters (default: auto when params given)",
    )
    parser.add_argument("-n", "--modulus", type=int, default=None, help="public modulus n")
    parser.add_argument("-e", "--exponent", type=int, default=None, help="public exponent e")
    parser.add_argument("-c", "--ciphertext", type=int, default=None, help="ciphertext c")
    parser.add_argument("--e2", type=int, default=None, help="second public exponent (common modulus)")
    parser.add_argument("--c1", type=int, default=None, help="ciphertext 1 (common modulus)")
    parser.add_argument("--c2", type=int, default=None, help="ciphertext 2 (common modulus)")
    parser.add_argument(
        "--broadcast",
        nargs="+",
        default=None,
        metavar="N:C",
        help="Håstad broadcast pairs as n:c values",
    )
    parser.add_argument(
        "--corpus",
        nargs="+",
        type=int,
        default=None,
        metavar="N",
        help="moduli for Batch-GCD attack",
    )
    parser.add_argument(
        "--demo",
        choices=["fermat", "wiener", "hastad", "common_modulus", "batch_gcd", "correct", "all"],
        default=None,
        help="which weak-key scenario to build and attack",
    )
    parser.add_argument("--bits", type=int, default=512, help="modulus size for the demo keys")
    args = parser.parse_args()

    if args.broadcast is not None:
        try:
            args.broadcast = _parse_broadcast(args.broadcast)
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))

    if args.demo is not None:
        kinds = (["fermat", "wiener", "hastad", "common_modulus", "batch_gcd", "correct"]
                 if args.demo == "all" else [args.demo])
        for k in kinds:
            _run_demo(k, args.bits)
    elif args.attack is not None or _has_attack_inputs(args):
        if args.attack is None:
            args.attack = "auto"
        raise SystemExit(_run_attack_cli(args))
    else:
        for k in ["fermat", "wiener", "hastad", "common_modulus", "batch_gcd", "correct"]:
            _run_demo(k, args.bits)
