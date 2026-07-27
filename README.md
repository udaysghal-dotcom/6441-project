# Crackify

An educational RSA weakness detection tool built from scratch in Python. Crackify implements RSA primitives and six known attacks without relying on external cryptographic libraries, exposing the mathematical underpinnings behind each vulnerability.

---

## Quick Start

```bash
cd 6441-project

# Run all demos (generates weak keys, attacks them, shows results)
python3 crackify.py

# Run a specific demo
python3 crackify.py --demo fermat

# Attack a real public key (auto-detects weakness)
python3 crackify.py -n <modulus> -e <exponent>
```

---

## Usage Modes

Crackify operates in three modes:

| Mode | When it triggers |
|---|---|
| **Demo** | `--demo` flag is provided, or no arguments at all |
| **Attack (specific)** | `--attack <name>` is provided with the required parameters |
| **Attack (auto)** | Attack parameters (`-n`, `-e`, etc.) are provided without `--attack` — Crackify auto-detects the weakness |

---

## Global Flags

| Flag | Type | Description |
|---|---|---|
| `-n`, `--modulus` | `int` | Public modulus N |
| `-e`, `--exponent` | `int` | Public exponent e |
| `-c`, `--ciphertext` | `int` | Ciphertext to decrypt (optional, used to recover the message) |
| `--bits` | `int` | Key size in bits for demo mode (default: `512`) |

---

## Demo Mode

Generates deliberately weak keys, attacks them, and verifies the recovered values match the originals.

```bash
# Run all demos (fermat, wiener, hastad, common_modulus, batch_gcd, correct)
python3 crackify.py --demo all

# Run a single demo
python3 crackify.py --demo fermat
python3 crackify.py --demo wiener
python3 crackify.py --demo hastad
python3 crackify.py --demo common_modulus
python3 crackify.py --demo batch_gcd
python3 crackify.py --demo correct       # shows a properly generated key resisting all attacks

# Use smaller keys for faster demos
python3 crackify.py --demo all --bits 256
```

---

## Attack Mode

### Auto-detect

Supply public key parameters and Crackify will try all eligible attacks in priority order (Fermat → Wiener → Common Modulus → Håstad → Batch GCD):

```bash
python3 crackify.py -n <modulus> -e <exponent>
python3 crackify.py -n <modulus> -e <exponent> -c <ciphertext>
```

### Fermat Factorisation

Exploits primes p and q that are too close together.

```bash
python3 crackify.py --attack fermat -n <modulus>

# With ciphertext (also recovers the message)
python3 crackify.py --attack fermat -n <modulus> -e <exponent> -c <ciphertext>
```

**Required:** `-n`

### Wiener's Attack

Exploits a small private exponent d via continued fraction expansion.

```bash
python3 crackify.py --attack wiener -n <modulus> -e <exponent>
```

**Required:** `-n`, `-e`

### Common Modulus Attack

Recovers the plaintext when the same modulus is used with two different public exponents.

| Flag | Description |
|---|---|
| `-e` | First public exponent (e1) |
| `--e2` | Second public exponent (e2) |
| `--c1` or `-c` | Ciphertext under e1 |
| `--c2` | Ciphertext under e2 |

```bash
python3 crackify.py --attack common_modulus \
  -n <modulus> \
  -e <e1> --e2 <e2> \
  --c1 <c1> --c2 <c2>
```

**Required:** `-n`, `-e`, `--e2`, `--c1`, `--c2`

### Håstad Broadcast Attack

Recovers the plaintext when the same unpadded message is sent to ≥ e recipients with different moduli.

| Flag | Format | Description |
|---|---|---|
| `--broadcast` | `N:C N:C ...` | Space-separated modulus:ciphertext pairs |
| `-e` | `int` | The public exponent (must have at least e pairs) |

```bash
python3 crackify.py --attack hastad \
  -e 3 \
  --broadcast 1234:5678 2345:6789 3456:7890
```

**Required:** `-e`, `--broadcast` (with at least e pairs)

### Batch GCD

Finds shared prime factors across a corpus of moduli generated with weak entropy.

| Flag | Format | Description |
|---|---|---|
| `--corpus` | `N N N ...` | Space-separated list of moduli to check |
| `-n` | `int` | Optional target modulus (if provided, focuses results on this key) |

```bash
# Scan a corpus for shared primes
python3 crackify.py --attack batch_gcd --corpus 111 222 333 444

# Focus on a specific target within the corpus
python3 crackify.py --attack batch_gcd -n <target_modulus> --corpus 111 222 333
```

**Required:** `--corpus` (at least 2 moduli total)

---

## Output

Successful attacks print:

```
[+] Attack Successful (Fermat)!
  p: <prime_factor_1>
  q: <prime_factor_2>
  d: <private_exponent>
  m: <recovered_message>
```

Failed attacks print:

```
[-] Fermat attack failed for the given inputs.
```

---

## Running Tests

The project uses `pytest` for testing. All tests live in the `tests/` directory.

```bash
cd 6441-project

# Activate the virtual environment
source .venv/bin/activate

# Run the full test suite
pytest

# Run with minimal output
pytest -q

# Deactivate when done
deactivate
```
