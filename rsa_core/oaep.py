import hashlib
import secrets
from .modmath import mod_exp

# to catch errors related to OEAPError rather than generic ValueError
class OAEPError(Exception):
    pass

# converts large integer into x length bytes
def _i2osp(x, length):
    if x >= (1 << (8 * length)):
        raise OAEPError("integer too large for the requested length")
    return x.to_bytes(length, "big")

# converts bytes back into large integer
def _os2ip(data):
    return int.from_bytes(data, "big")

# a byte wise XOR helper 
def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# mask generation function 1, masks to len = length 
def mgf1(seed, length, hashfn=hashlib.sha256):
    output = b""
    counter = 0
    while len(output) < length:
        c = _i2osp(counter, 4)
        output += hashfn(seed + c).digest()
        counter += 1
    return output[:length]

# implements oaep encoding for a 1024-bit key
def oaep_encode(message_bytes, k, label=b"", hashfn=hashlib.sha256):

    # calc length and validate input size
    h_len = hashfn().digest_size
    m_len = len(message_bytes)
    if m_len > k - 2 * h_len - 2:
        raise OAEPError("message too long for this modulus size")

    # build data block
    l_hash = hashfn(label).digest()
    ps = b"\x00" * (k - m_len - 2 * h_len - 2)
    data_block = l_hash + ps + b"\x01" + message_bytes

    # build random seed and mask the data block
    seed = secrets.token_bytes(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hashfn)
    masked_db = _xor(data_block, db_mask)
    seed_mask = mgf1(masked_db, h_len, hashfn)
    masked_seed = _xor(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded, k, label=b"", hashfn=hashlib.sha256):
    h_len = hashfn().digest_size
    if k < 2 * h_len + 2 or len(encoded) != k:
        raise OAEPError("decoding error")

    # split encoded block into components 
    y = encoded[0]
    masked_seed = encoded[1:1 + h_len]
    masked_db = encoded[1 + h_len:]

    # unmask the seed and data block
    seed_mask = mgf1(masked_db, h_len, hashfn)
    seed = _xor(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - h_len - 1, hashfn)
    db = _xor(masked_db, db_mask)

    l_hash = hashfn(label).digest()
    l_hash_prime = db[:h_len]

    # walk past the zero padding to the 0x01 separator
    i = h_len
    while i < len(db) and db[i] == 0:
        i += 1

    # message extraction
    valid = (y == 0) and (l_hash_prime == l_hash) and (i < len(db)) and (db[i] == 1)
    if not valid:
        raise OAEPError("decoding error")
    return db[i + 1:]

def _modulus_bytes(n):
    return (n.bit_length() + 7) // 8

# full padded encryption, returns ciphertext as k-byte string
def encrypt(pub, message_bytes, label=b"", hashfn=hashlib.sha256):
    k = _modulus_bytes(pub.n)
    encoded = oaep_encode(message_bytes, k, label, hashfn)
    m = _os2ip(encoded)
    c = mod_exp(m, pub.e, pub.n)
    return _i2osp(c, k)

def decrypt(priv, ciphertext, label=b"", hashfn=hashlib.sha256):
    k = _modulus_bytes(priv.n)
    if len(ciphertext) != k:
        raise OAEPError("ciphertext has the wrong length")
    c = _os2ip(ciphertext)
    m = mod_exp(c, priv.d, priv.n)
    encoded = _i2osp(m, k)
    return oaep_decode(encoded, k, label, hashfn)

if __name__ == "__main__":
    from .keygen import generate_keypair

    pub, priv = generate_keypair(1024)
    msg = b"some random message"
    ct = encrypt(pub, msg)
    recovered = decrypt(priv, ct)
    print("recovered original string", recovered == msg)

    tampered = bytearray(ct)
    tampered[-1] ^= 0x01
    try:
        decrypt(priv, bytes(tampered))
        print("no tamper detected")
    except OAEPError:
        print("tamper detected")
