from hashlib import sha256
import math
from random import randbytes

def sha_256(m):

    sha_hash = sha256()
    sha_hash.update(m)

    return sha_hash.digest()

def mgf1(seed, mlen: int):

    t = b''
    hlen = sha256(t).digest_size

    for c in range(math.ceil(mlen/hlen)):
        c = c.to_bytes(4, byteorder='big')
        t+= sha_256(seed + c) 

    return t[:mlen]


def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))


def oaep_encode(message, k):
    
    label = b''
    mlen = len(message)
    lhash = sha_256(label)
    hlen = len(lhash)
    seed = randbytes(hlen)

    ps_len =  k - mlen - (2 * hlen) - 2
    ps = b'0x00' * ps_len
    db = lhash + ps + b'\x01' + message

    db_mask = mgf1(seed, k - hlen - 1)
    masked_db = xor_bytes(db, db_mask)
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = xor_bytes(seed, seed_mask)

    return b'\x00' + masked_seed + masked_db

def oaep_decode(encoded_m, k):

    label = b''
    lhash = sha_256(label)
    hlen = len(lhash)

    _, masked_seed, masked_db = encoded_m[:1], encoded_m[1:1 + hlen], encoded_m[1 + hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - hlen - 1)
    db = xor_bytes(masked_db, db_mask)

    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break

    message = db[i:]  
    return message
