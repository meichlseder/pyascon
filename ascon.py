#!/usr/bin/env python

"""
Implementation of Ascon, an authenticated cipher
http://ascon.iaik.tugraz.at/
"""

debug = False
debugpermutation = False

# === Ascon encryption and decryption ===

def ascon_encrypt(key, nonce, associateddata, plaintext): 
    """
    Ascon encryption.
    key: a bytes object of size 12 or 16 (for 96- or 128-bit security)
    nonce: a bytes object of same size as key (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    plaintext: a bytes object of arbitrary length
    returns a bytes object containing the ciphertext and tag
    """
    assert(len(key) in [12, 16])
    assert(len(nonce) == len(key))
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8   # bits
    a = 12   # rounds
    b = 6 if k == 128 else 8   # rounds
    rate = 8 if k == 128 else 16   # bytes

    ascon_initialize(S, k, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, a, key)
    return ciphertext + tag


def ascon_decrypt(key, nonce, associateddata, ciphertext):
    """
    Ascon decryption.
    key: a bytes object of size 12 or 16 (for 96- or 128-bit security)
    nonce: a bytes object of same size as key (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    ciphertext: a bytes object of arbitrary length (also contains tag)
    returns a bytes object containing the plaintext or None if verification fails
    """
    assert(len(key) in [12, 16])
    assert(len(key) == len(nonce))
    assert(len(ciphertext) >= len(key))
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8 # bits
    a = 12 # rounds
    b = 6 if k == 128 else 8  # rounds
    rate = 8 if k == 128 else 16 # bytes

    ascon_initialize(S, k, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ciphertext[:-len(key)])
    tag = ascon_finalize(S, a, key)
    if tag == ciphertext[-len(key):]:
        return plaintext
    else:
        return None


# === Ascon building blocks ===

def ascon_initialize(S, k, a, b, key, nonce):
    """
    Ascon initialization phase. 
    S: Ascon state, a list of 5 64-bit integers
    k: key size in bits
    a: number of initialization/finalization rounds for permutation
    b: number of intermediate rounds for permutation
    key: a bytes object of size 12 or 16 (for 96- or 128-bit security)
    nonce: a bytes object of same size as key
    returns nothing, updates S
    """
    zero_key_nonce = zero_bytes(32-len(key)-len(nonce)) + key + nonce
    zero_key = zero_bytes(16-len(key)) + key
    S[0] = bytes_to_int(to_bytes([k, a, b, 0, 0, 0, 0, 0]))
    S[1] = bytes_to_int(zero_key_nonce[0:8])
    S[2] = bytes_to_int(zero_key_nonce[8:16])
    S[3] = bytes_to_int(zero_key_nonce[16:24])
    S[4] = bytes_to_int(zero_key_nonce[24:32])
    if debug: printstate(S, "initial value:")

    ascon_permutation(S, a)

    S[3] ^= bytes_to_int(zero_key[0:8])
    S[4] ^= bytes_to_int(zero_key[8:16])
    if debug: printstate(S, "initialization:")


def ascon_process_associated_data(S, b, rate, associateddata):
    """
    Ascon associated data processing phase. 
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (8 for 128-bit security, 16 for 96-bit security)
    associateddata: a bytes object of arbitrary length
    returns nothing, updates S
    """
    if len(associateddata) > 0:
        a_zeros = rate - (len(associateddata) % rate) - 1
        a_padding = to_bytes([0x80] + [0 for i in range(a_zeros)])
        a_padded = associateddata + a_padding

        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block+8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block+8:block+16])

            ascon_permutation(S, b)

    S[4] ^= 1
    if debug: printstate(S, "process associated data:")


def ascon_process_plaintext(S, b, rate, plaintext):
    """
    Ascon plaintext processing phase (during encryption). 
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (8 for 128-bit security, 16 for 96-bit security)
    plaintext: a bytes object of arbitrary length
    returns the ciphertext (without tag), updates S
    """
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x80] + (rate-p_lastlen-1)*[0x00])
    p_padded = plaintext + p_padding

    # first t-1 blocks
    ciphertext = to_bytes([])
    for block in range(0, len(p_padded) - rate, rate):
        if rate == 8:
            S[0] ^= bytes_to_int(p_padded[block:block+8])
            ciphertext += int_to_bytes(S[0], 8)
        elif rate == 16:
            S[0] ^= bytes_to_int(p_padded[block:block+8])
            S[1] ^= bytes_to_int(p_padded[block+8:block+16])
            ciphertext += (int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8))

        ascon_permutation(S, b)

    # last block t
    block = len(p_padded) - rate
    if rate == 8:
        S[0] ^= bytes_to_int(p_padded[block:block+8])
        ciphertext += int_to_bytes(S[0], 8)[:p_lastlen]
    elif rate == 16:
        S[0] ^= bytes_to_int(p_padded[block:block+8])
        S[1] ^= bytes_to_int(p_padded[block+8:block+16])
        ciphertext += (int_to_bytes(S[0], 8)[:min(8,p_lastlen)] + int_to_bytes(S[1], 8)[:max(0,p_lastlen-8)])
    if debug: printstate(S, "process plaintext:")
    return ciphertext


def ascon_process_ciphertext(S, b, rate, ciphertext):
    """
    Ascon ciphertext processing phase (during decryption). 
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (8 for 128-bit security, 16 for 96-bit security)
    ciphertext: a bytes object of arbitrary length
    returns the plaintext, updates S
    """
    c_lastlen = len(ciphertext) % rate
    c_padded = ciphertext + zero_bytes(rate - c_lastlen)

    # first t-1 blocks
    plaintext = to_bytes([])
    for block in range(0, len(c_padded) - rate, rate):
        if rate == 8:
            Ci = bytes_to_int(c_padded[block:block+8])
            plaintext += int_to_bytes(S[0] ^ Ci, 8)
            S[0] = Ci
        elif rate == 16:
            Ci = (bytes_to_int(c_padded[block:block+8]), bytes_to_int(c_padded[block+8:block+16]))
            plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))
            S[0] = Ci[0]
            S[1] = Ci[1]

        ascon_permutation(S, b)

    # last block t
    block = len(c_padded) - rate
    if rate == 8:
        c_padding1 = (0x80 << (rate-c_lastlen-1)*8)
        c_mask = (0xFFFFFFFFFFFFFFFF >> (c_lastlen*8))
        Ci = bytes_to_int(c_padded[block:block+8])
        plaintext += int_to_bytes(Ci ^ S[0], 8)[:c_lastlen]
        S[0] = Ci ^ (S[0] & c_mask) ^ c_padding1
    elif rate == 16:
        c_lastlen_word = c_lastlen % 8
        c_padding1 = (0x80 << (8-c_lastlen_word-1)*8)
        c_mask = (0xFFFFFFFFFFFFFFFF >> (c_lastlen_word*8))
        Ci = (bytes_to_int(c_padded[block:block+8]), bytes_to_int(c_padded[block+8:block+16]))
        plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))[:c_lastlen]
        if c_lastlen < 8:
            S[0] = Ci[0] ^ (S[0] & c_mask) ^ c_padding1
        else:
            S[0] = Ci[0]
            S[1] = Ci[1] ^ (S[1] & c_mask) ^ c_padding1
    if debug: printstate(S, "process ciphertext:")
    return plaintext


def ascon_finalize(S, a, key):
    """
    Ascon finalization phase.
    S: Ascon state, a list of 5 64-bit integers
    a: number of initialization/finalization rounds for permutation
    key: a bytes object of size 12 or 16 (for 96- or 128-bit security)
    returns the tag, updates S
    """
    if len(key) == 12:
        S[2] ^= bytes_to_int(key[0:8])
        S[3] ^= bytes_to_int(key[8:12] + to_bytes([0, 0, 0, 0]))
    elif len(key) == 16:
        S[1] ^= bytes_to_int(key[0:8])
        S[2] ^= bytes_to_int(key[8:16])

    ascon_permutation(S, a)

    if len(key) == 12:
        S[3] ^= bytes_to_int(key[0:4])
        S[4] ^= bytes_to_int(key[4:12])
        tag = int_to_bytes(S[3], 4) + int_to_bytes(S[4], 8)
    elif len(key) == 16:
        S[3] ^= bytes_to_int(key[0:8])
        S[4] ^= bytes_to_int(key[8:16])
        tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    if debug: printstate(S, "finalization:")
    return tag


def ascon_permutation(S, rounds=1):
    """
    Ascon core permutation for the sponge construction.
    S: Ascon state, a list of 5 64-bit integers
    rounds: number of rounds to perform
    returns nothing, updates S
    """
    assert(rounds < 16)
    if debugpermutation: printwords(S, "permutation input:")
    for i in range(rounds):
        # --- add round constants ---
        S[2] ^= (0xf0 - i*0x10 + i*0x1)
        if debugpermutation: printwords(S, "round constant addition:")
        # --- substitution layer ---
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i+1)%5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0XFFFFFFFFFFFFFFFF
        if debugpermutation: printwords(S, "substitution layer:")
        # --- linear diffusion layer ---
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)
        if debugpermutation: printwords(S, "linear diffusion layer:")


# === helper functions ===

def get_random_bytes(num):
    import os
    return to_bytes(os.urandom(num))

def zero_bytes(n):
    return n * "\x00"

def to_bytes(l): # where l is a list or bytearray or bytes
    return bytes(bytearray(l))

def bytes_to_int(bytes):
    return sum([ord(bi) << ((len(bytes) - 1 - i)*8) for i, bi in enumerate(to_bytes(bytes))])

def int_to_bytes(integer, nbytes):
    return to_bytes([(integer >> ((nbytes - 1 - i) * 8)) % 256 for i in range(nbytes)])

def rotr(val, r):
    return ((val >> r) ^ (val << (64-r))) % (1 << 64)

def bytes_to_hex(b):
    return "".join(x.encode('hex') for x in b)

def printstate(S, description=""):
    print " " + description
    print " ".join(["{s:016x}".format(s=s) for s in S])

def printwords(S, description=""):
    print " " + description
    print "\n".join(["  x{i}={s:016x}".format(**locals()) for i, s in enumerate(S)])


# === some demo if called directly ===

if __name__ == "__main__":
    keysize = 16
    print "=== demo encryption using Ascon{bitsize} ===".format(bitsize=keysize*8)

    key = zero_bytes(keysize)
    nonce = zero_bytes(keysize)
    #key = get_random_bytes(keysize)
    #nonce = get_random_bytes(keysize)
    associateddata = b"ASCON"
    plaintext = b"ascon"

    ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext)
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext)

    if receivedplaintext == None: 
        print "verification failed!"
        
    data = [
            ("key", key), 
            ("nonce", nonce), 
            ("plaintext", plaintext), 
            ("ass.data", associateddata), 
            ("ciphertext", ciphertext[:-len(key)]), 
            ("tag", ciphertext[-len(key):]), 
            ("received", receivedplaintext), 
           ]
    maxlen = max([len(text) for (text, val) in data])
    for text, val in data:
        print "{text}:{align} 0x{val} ({length} bytes)".format(text=text, align=((maxlen - len(text)) * " "), val=bytes_to_hex(val), length=len(val))
