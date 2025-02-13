#!/usr/bin/env python3

"""
Implementation of Ascon, an authenticated cipher and hash function
NIST SP 800-232
https://ascon.iaik.tugraz.at/
"""

debug = False
debugpermutation = False

# === Ascon hash/xof ===

def ascon_hash(message, variant="Ascon-Hash256", hashlength=32, customization=b""): 
    """
    Ascon hash function and extendable-output function.
    message: a bytes object of arbitrary length
    variant: "Ascon-Hash256" (with 256-bit output for 128-bit security), "Ascon-XOF128", or "Ascon-CXOF128" (both with arbitrary output length, security=min(128, bitlen/2))
    hashlength: the requested output bytelength (must be 32 for variant "Ascon-Hash256"; can be arbitrary for Ascon-XOF128, but should be >= 32 for 128-bit security)
    customization: a bytes object of at most 256 bytes specifying the customization string (only for Ascon-CXOF128)
    returns a bytes object containing the hash tag
    """
    versions = {"Ascon-Hash256": 2,
                "Ascon-XOF128": 3,
                "Ascon-CXOF128": 4}
    assert variant in versions.keys()
    if variant == "Ascon-Hash256": assert hashlength == 32
    if variant == "Ascon-CXOF128": assert len(customization) <= 256
    else: assert len(customization) == 0
    a = b = 12 # rounds
    rate = 8 # bytes
    taglen = 256 if variant == "Ascon-Hash256" else 0
    customize = True if variant == "Ascon-CXOF128" else False

    # Initialization
    iv = to_bytes([versions[variant], 0, (b<<4) + a]) + int_to_bytes(taglen, 2) + to_bytes([rate, 0, 0])
    S = bytes_to_state(iv + zero_bytes(32))
    if debug: printstate(S, "initial value:")

    ascon_permutation(S, 12)
    if debug: printstate(S, "initialization:")

    # Customization
    if customize: 
        z_padding = to_bytes([0x01]) + zero_bytes(rate - (len(customization) % rate) - 1)
        z_length = int_to_bytes(len(customization)*8, 8)
        z_padded = z_length + customization + z_padding

        # customization blocks 0,...,m
        for block in range(0, len(z_padded), rate):
            S[0] ^= bytes_to_int(z_padded[block:block+rate])
            ascon_permutation(S, 12)
        if debug: printstate(S, "customization:")

    # Message Processing (Absorbing)
    m_padding = to_bytes([0x01]) + zero_bytes(rate - (len(message) % rate) - 1)
    m_padded = message + m_padding

    # message blocks 0,...,n
    for block in range(0, len(m_padded), rate):
        S[0] ^= bytes_to_int(m_padded[block:block+rate])
        ascon_permutation(S, 12)
    if debug: printstate(S, "process message:")

    # Finalization (Squeezing)
    H = b""
    while len(H) < hashlength:
        H += int_to_bytes(S[0], rate)
        ascon_permutation(S, 12)
    if debug: printstate(S, "finalization:")
    return H[:hashlength]


# === Ascon MAC/PRF ===

def ascon_mac(key, message, variant="Ascon-Mac", taglength=16): 
    """
    Ascon message authentication code (MAC) and pseudorandom function (PRF).
    key: a bytes object of size 16
    message: a bytes object of arbitrary length (<= 16 for "Ascon-PrfShort")
    variant: "Ascon-Mac" (128-bit output, arbitrarily long input), "Ascon-Prf" (arbitrarily long input and output), or "Ascon-PrfShort" (t-bit output for t<=128, m-bit input for m<=128)
    taglength: the requested output bytelength l/8 (must be <=16 for variants "Ascon-Mac" and "Ascon-PrfShort", arbitrary for "Ascon-Prf"; should be >= 16 for 128-bit security)
    returns a bytes object containing the authentication tag
    """
    assert variant in ["Ascon-Mac", "Ascon-Prf", "Ascon-PrfShort"]
    if variant == "Ascon-Mac": assert len(key) == 16 and taglength <= 16
    if variant == "Ascon-Prf": assert len(key) == 16
    if variant == "Ascon-PrfShort": assert len(key) == 16 and taglength <= 16 and len(message) <= 16
    a = b = 12  # rounds
    msgblocksize = 32 # bytes (input rate for Mac, Prf)
    rate = 16 # bytes (output rate)

    # TODO update IVs to be consistent with NIST format

    if variant == "Ascon-PrfShort":
        # Initialization + Message Processing (Absorbing)
        IV = to_bytes([len(key) * 8, len(message)*8, a + 64, taglength * 8]) + zero_bytes(4)
        S = bytes_to_state(IV + key + message + zero_bytes(16 - len(message)))
        if debug: printstate(S, "initial value:")

        ascon_permutation(S, a)
        if debug: printstate(S, "process message:")

        # Finalization (Squeezing)
        T = int_to_bytes(S[3] ^ bytes_to_int(key[0:8]), 8) + int_to_bytes(S[4] ^ bytes_to_int(key[8:16]), 8)
        return T[:taglength]

    else: # Ascon-Prf, Ascon-Mac
        # Initialization
        if variant == "Ascon-Mac": tagspec = int_to_bytes(16*8, 4)
        if variant == "Ascon-Prf": tagspec = int_to_bytes(0*8, 4)
        S = bytes_to_state(to_bytes([len(key) * 8, rate * 8, a + 128, a-b]) + tagspec + key + zero_bytes(16))
        if debug: printstate(S, "initial value:")

        ascon_permutation(S, a)
        if debug: printstate(S, "initialization:")

        # Message Processing (Absorbing)
        m_padding = to_bytes([0x01]) + zero_bytes(msgblocksize - (len(message) % msgblocksize) - 1)
        m_padded = message + m_padding

        # first s-1 blocks
        for block in range(0, len(m_padded) - msgblocksize, msgblocksize):
            S[0] ^= bytes_to_int(m_padded[block:block+8])     # msgblocksize=32 bytes
            S[1] ^= bytes_to_int(m_padded[block+8:block+16])
            S[2] ^= bytes_to_int(m_padded[block+16:block+24])
            S[3] ^= bytes_to_int(m_padded[block+24:block+32])
            ascon_permutation(S, b)
        # last block
        block = len(m_padded) - msgblocksize
        S[0] ^= bytes_to_int(m_padded[block:block+8])     # msgblocksize=32 bytes
        S[1] ^= bytes_to_int(m_padded[block+8:block+16])
        S[2] ^= bytes_to_int(m_padded[block+16:block+24])
        S[3] ^= bytes_to_int(m_padded[block+24:block+32])
        S[4] ^= 1
        if debug: printstate(S, "process message:")

        # Finalization (Squeezing)
        T = b""
        ascon_permutation(S, a)
        while len(T) < taglength:
            T += int_to_bytes(S[0], 8)  # rate=16
            T += int_to_bytes(S[1], 8)
            ascon_permutation(S, b)
        if debug: printstate(S, "finalization:")
        return T[:taglength]


# === Ascon AEAD encryption and decryption ===

def ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-AEAD128"): 
    """
    Ascon encryption.
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16 (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    plaintext: a bytes object of arbitrary length
    variant: "Ascon-AEAD128"
    returns a bytes object of length len(plaintext)+16 containing the ciphertext and tag
    """
    versions = {"Ascon-AEAD128": 1}
    assert variant in versions.keys()
    assert len(key) == 16 and len(nonce) == 16
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8   # bits
    a = 12   # rounds
    b = 8    # rounds
    rate = 16   # bytes

    ascon_initialize(S, k, rate, a, b, versions[variant], key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, rate, a, key)
    return ciphertext + tag


def ascon_decrypt(key, nonce, associateddata, ciphertext, variant="Ascon-AEAD128"):
    """
    Ascon decryption.
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16 (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    ciphertext: a bytes object of arbitrary length (also contains tag)
    variant: "Ascon-AEAD128"
    returns a bytes object containing the plaintext or None if verification fails
    """
    versions = {"Ascon-AEAD128": 1}
    assert variant in versions.keys()
    assert len(key) == 16 and len(nonce) == 16 and len(ciphertext) >= 16
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8 # bits
    a = 12  # rounds
    b = 8   # rounds
    rate = 16   # bytes

    ascon_initialize(S, k, rate, a, b, versions[variant], key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ciphertext[:-16])
    tag = ascon_finalize(S, rate, a, key)
    if tag == ciphertext[-16:]:
        return plaintext
    else:
        return None


# === Ascon AEAD building blocks ===

def ascon_initialize(S, k, rate, a, b, version, key, nonce):
    """
    Ascon initialization phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    k: key size in bits
    rate: block size in bytes (16 for Ascon-AEAD128)
    a: number of initialization/finalization rounds for permutation
    b: number of intermediate rounds for permutation
    version: 1 (for Ascon-AEAD128)
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16
    returns nothing, updates S
    """
    taglen = 128
    iv = to_bytes([version, 0, (b<<4) + a]) + int_to_bytes(taglen, 2) + to_bytes([rate, 0, 0])
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(iv + key + nonce)
    if debug: printstate(S, "initial value:")

    ascon_permutation(S, a)

    zero_key = bytes_to_state(zero_bytes(40-len(key)) + key)
    S[0] ^= zero_key[0]
    S[1] ^= zero_key[1]
    S[2] ^= zero_key[2]
    S[3] ^= zero_key[3]
    S[4] ^= zero_key[4]
    if debug: printstate(S, "initialization:")


def ascon_process_associated_data(S, b, rate, associateddata):
    """
    Ascon associated data processing phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    associateddata: a bytes object of arbitrary length
    returns nothing, updates S
    """
    if len(associateddata) > 0:
        a_padding = to_bytes([0x01]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded = associateddata + a_padding

        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block+8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block+8:block+16])

            ascon_permutation(S, b)

    S[4] ^= 1<<63
    if debug: printstate(S, "process associated data:")


def ascon_process_plaintext(S, b, rate, plaintext):
    """
    Ascon plaintext processing phase (during encryption) - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    plaintext: a bytes object of arbitrary length
    returns the ciphertext (without tag), updates S
    """
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x01]) + zero_bytes(rate-p_lastlen-1)
    p_padded = plaintext + p_padding

    # first t-1 blocks
    ciphertext = to_bytes([])
    for block in range(0, len(p_padded) - rate, rate):
        S[0] ^= bytes_to_int(p_padded[block:block+8])
        S[1] ^= bytes_to_int(p_padded[block+8:block+16])
        ciphertext += (int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8))
        ascon_permutation(S, b)

    # last block t
    block = len(p_padded) - rate
    S[0] ^= bytes_to_int(p_padded[block:block+8])
    S[1] ^= bytes_to_int(p_padded[block+8:block+16])
    ciphertext += (int_to_bytes(S[0], 8)[:min(8,p_lastlen)] + int_to_bytes(S[1], 8)[:max(0,p_lastlen-8)])
    if debug: printstate(S, "process plaintext:")
    return ciphertext


def ascon_process_ciphertext(S, b, rate, ciphertext):
    """
    Ascon ciphertext processing phase (during decryption) - internal helper function. 
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    ciphertext: a bytes object of arbitrary length
    returns the plaintext, updates S
    """
    c_lastlen = len(ciphertext) % rate
    c_padded = ciphertext + zero_bytes(rate - c_lastlen)

    # first t-1 blocks
    plaintext = to_bytes([])
    for block in range(0, len(c_padded) - rate, rate):
        Ci = (bytes_to_int(c_padded[block:block+8]), bytes_to_int(c_padded[block+8:block+16]))
        plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))
        S[0] = Ci[0]
        S[1] = Ci[1]
        ascon_permutation(S, b)

    # last block t
    block = len(c_padded) - rate
    c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate-c_lastlen-1)
    c_mask = zero_bytes(c_lastlen) + ff_bytes(rate-c_lastlen)
    Ci = (bytes_to_int(c_padded[block:block+8]), bytes_to_int(c_padded[block+8:block+16]))
    plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))[:c_lastlen]
    S[0] = (S[0] & bytes_to_int(c_mask[0:8]))  ^ Ci[0] ^ bytes_to_int(c_padx[0:8])
    S[1] = (S[1] & bytes_to_int(c_mask[8:16])) ^ Ci[1] ^ bytes_to_int(c_padx[8:16])
    if debug: printstate(S, "process ciphertext:")
    return plaintext


def ascon_finalize(S, rate, a, key):
    """
    Ascon finalization phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    rate: block size in bytes (16 for Ascon-AEAD128)
    a: number of initialization/finalization rounds for permutation
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    returns the tag, updates S
    """
    assert len(key) == 16
    S[rate//8+0] ^= bytes_to_int(key[0:8])
    S[rate//8+1] ^= bytes_to_int(key[8:16])

    ascon_permutation(S, a)

    S[3] ^= bytes_to_int(key[-16:-8])
    S[4] ^= bytes_to_int(key[-8:])
    tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    if debug: printstate(S, "finalization:")
    return tag


# === Ascon permutation ===

def ascon_permutation(S, rounds=1):
    """
    Ascon core permutation for the sponge construction - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    rounds: number of rounds to perform
    returns nothing, updates S
    """
    assert rounds <= 12
    if debugpermutation: printwords(S, "permutation input:")
    for r in range(12-rounds, 12):
        # --- add round constants ---
        S[2] ^= (0xf0 - r*0x10 + r*0x1)
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
    return n * b"\x00"

def ff_bytes(n):
    return n * b"\xFF"

def to_bytes(l): # where l is a list or bytearray or bytes
    return bytes(bytearray(l))

def bytes_to_int(bytes):
    return sum([bi << (i*8) for i, bi in enumerate(to_bytes(bytes))])

def bytes_to_state(bytes):
    return [bytes_to_int(bytes[8*w:8*(w+1)]) for w in range(5)]

def int_to_bytes(integer, nbytes):
    return to_bytes([(integer >> (i * 8)) % 256 for i in range(nbytes)])

def rotr(val, r):
    return (val >> r) | ((val & (1<<r)-1) << (64-r))

def bytes_to_hex(b):
    return b.hex()
    #return "".join(x.encode('hex') for x in b)

def printstate(S, description=""):
    print(" " + description)
    print(" ".join(["{s:016x}".format(s=s) for s in S]))

def printwords(S, description=""):
    print(" " + description)
    print("\n".join(["  x{i}={s:016x}".format(**locals()) for i, s in enumerate(S)]))


# === some demo if called directly ===

def demo_print(data):
    maxlen = max([len(text) for (text, val) in data])
    for text, val in data:
        print("{text}:{align} 0x{val} ({length} bytes)".format(text=text, align=((maxlen - len(text)) * " "), val=bytes_to_hex(val), length=len(val)))

def demo_aead(variant="Ascon-AEAD128"):
    assert variant in ["Ascon-AEAD128"]
    print("=== demo encryption using {variant} ===".format(variant=variant))

    # choose a cryptographically strong random key and a nonce that never repeats for the same key:
    key   = get_random_bytes(16)  # zero_bytes(16)
    nonce = get_random_bytes(16)  # zero_bytes(16)
    
    associateddata = b"ASCON"
    plaintext      = b"ascon"

    ciphertext        = ascon_encrypt(key, nonce, associateddata, plaintext,  variant)
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext, variant)

    if receivedplaintext == None: print("verification failed!")
        
    demo_print([("key", key), 
                ("nonce", nonce), 
                ("plaintext", plaintext), 
                ("ass.data", associateddata), 
                ("ciphertext", ciphertext[:-16]), 
                ("tag", ciphertext[-16:]), 
                ("received", receivedplaintext), 
               ])

def demo_hash(variant="Ascon-Hash256", hashlength=32):
    assert variant in ["Ascon-Hash256", "Ascon-XOF128", "Ascon-CXOF128"]
    print("=== demo hash using {variant} ===".format(variant=variant))

    message = b"ascon"
    customization = b"custom" if variant == "Ascon-CXOF128" else b""
    tag = ascon_hash(message, variant, hashlength, customization)

    demo_print([("message", message), ("customization", customization), ("tag", tag)])

def demo_mac(variant="Ascon-Mac", taglength=16):
    # TODO rename variants to be consistent with NIST format
    assert variant in ["Ascon-Mac", "Ascon-Prf", "Ascon-PrfShort"]
    print("=== demo MAC using {variant} ===".format(variant=variant))

    key = get_random_bytes(16)
    message = b"ascon"
    tag = ascon_mac(key, message, variant)

    demo_print([("key", key), ("message", message), ("tag", tag)])


if __name__ == "__main__":
    demo_aead("Ascon-AEAD128")
    demo_hash("Ascon-Hash256")
    demo_hash("Ascon-XOF128")
    demo_hash("Ascon-CXOF128")
    demo_mac("Ascon-Mac")
