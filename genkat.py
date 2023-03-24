#!/usr/bin/env python3

"""
KAT implementation for NIST (based on TestVectorGen.zip)
"""

import ascon
import sys
from writer import MultipleWriter


def kat_bytes(length):
    return bytes(bytearray([i % 256 for i in range(length)]))


def kat_aead(variant):
    MAX_MESSAGE_LENGTH = 32
    MAX_ASSOCIATED_DATA_LENGTH = 32

    klen = 20 if variant == "Ascon-80pq" else 16  # =CRYPTO_KEYBYTES
    nlen = 16  # =CRYPTO_NPUBBYTES
    tlen = 16  # <=CRYPTO_ABYTES
    filename = "LWC_AEAD_KAT_{klenbits}_{nlenbits}".format(klenbits=klen*8, nlenbits=nlen*8)
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]

    key   = kat_bytes(klen)
    nonce = kat_bytes(nlen)
    msg   = kat_bytes(MAX_MESSAGE_LENGTH)
    ad    = kat_bytes(MAX_ASSOCIATED_DATA_LENGTH)

    with MultipleWriter(filename) as w:
        count = 1
        for mlen in range(MAX_MESSAGE_LENGTH+1):
            for adlen in range(MAX_ASSOCIATED_DATA_LENGTH+1):
                w.open()
                w.append("Count", count)
                count += 1
                w.append("Key", key, klen)
                w.append("Nonce", nonce, nlen)
                w.append("PT", msg, mlen)
                w.append("AD", ad, adlen)
                ct = ascon.ascon_encrypt(key, nonce, ad[:adlen], msg[:mlen], variant)
                assert len(ct) == mlen + tlen
                w.append("CT", ct, len(ct))
                msg2 = ascon.ascon_decrypt(key, nonce, ad[:adlen], ct, variant)
                assert len(msg2) == mlen
                assert msg2 == msg[:mlen]
                w.close()


def kat_hash(variant="Ascon-Hash"):
    MAX_MESSAGE_LENGTH = 1024
    hlen = 32  # =CRYPTO_BYTES
    filename = "LWC_HASH_KAT_{hlenbits}".format(hlenbits=hlen*8)
    assert variant in ["Ascon-Xof", "Ascon-Xofa", "Ascon-Hash", "Ascon-Hasha"]

    msg = kat_bytes(MAX_MESSAGE_LENGTH)
    with MultipleWriter(filename) as w:
        count = 1
        for mlen in range(MAX_MESSAGE_LENGTH+1):
            w.open()
            w.append("Count", count)
            count += 1
            w.append("Msg", msg, mlen)
            tag = ascon.ascon_hash(msg[:mlen], variant, hlen)
            w.append("MD", tag, hlen)
            w.close()


def kat_auth(variant="Ascon-Mac"):
    MAX_MESSAGE_LENGTH = 1024
    if variant == "Ascon-PrfShort": MAX_MESSAGE_LENGTH = 16
    klen = 16
    hlen = 16
    filename = "LWC_AUTH_KAT_{klenbits}_{hlenbits}".format(klenbits=klen*8, hlenbits=hlen*8)
    assert variant in ["Ascon-Mac", "Ascon-Maca", "Ascon-Prf", "Ascon-Prfa", "Ascon-PrfShort"]

    key = kat_bytes(klen)
    msg = kat_bytes(MAX_MESSAGE_LENGTH)
    with MultipleWriter(filename) as w:
        count = 1
        for mlen in range(MAX_MESSAGE_LENGTH+1):
            w.open()
            w.append("Count", count)
            count += 1
            w.append("Key", key, klen)
            w.append("Msg", msg, mlen)
            tag = ascon.ascon_mac(key, msg[:mlen], variant, hlen)
            w.append("Tag", tag, hlen)
            w.close()


def kat(variant):
    aead_variants = ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    hash_variants = ["Ascon-Hash", "Ascon-Hasha", "Ascon-Xof", "Ascon-Xofa"]
    auth_variants = ["Ascon-Mac", "Ascon-Maca", "Ascon-Prf", "Ascon-Prfa", "Ascon-PrfShort"]
    assert variant in aead_variants + hash_variants + auth_variants
    if variant in aead_variants: kat_fun = kat_aead
    if variant in hash_variants: kat_fun = kat_hash
    if variant in auth_variants: kat_fun = kat_auth
    kat_fun(variant)


if __name__ == "__main__":
    variant = sys.argv[1] if len(sys.argv) > 1 else "Ascon-128"
    kat(variant)
