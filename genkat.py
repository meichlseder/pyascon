#!/usr/bin/env python3

"""
KAT implementation for NIST (based on TestVectorGen.zip)
"""
from __future__ import annotations

import ascon
import sys
from writer import MultipleWriter
from typing import Literal

def kat_bytes(length: int) -> bytes:
    return bytes(bytearray([i % 256 for i in range(length)]))

def kat_aead(variant: ascon.AsconAeadVariant) -> None:
    MAX_MESSAGE_LENGTH = 32
    MAX_ASSOCIATED_DATA_LENGTH = 32

    klen = 16  # =CRYPTO_KEYBYTES
    nlen = 16  # =CRYPTO_NPUBBYTES
    tlen = 16  # <=CRYPTO_ABYTES
    filename = "LWC_AEAD_KAT_{klenbits}_{nlenbits}".format(klenbits=klen*8, nlenbits=nlen*8)
    assert variant in ["Ascon-AEAD128"]

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
                assert msg2 is not None
                assert len(msg2) == mlen
                assert msg2 == msg[:mlen]
                w.close()


def kat_hash(variant: ascon.AsconHashVariant|ascon.AsconCxofVariant = "Ascon-Hash256") -> None:
    MAX_MESSAGE_LENGTH = 1024
    hlen = 32  # =CRYPTO_BYTES
    hashtypes = {"Ascon-Hash256": "HASH",
                 "Ascon-XOF128": "HASH",  # or: XOF
                 "Ascon-CXOF128": "HASH"} # or: CXOF
    assert variant in hashtypes.keys()
    
    filename = "LWC_{hashtype}_KAT_{hlenbits}".format(hashtype=hashtypes[variant], hlenbits=hlen*8)

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


def kat_cxof(variant: Literal["Ascon-CXOF128"] = "Ascon-CXOF128") -> None:
    # proposed KAT format - not official reference
    MAX_MESSAGE_LENGTH = 32
    MAX_CUSTOMIZATION_LENGTH = 32
    hlen = 32  # =CRYPTO_BYTES
    cxoftypes = {"Ascon-CXOF128": "CXOF"}
    assert variant in cxoftypes.keys()
    
    filename = "LWC_{cxoftype}_KAT_{hlenbits}".format(cxoftype=cxoftypes[variant], hlenbits=hlen*8)

    msg    = kat_bytes(MAX_MESSAGE_LENGTH)
    custom = kat_bytes(MAX_CUSTOMIZATION_LENGTH)
    with MultipleWriter(filename) as w:
        count = 1
        for mlen in range(MAX_MESSAGE_LENGTH+1):
            for zlen in range(MAX_CUSTOMIZATION_LENGTH+1):
                w.open()
                w.append("Count", count)
                count += 1
                w.append("Msg", msg, mlen)
                w.append("Z", custom, zlen) # or CS?
                tag = ascon.ascon_hash(msg[:mlen], variant, hlen, custom[:zlen])
                w.append("MD", tag, hlen)
                w.close()


def kat_auth(variant: ascon.AsconMacVariant = "Ascon-Mac") -> None:
    MAX_MESSAGE_LENGTH = 1024
    if variant == "Ascon-PrfShort": MAX_MESSAGE_LENGTH = 16
    klen = 16
    hlen = 16
    filename = "LWC_AUTH_KAT_{klenbits}_{hlenbits}".format(klenbits=klen*8, hlenbits=hlen*8)
    assert variant in ["Ascon-Mac", "Ascon-Prf", "Ascon-PrfShort"]

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


def kat(variant: ascon.AsconVariant) -> None:
    aead_variants = ("Ascon-AEAD128",)
    hash_variants = ("Ascon-Hash256", "Ascon-XOF128", "Ascon-CXOF128")
    cxof_variants = ("Ascon-CXOF128",) # will produce two KATs (hash+cxof)
    auth_variants = ("Ascon-Mac", "Ascon-Prf", "Ascon-PrfShort")
    assert variant in aead_variants + hash_variants + cxof_variants + auth_variants
    if variant in aead_variants: kat_aead(variant)
    if variant in hash_variants: kat_hash(variant)
    if variant in cxof_variants: kat_cxof(variant)
    if variant in auth_variants: kat_auth(variant)


if __name__ == "__main__":
    variant = sys.argv[1] if len(sys.argv) > 1 else "Ascon-AEAD128"
    kat(variant)
