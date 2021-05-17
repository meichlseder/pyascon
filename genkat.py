#!/usr/bin/env python3

"""
KAT implementation for NIST (based on TestVectorGen.zip)
"""

import ascon
import sys

def kat_print_str(fp, string):
    "print string to file pointer fp"
    fp.write("{string}\n".format(string=string))

def kat_print_val(fp, label, value):
    "print 'label = value' for integer 'value' with kat_print to file pointer fp"
    kat_print_str(fp, "{label} = {value}".format(label=label, value=value))

def kat_print_hex(fp, label, data, length):
    "print 'label = data[:length]' for string 'data' with kat_print to file pointer fp"
    assert len(data) >= length
    kat_print_str(fp, "{label} = {data}".format(label=label, data=data[:length].hex().upper()))

def kat_bytes(length):
    return bytes(bytearray([i % 256 for i in range(length)]))


def kat_aead(variant):
    MAX_MESSAGE_LENGTH = 32
    MAX_ASSOCIATED_DATA_LENGTH = 32

    klen = 20 if variant == "Ascon-80pq" else 16  # =CRYPTO_KEYBYTES
    nlen = 16  # =CRYPTO_NPUBBYTES
    tlen = 16  # <=CRYPTO_ABYTES
    filename = "LWC_AEAD_KAT_{klenbits}_{nlenbits}.txt".format(klenbits=klen*8, nlenbits=nlen*8)
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]

    key   = kat_bytes(klen)
    nonce = kat_bytes(nlen)
    msg   = kat_bytes(MAX_MESSAGE_LENGTH)
    ad    = kat_bytes(MAX_ASSOCIATED_DATA_LENGTH)

    with open(filename, "w") as fp:
        count = 1
        for mlen in range(MAX_MESSAGE_LENGTH+1):
            for adlen in range(MAX_ASSOCIATED_DATA_LENGTH+1):
                kat_print_val(fp, "Count", count)
                count += 1
                kat_print_hex(fp, "Key", key, klen)
                kat_print_hex(fp, "Nonce", nonce, nlen)
                kat_print_hex(fp, "PT", msg, mlen)
                kat_print_hex(fp, "AD", ad, adlen)
                ct = ascon.ascon_encrypt(key, nonce, ad[:adlen], msg[:mlen], variant)
                assert len(ct) == mlen + tlen
                kat_print_hex(fp, "CT", ct, len(ct))
                kat_print_str(fp, "")
                msg2 = ascon.ascon_decrypt(key, nonce, ad[:adlen], ct, variant)
                assert len(msg2) == mlen
                assert msg2 == msg[:mlen]
        

def kat_hash(variant="Ascon-Hash"):
    MAX_MESSAGE_LENGTH = 1024
    hlen = 32  # =CRYPTO_BYTES
    filename = "LWC_HASH_KAT_{hlenbits}.txt".format(hlenbits=hlen*8)
    assert variant in ["Ascon-Xof", "Ascon-Xofa", "Ascon-Hash", "Ascon-Hasha"]

    msg = kat_bytes(MAX_MESSAGE_LENGTH)
    with open(filename, "w") as fp:
        count = 1
        for mlen in range(MAX_MESSAGE_LENGTH+1):
            kat_print_val(fp, "Count", count)
            count += 1
            kat_print_hex(fp, "Msg", msg, mlen)
            tag = ascon.ascon_hash(msg[:mlen], variant, hlen)
            kat_print_hex(fp, "MD", tag, hlen)
            kat_print_str(fp, "")


def kat(variant):
    aead_variants = ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    hash_variants = ["Ascon-Hash", "Ascon-Hasha", "Ascon-Xof", "Ascon-Xofa"]
    assert variant in aead_variants + hash_variants
    kat_fun = kat_aead if variant in aead_variants else kat_hash
    kat_fun(variant)


if __name__ == "__main__":
    variant = sys.argv[1] if len(sys.argv) > 1 else "Ascon-128"
    kat(variant)
