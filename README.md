Python implementation of Ascon
==============================

This is a Python3 implementation of Ascon v1.2, an authenticated cipher and hash function.

https://github.com/meichlseder/pyascon

Ascon
-----

Ascon is a family of [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) (AEAD) and [hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function) algorithms designed to be lightweight and easy to implement, even with added countermeasures against side-channel attacks.
It was designed by a team of cryptographers from Graz University of Technology, Infineon Technologies, and Radboud University: Christoph Dobraunig, Maria Eichlseder, Florian Mendel, and Martin Schläffer.

Ascon has been selected as the standard for lightweight cryptography in the [NIST Lightweight Cryptography competition (2019–2023)](https://csrc.nist.gov/projects/lightweight-cryptography) and as the primary choice for lightweight authenticated encryption in the final portfolio of the [CAESAR competition (2014–2019)](https://competitions.cr.yp.to/caesar-submissions.html).

Find more information, including the specification and more implementations here:

https://ascon.iaik.tugraz.at/


Algorithms
----------

This is a simple reference implementation of Ascon v1.2 as submitted to the NIST LWC competition that includes 

  * Authenticated encryption `ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-128")` (and similarly `decrypt`) with the following 3 family members:

    - `Ascon-128`
    - `Ascon-128a`
    - `Ascon-80pq`
  
  * Hashing algorithms `ascon_hash(message, variant="Ascon-Hash", hashlength=32)` including 4 hash function variants with fixed 256-bit (`Hash`) or variable (`Xof`) output lengths:

    - `Ascon-Hash`
    - `Ascon-Hasha`
    - `Ascon-Xof`
    - `Ascon-Xofa`
  
  * Message authentication codes `ascon_mac(key, message, variant="Ascon-Mac", taglength=16)` including 5 MAC variants (from https://eprint.iacr.org/2021/1574, not part of the LWC proposal) with fixed 128-bit (`Mac`) or variable (`Prf`) output lengths, including a variant for short messages of up to 128 bits (`PrfShort`).

    - `Ascon-Mac`
    - `Ascon-Maca`
    - `Ascon-Prf`
    - `Ascon-Prfa`
    - `Ascon-PrfShort`

Files
-----

  * `ascon.py`: 
    Implements all family members as well as the underlying permutation:

    - `ascon_encryption()`/`ascon_decrypt()` for authenticated encryption,
    - `ascon_hash()` for hashing,
    - `ascon_mac()` for message authentication,
    - `ascon_permutation()` for the underlying permutation.

    By default, prints the results of encrypting and hashing some example strings.

    - `debug = True|False`: Set this variable to print the intermediate state after each phase of the encryption/hashing process.
    - `debugpermutation = True|False`: Set this variable to print the intermediate state after each step of the permutation's round function.


  * `genkat.py`:
    Produces result files for the Known Answer Tests (KATs) defined for the [NIST LWC competition](https://csrc.nist.gov/projects/lightweight-cryptography) ([call for algorithms](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/final-lwc-submission-requirements-august2018.pdf), [test vector generation code](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/TestVectorGen.zip)).

    Call with the name of the target algorithm (see above) as first parameter, default is `Ascon-128`:

    ```sh
    python3 genkat.py Ascon-128

    ```

    Results are written to 

    - `LWC_AEAD_KAT_{klenbits}_{nlenbits}.txt` for authenticated encryption,
    - `LWC_HASH_KAT_{hlenbits}.txt` for hashing,
    - `LWC_AUTH_KAT_128_128.txt` for message authentication codes.

    Additionally, a JSON version of the same data is written to the corresponding `.json` files.
    Note that this may overwrite KATs for other variants which share the same parameters.


  * `writer.py`:
    Helper code for `genkat.py` that specifies the text and JSON encoding.

