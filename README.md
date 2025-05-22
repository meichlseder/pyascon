Python implementation of Ascon
==============================

This is a Python3 implementation of Ascon, a family of lightweight cryptographic algorithms.
`ascon.py` includes the authenticated encryption and hash function variants as specified in [NIST SP 800-232 (initial public draft)](https://csrc.nist.gov/pubs/sp/800/232/ipd).

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

This is a simple reference implementation of Ascon as specified in NIST's draft standard, NIST SP 800-232, which includes

  * Authenticated encryption `ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-AEAD128")` (and similarly `decrypt`):

    - `Ascon-AEAD128`
  
  * Hashing algorithms `ascon_hash(message, variant="Ascon-Hash256", hashlength=32)` including 3 hash function variants with slightly different interfaces:

    - `Ascon-Hash256` with fixed 256-bit output
    - `Ascon-XOF128` with variable output lengths (specified with `hashlength`)
    - `Ascon-CXOF128` with variable output lengths (`hashlength`) and supporting a customization string as an additional input
  

Older Algorithm Variants
------------------------

Older versions of `ascon.py` implement Ascon v1.2 as submitted to the NIST LWC competition and published in the Journal of Cryptology, as well as additional functionality for message authentication. These versions can be found in commit (TODO), including

  * Authenticated encryption:

    - `Ascon-128`
    - `Ascon-128a`
    - `Ascon-80pq`
  
  * Hashing algorithms:

    - `Ascon-Hash`
    - `Ascon-Hasha`
    - `Ascon-Xof`
    - `Ascon-Xofa`
  
  * Message authentication codes `ascon_mac(key, message, variant="Ascon-Mac", taglength=16)` for 5 MAC variants (from https://eprint.iacr.org/2021/1574, not part of the LWC proposal) with fixed 128-bit (`Mac`) or variable (`Prf`) output lengths, including a variant for short messages of up to 128 bits (`PrfShort`).

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

    Call with the name of the target algorithm (see above) as first parameter, default is `Ascon-AEAD128`:

    ```sh
    python3 genkat.py Ascon-AEAD128

    ```

    Results are written to 

    - `LWC_AEAD_KAT_{klenbits}_{nlenbits}.txt` for authenticated encryption,
    - `LWC_HASH_KAT_{hlenbits}.txt` for hashing,
    - `LWC_XOF_KAT_{hlenbits}.txt` for extendable-output hashing (custom KAT configuration),
    - `LWC_CXOF_KAT_{hlenbits}.txt` for customizable-input extendable-output hashing (custom KAT configuration), and
    - `LWC_AUTH_KAT_128_128.txt` for various message authentication codes.

    Additionally, a JSON version of the same data is written to the corresponding `.json` files.
    Note that this may overwrite KATs for other variants which share the same parameters (in the `AUTH` case).


  * `writer.py`:
    Helper code for `genkat.py` that specifies the text and JSON encoding.

