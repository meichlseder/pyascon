Python implementation of Ascon
==============================

This is a Python3 implementation of Ascon v1.2, an authenticated cipher and hash function.

https://github.com/meichlseder/pyascon

Ascon
-----

Ascon is a family of [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) (AEAD) and [hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function) algorithms designed to be lightweight and easy to implement, even with added countermeasures against side-channel attacks.
It was designed by a team of cryptographers from Graz University of Technology, Infineon Technologies, and Radboud University: Christoph Dobraunig, Maria Eichlseder, Florian Mendel, and Martin Schläffer.

Ascon has been selected as the primary choice for lightweight authenticated encryption in the final portfolio of the [CAESAR competition (2014–2019)](https://competitions.cr.yp.to/caesar-submissions.html) and is currently competing in the [NIST Lightweight Cryptography competition (2019–)](https://csrc.nist.gov/projects/lightweight-cryptography). 

Find more information, including the specification and more implementations here:

https://ascon.iaik.tugraz.at/


Algorithms
----------

This is a simple reference implementation of Ascon v1.2 as submitted to the NIST LWC competition that includes 

  * Three family members for authenticated encryption:

    - `Ascon-128`
    - `Ascon-128a`
    - `Ascon-80pq`
  
  * Four hashing algorithms: hash function variants with fixed 256-bit (`Hash`) or variable (`Xof`) output lengths 

    - `Ascon-Hash`
    - `Ascon-Hasha`
    - `Ascon-Xof`
    - `Ascon-Xofa`

Files
-----

  * `ascon.py`: 
    Implements the seven family members as well as the underlying permutation:

    - `ascon_encryption()`/`ascon_decrypt()` for authenticated encryption,
    - `ascon_hash()` for hashing,
    - `ascon_permutation` for the underlying permutation.

    By default, prints the results of encrypting and hashing some example strings.

    - `debug = True|False`: Set this variable to print the intermediate state after each phase of the encryption/hashing process.
    - `debugpermutation = True|False`: Set this variable to print the intermediate state after each step of the permutation's round function.


  * `genkat.py`:
    Produces result files for the Known Answer Tests (KATs) defined for the [NIST LWC competition](https://csrc.nist.gov/projects/lightweight-cryptography) ([call for algorithms](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/final-lwc-submission-requirements-august2018.pdf), [test vector generation code](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/TestVectorGen.zip)).

    Call with the name of the target algorithm (see above) as first parameter, default is `Ascon-128`.

    Results are written to 

    - `LWC_AEAD_KAT_{klenbits}_{nlenbits}.txt` for authenticated encryption,
    - `LWC_HASH_KAT_{hlenbits}.txt` for hashing.

