# Cryptol Specifications for ML-KEM (FIPS 203)

## Description
This directory contains the Cryptol specifications for the ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) as outlined in the final draft of FIPS 203. Although the original LaTeX files from the standard were not available during this development, the Cryptol code in this executable specification was carefully developed to closely resemble the standard.

The full specification is available at:
https://doi.org/10.6028/NIST.FIPS.203

## Requirements
- Cryptol Version: 3.2.0 or later
- Environment variable CRYPTOLPATH should contain the path to the Cryptol specs repo.

## References
- [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)
- [Known Answer Tests (KATs) for ML-KEM](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM) (produced by a third party).
- [CAVP KATs](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files).

## Additional Notes
- Included in this directory is an `.awk` file designated to generate a script. This facilicates alignment of our specs with both the published KATs and the intermediate KATs available on the NIST website.
- The Cryptol specifications have been tested to ensure correctness. All properties related to correctness of the algorithms (such as decryption of encryption equaling identity and decoding of encoding equaling identity) pass successfully.
