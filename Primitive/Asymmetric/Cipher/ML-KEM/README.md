# Cryptol Specifications for ML-KEM (FIPS 203)

## Description
This directory contains the Cryptol specifications for the ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) as outlined in FIPS 203. These specifications have been carefully developed to closely resemble the standard. While the original LaTeX files from the standard were not available during this development, the final Cryptol code aligns well with the specifications. For detailed information on FIPS 203, visit:
https://csrc.nist.gov/pubs/fips/203/ipd

## Requirements

- Cryptol Version: 2.12 or later
- Environment variable CRYPTOLPATH should contain the path to the Cryptol specs repo.

## References
- FIPS 203: https://csrc.nist.gov/pubs/fips/203/ipd
- Known Answer Tests (KATs) for ML-KEM: https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM
- Intermediate KATs by NIST: https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files

## Additional Notes
- Included in this directory is an `.awk` file designated to generate a script. This facilicates alignment of our specs with both the published KATs and the intermediate KATs available on the NIST website.
- The Cryptol specifications have been tested to ensure correctness. All properties related to correctness of the algorithms (such as decryption of encryption equaling identity and decoding of encoding equaling identity) pass successfully.