This directory contains the Cryptol specifications for the ML-DSA (Module-Lattice-Based Digital Signature Algorithm) as defined in the specification [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204).

The Cryptol code in this executable specification was developed to closely resemble the standard; it prioritizes readability and obvious correctness over efficiency.

# Requirements

- Cryptol Version: 3.2.0.
- Environment variable CRYPTOLPATH should contain the path to the Cryptol specs repo.

# Testing
The Cryptol specifications have been tested to ensure correctness. All properties related to correctness of the algorithms (such as decryption of encryption equaling identity and decoding of encoding equaling identity) pass successfully. Internal properties and other correctness checks can be run by loading any instantiation of ML-DSA and checking the docstrings (it will take some time to run, but should be less than an hour) in the Cryptol REPL:
```
:load Primitive/Asymmetric/Signature/ML_DSA/Instantiations/ML_DSA_44.cry
:check-docstrings
```

Each instantiation also has a small suite of known-answer tests (KATs) from a trusted source, including
[NIST's ACVP program](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204) and
the [post-quantum-crypto KATs](https://github.com/post-quantum-cryptography/KAT). Individual KATs are annotated
with the amount of time they are expected to take to run.
```
:load Primitive/Asymmetric/Signature/ML_DSA/Tests/ML_DSA_44.cry
:check-docstrings
```

# Previous versions

This repo previously contained several implementations of CRYSTALS-Dilithium from [the NIST Post-Quantum competition](https://csrc.nist.gov/projects/post-quantum-cryptography). This included versions and tests from Round 1, Round 2, and from [the initial public draft of the eventual FIPS-204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf). They were removed in the commit with hash:
> [dd8ebe708b716082dd8c073c238993ef9b62e421](https://github.com/GaloisInc/cryptol-specs/commit/dd8ebe708b716082dd8c073c238993ef9b62e421)
