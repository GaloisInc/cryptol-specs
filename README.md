This repository contains a wide range of cryptographic algorithms
specified in the Cryptol language. Our long-term goal is for these
specifications to be literate files that share as much common code as
possible, and to allow implementation correctness proofs to depend on
one shared, canonical description of the algorithms they target. As a
starting point, however, we plan to collect as many specifications as
we can find, as-is, and incrementally improve their presentation and
inter-dependency.

- [NIST Post-Quantum Cryptography Standardization Selections](#nist-post-quantum-cryptography-standardization-selections)
- [Remarks](#remarks-on-correctness)
- [Contributing](#contributing)


Some of the widely adopted cryptographic algorithms contained in this
repository are listed below.

|                            | Primitive                                                                              | Synthesis | Verification |
|----------------------------|----------------------------------------------------------------------------------------|-----------|--------------|
| **Block Cipher**           | [AES](Primitive/Symmetric/Cipher/Block/AES)                                            |           |              |
|                            | [Triple DES](Primitive/Symmetric/Cipher/Block/TripleDES.md)                            |           |              |
| **Stream Cipher**          | [ChaCha20-Poly1305](Primitive/Symmetric/Cipher/Authenticated/ChaChaPolyCryptolIETF.md) |           |              |
| **Message Authentication** | [HMAC](Primitive/Symmetric/MAC/HMAC.cry)                                               |           |              |
| **Digital Signature**      | [ECDSA](Primitive/Asymmetric/Signature/ECDSA)                                          |           |              |
|                            | [SPHINCS+](Primitive/Asymmetric/Signature/SphincsPlus/)                                |           |              |
|                            | [FALCON](Primitive/Asymmetric/Signature/FALCON/1.2/)                                   |           |              |
|                            | [CRYSTALS Dilithium](Primitive/Asymmetric/Signature/Dilithium/)                        |           |              |
| **Hash**                   | [SHA1](Primitive/Keyless/Hash/SHA1.cry)                                                |           |              |
|                            | [SHA256](Primitive/Keyless/Hash/SHA2/Instantiations/SHA256.cry)                        |           |              |
|                            | [SHA2](Primitive/Keyless/Hash/SHA2/)                                                   |           |              |
|                            | [SHA3](Primitive/Keyless/Hash/SHA3/)                                                   |           |              |
| **Key Encapsulation**      | [ML-KEM (CRYSTALS-Kyber)](Primitive/Asymmetric/KEM/ML_KEM/)                            |           |              |
| **Asymmetric Encryption**  | [RSA](Primitive/Asymmetric/Cipher/RSA.cry)                                             |           |              |

All Cryptol files in this repository are covered by the BSDv3 license. See LICENSE file.

# NIST Post-Quantum Cryptography Standardization Selections
This repo includes executable specifications of several quantum-resistant schemes. These are drawn from the finalists of the [NIST Post-Quantum Cryptography competition](https://csrc.nist.gov/projects/post-quantum-cryptography). In some cases, we have multiple versions of the algorithms from various rounds of the competition, as well as from the initial public draft (IPD) and final specifications produced by NIST.

| Primitive | NIST Name (Original Name)   | Type          | Versions Available |
|-----------|-----------------------------|---------------|--------------------|
| PKE / KEM | ML-KEM (CRYSTALS-Kyber)     | Lattice-based | [Final spec (FIPS-203)](Primitive/Asymmetric/KEM/ML_KEM/) |
| Signature | ML-DSA (CRYSTALS-Dilithium) | Lattice-based | [Final spec (FIPS-204), IPD, Round 2, Round 1](Primitive/Asymmetric/Signature/Dilithium/) |
| Signature | FN-DSA (FALCON)             | Lattice-based | [Round 1.2](Primitive/Asymmetric/Signature/FALCON/1.2/) |
| Signature | SLH-DSA (SPHINCS+)          | Hash-based    | [Round 3.1](Primitive/Asymmetric/Signature/SphincsPlus/) |


## Appreciations
Without the generous help of the authors who were willing to share their work with us, our team would not have been able to create such an effective codebase. We are truly grateful for their support. In particular, we'd like to thank:
- Vadim Lyubashevsky (CRYSTALS Kyber and CRYSTALS Dilithium)
- Andreas Hülsing (SPHINCS+)
- Pierre-Alain Fouque and Thomas Pornin (FALCON)

# Remarks on correctness
The Cryptol specs presented here are written with the objective of being as close as possible to the specs as presented in the official papers so that even someone without cryptographic experience can verify that the Cryptol code meets the spec by reading it "line by line". As a result, the Cryptol code may not be as efficient as other implementations (for example it may implement DFT instead of FFT), yet it is closer to the paper definitions and aims to be functionally equivalent to them.

In addition to "correctness by visual inspection," the executable specs in this repo define provable properties. Some of these are "internal" properties of the specs (e.g. two functions must be each others' inverses). Others define top-level properties of schemes (e.g. in a signature scheme, a signature generated on a message with a valid key will verify). High-level properties are not always provable — some schemes, like ML-KEM and ML-DSA, have correctness properties that hold with overwhelming probability (but not for every possible input) — but can be checked.

Finally, NIST provides known-answer tests (KATs) via [the CAVP program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) that can be used to check that a scheme aligns with the standardized version. We have properties that prove that we satisfy the KATs on the majority of schemes for which they are available (although we typically only include a subset of the available KATs).


# Contributing
You can contribute to this project by submitting issues or bug reports.
