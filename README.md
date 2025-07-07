This repository contains a wide range of cryptographic algorithms
specified in the Cryptol language. Our long-term goal is for these
specifications to be literate files that share as much common code as
possible, and to allow implementation correctness proofs to depend on
one shared, canonical description of the algorithms they target. As a
starting point, however, we plan to collect as many specifications as
we can find, as-is, and incrementally improve their presentation and
inter-dependency.

All Cryptol files in this repository are covered by [the 3-clause BSD license](LICENSE).

# Collections of Algorithms
This repo has executable specifications for many cryptographic algorithms.

## CNSA 2.0
This repo includes all the general purpose, quantum-resistant algorithms approved in [the Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) and one of the application-specific algorithms.
The repo includes most of the approved parameter sets for each of the above algorithms; this table only links to the parameters specifically included in CNSA 2.0.

| Primitive | Specification | Parameters |
| --- | --- | --- |
| Block cipher | [AES](Primitive/Symmetric/Cipher/Block/AES) | [AES256](Primitive/Symmetric/Cipher/Block/AES/Instantiations/AES256.cry) ([AES256-CTR](Primitive/Symmetric/Cipher/Block/Modes/Instantiations/AES256_CTR.cry), [AES256-GCM](Primitive/Symmetric/Cipher/Authenticated/GCM/Instantiations/AES256_GCM.cry)) |
| Key establishment | [ML-KEM](Primitive/Asymmetric/KEM/ML_KEM/) | [ML-KEM-1024](Primitive/Asymmetric/KEM/ML_KEM/Instantiations/ML_KEM1024.cry) |
| Signature | [ML-DSA](Primitive/Asymmetric/Signature/ML_DSA/) | [ML-DSA-87](Primitive/Asymmetric/Signature/ML_DSA/Instantiations/ML_DSA_87.cry) |
| Hashing | [SHA2](Primitive/Keyless/Hash/SHA2/Specification.cry) | [SHA-384](Primitive/Keyless/Hash/SHA2/Instantiations/SHA384.cry), [SHA-512](Primitive/Keyless/Hash/SHA2/Instantiations/SHA512.cry) |
| Hashing | [SHA3](Primitive/Keyless/Hash/SHA3) | [SHA3-384](Primitive/Keyless/Hash/SHA3/Instantiations/SHA3_384.cry), [SHA3-512](Primitive/Keyless/Hash/SHA3/Instantiations/SHA3_512.cry) |

## NIST Post-Quantum Cryptography Standardization Selections
This repo includes several quantum-resistant schemes drawn from the finalists of the [NIST Post-Quantum Cryptography competition](https://csrc.nist.gov/projects/post-quantum-cryptography). Some of these have been updated to the final approved version; others are from earlier rounds of the competition.

| Primitive | NIST Name (Original Name)   | Type          | Versions Available |
|-----------|-----------------------------|---------------|--------------------|
| PKE / KEM | ML-KEM (CRYSTALS-Kyber)     | Lattice-based | [Final spec (FIPS-203)](Primitive/Asymmetric/KEM/ML_KEM/) |
| Signature | ML-DSA (CRYSTALS-Dilithium) | Lattice-based | [Final spec (FIPS-204)](Primitive/Asymmetric/Signature/ML_DSA/) |
| Signature | FN-DSA (FALCON)             | Lattice-based | [Round 1.2](Primitive/Asymmetric/Signature/FALCON/1.2/) |
| Signature | SLH-DSA (SPHINCS+)          | Hash-based    | [Round 3.1](Primitive/Asymmetric/Signature/SphincsPlus/) |

We appreciate the generous help of the authors who were willing to share their work with us, while developing early versions of these executable specifications. We are truly grateful for their support. In particular, we'd like to thank:
- Vadim Lyubashevsky (CRYSTALS Kyber and CRYSTALS Dilithium)
- Andreas Hülsing (SPHINCS+)
- Pierre-Alain Fouque and Thomas Pornin (FALCON)

## Suite B
This repo includes the set of cryptographic algorithms specified in [NSA's Suite B Cryptography](https://en.wikipedia.org/wiki/NSA_Suite_B_Cryptography).

| Primitive | Specification | Parameters |
| --- | --- | --- |
| Block cipher | [AES](Primitive/Symmetric/Cipher/Block/AES) | [AES128-CTR](Primitive/Symmetric/Cipher/Block/Modes/Instantiations/AES128_CTR.cry), [AES128-GCM](Primitive/Symmetric/Cipher/Authenticated/GCM/Instantiations/AES128_GCM.cry), [AES256-CTR](Primitive/Symmetric/Cipher/Block/Modes/Instantiations/AES256_CTR.cry), [AES256-GCM](Primitive/Symmetric/Cipher/Authenticated/GCM/Instantiations/AES256_GCM.cry)|
| Key agreement | [ECDH](Primitive/Asymmetric/KEM/ECDH/) | [ECDH-P256](Primitive/Asymmetric/KEM/ECDH/Instantiations/ECDH_P256.cry), [ECDH-P384](Primitive/Asymmetric/KEM/ECDH/Instantiations/ECDH_P384.cry) |
| Signature | [ECDSA](Primitive/Asymmetric/Signature/ECDSA/) | [ECDSA-P256-SHA256](Primitive/Asymmetric/Signature/ECDSA/Instantiations/ECDSA_P256_SHA256.cry), [ECDSA-P384-SHA384](Primitive/Asymmetric/Signature/ECDSA/Instantiations/ECDSA_P384_SHA384.cry) |
| Hashing | [SHA2](Primitive/Keyless/Hash/SHA2/Specification.cry) | [SHA-256](Primitive/Keyless/Hash/SHA2/Instantiations/SHA256.cry), [SHA-384](Primitive/Keyless/Hash/SHA2/Instantiations/SHA384.cry) |

## Other kinds of algorithms

There are some [ciphers for authenticated encryption](Primitive/Symmetric/Cipher/Authenticated/) that are commonly used but not formally NIST-approved, like [ChaCha20-Poly1305](Primitive/Symmetric/Cipher/Authenticated/ChaChaPolyCryptolIETF.md) and [AES-GCM-SIV](Primitive/Symmetric/Cipher/Authenticated/AES_GCM_SIV.cry). There are also [many block ciphers](Primitive/Symmetric/Cipher/Block/), including some of historical interest (e.g. [Triple DES](Primitive/Symmetric/Cipher/Block/TripleDES.md)), and a smaller collection of [stream ciphers](Primitive/Symmetric/Cipher/Stream/)

There is an implementation of [HMAC](Primitive/Symmetric/MAC/HMAC/Specification.cry) that is used to instantiate [a hash-based key derivation function (HKDF)](Primitive/Symmetric/KDF/).

There are two members of [the BLAKE family of hash functions](Primitive/Keyless/Hash/), as well as several historical hash functions, like [MD5](Primitive/Keyless/Hash/MD5.md) and [SHA1](Primitive/Keyless/Hash/SHA1/Specification.cry), that are not suitable for general use. There's also a version of the standardized [deterministic random bit generator (DRBG)](Primitive/Keyless/Generator/DRBG.cry).

There's a family of RSA-based schemes, including [the basic RSA cipher](Primitive/Asymmetric/Cipher/RSA.cry), [RSA with various encoding schemes](Primitive/Asymmetric/Scheme), and some [RSA-based signature schemes](Primitive/Asymmetric/Signature).




# Remarks on correctness
The Cryptol specs presented here are written with the objective of being as close as possible to the specs as presented in the official papers so that even someone without cryptographic experience can verify that the Cryptol code meets the spec by reading it "line by line". As a result, the Cryptol code may not be as efficient as other implementations (for example it may implement DFT instead of FFT), yet it is closer to the paper definitions and aims to be functionally equivalent to them.

In addition to "correctness by visual inspection," the executable specs in this repo define provable properties. Some of these are "internal" properties of the specs (e.g. two functions must be each others' inverses). Others define top-level properties of schemes (e.g. in a signature scheme, a signature generated on a message with a valid key will verify). High-level properties are not always provable — some schemes, like ML-KEM and ML-DSA, have correctness properties that hold with overwhelming probability (but not for every possible input) — but can be checked.

Finally, NIST provides known-answer tests (KATs) via [the CAVP program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) that can be used to check that a scheme aligns with the standardized version. We have properties that prove that we satisfy the KATs on the majority of schemes for which they are available (although we typically only include a subset of the available KATs).


# Contributing
You can contribute to this project by submitting issues or bug reports. Please see our [gold standard spec criteria](https://github.com/GaloisInc/cryptol-specs/wiki/Reviewing-guidelines) for details on what a good executable specification looks like. At this time, we have not completed a style guide, but we have [an issue](https://github.com/GaloisInc/cryptol-specs/issues/5) that may contain some preliminary guidelines.
