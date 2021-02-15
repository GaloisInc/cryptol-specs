This repository contains a wide range of cryptographic algorithms
specified in the Cryptol language. Our long-term goal is for these
specifications to be literate files that share as much common code as
possible, and to allow implementation correctness proofs to depend on
one shared, canonical description of the algorithms they target. As a
starting point, however, we plan to collect as many specifications as
we can find, as-is, and incrementally improve their presentation and
inter-dependency.

Some of the widely adopted cryptographic algorithms contained in this
repository are listed below.

|                           | Primitive         | Synthesis   | Verification |
| ------------------------- | ----------------- | ----------- | ------------ |
| **Block Cipher**          | [AES](Primitive/Symmetric/Cipher/Block/AES.cry)| | |
|                           | [Triple DES](Primitive/Symmetric/Cipher/Block/TripleDES.cry)| | |
| **Stream Cipher**         | [ChaCha20-Poly1305](Primitive/Symmetric/Cipher/Authenticated/ChaChaPolyCryptolIETF.md)| | |
| **Message Authentication**| [HMAC](Primitive/Symmetric/MAC/HMAC.cry)| | |
| **Digital Signature**     | [ECDSA](Primitive/Asymmetric/Signature/ecdsa.cry)| | |
|                           | [SPHINCS+](Primitive/Asymmetric/Signature/SphincsPlus.md)| | |
| **Hash**                  | [SHA1](Primitive/Keyless/Hash/SHA1.cry)| | |
|                           | [SHA256](Primitive/Keyless/Hash/SHA256.cry)| | |
|                           | [SHA2, SHA3](Primitive/Keyless/Hash/SHA.cry)| | |
