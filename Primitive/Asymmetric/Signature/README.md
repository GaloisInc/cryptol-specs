Digital signatures based on asymmetric primitives.

Most approved signature schemes are randomized. Typically, this requires the signer to generate randomness during the signing process. Cryptol cannot simulate randomness generation, so for randomized signatures, the random value is passed as an argument to the signing function.

| Scheme | Standard | Literate | Up-to-date |
| --- | --- | --- | --- |
| ECDSA  | Gold | No | Yes |
| FN-DSA (FALCON) | | Yes | Outdated (1.2) |
| ML-DSA (CRYSTALS-Dilithium) | Gold | No | Yes |
| SLH-DSA (Sphincs+) |  | Yes | Outdated (3.1) |
| XMSS |  | No | Not complete |
| RSA, RSA-PSS | | No | Not sure |
