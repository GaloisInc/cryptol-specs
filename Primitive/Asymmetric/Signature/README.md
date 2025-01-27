Digital signatures based on asymmetric primitives.

Most approved signature schemes are randomized. Typically, this requires the signer to generate randomness during the signing process. Cryptol cannot simulate randomness generation, so for randomized signatures, the random value is passed as an argument to the signing function.

| Scheme | Status |
| --- | --- |
| ECDSA  | Gold standard, non-literate spec |
| FN-DSA (FALCON) | Literate spec, but for an outdated version |
| ML-DSA (CRYSTALS-Dilithium) | Gold standard, non-literate spec |
| SLH-DSA (Sphincs+) | Literate spec, but for an outdated version |
| XMSS | Not complete |
| RSA, RSA-PSS | Not gold standard |
