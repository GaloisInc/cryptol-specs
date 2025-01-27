This contains an implementation of elliptic curve Diffie-Hellman (ECDH), also known as the ECC-CDH primitive in [NIST SP 800-56A, revision 3](https://doi.org/10.6028/NIST.SP.800-56Ar3).

⚠ Warning ⚠

This primitive is only a small part of the approved key agreement schemes from SP 800-56A!
This executable specification omits many components, including cryptographic elements and the larger key agreement schemes that combine those elements into secure protocols. These missing pieces are _necessary_ for secure key establishment! Use of the `ECC_CDH` primitive in this file does not constitute key agreement!

In particular, the output of this function must not be used as key material; it is a shared secret. It must be passed through an approved key derivation method before it can be used as a key.
