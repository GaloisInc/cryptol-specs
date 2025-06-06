This directory includes executable specifications for several hash functions.

| Scheme | [Gold standard](https://github.com/GaloisInc/cryptol-specs/wiki/Reviewing-guidelines)? | Literate |
| --- | --- | --- |
| SHA2 | Yes | No |
| SHA2Internal | | No |
| SHA3 | Yes | No |
| BLAKE (2b and 2s) | | No |
| FNV | | No |
| MD5 | | Yes |
| SHA1 | Yes | No |

## SHA2
There are two versions of SHA2 here, as defined in [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4). The [`SHA2`](/Primitive/Keyless/Hash/SHA2/) directory contains the spec-adherent version and should be used for the vast majority of applications. In addition, the directory contains an FFI implementation of SHA256. This can be used to test algorithms that require many invocations of SHA256 (such as WOTS+), and it has been checked equivalent (but not _proven_ equivalent) to the gold-standard [`SHA256`](/Primitive/Keyless/Hash/SHA2/Instantiations/SHA256.cry) spec.

The [`SHA2Internal`](/Primitive/Keyless/Hash/SHA2Internal/) directory contains an equivalent implementation. It was originally written as part of a proof of correctness for a Java implementation of SHA2. It makes public several internal components of SHA2, like the compression function and the state representation, that are not part of the public interface defined in FIPS 180-4.
These are used in the implementation of several other algorithms in this repo, like [SHACAL](/Primitive/Symmetric/Cipher/Block/SHACAL.cry). We've kept the two instantiations that these dependencies use and [checked equivalence of the two versions](SHA2Internal/Equivalence.cry) but recommend using the spec-adherent version where possible.

## SHA3
The SHA3 executable specification is based on [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202).
The implementation is divided into the main body of the implementation in [`SHA3/Specification.cry`](SHA3/Specification.cry) and a public API for the hash functions [SHA3](SHA3/SHA3.cry). The public APIs for the extendable-output functions (SHAKE) are directly in [the instantiations](SHA3/Instantiations/).

One quirk of the Keccak algorithm underlying SHA3 is that it assumes an unusual bit ordering for the input. In practice, most applications do not want to rearrange inputs to match that bit ordering (indeed, the KATs provided by NIST are not provided with that ordering), so the default `hash` and `xof` functions for the `SHA3` and `SHAKE` algorithms take input and return output in big-endian, or most-significant-bit first, ordering. For applications that have unusual bit-ordering needs, the `sha3`, `shake128`, and `shake256` functions take input and return output in the Keccak bit ordering, and the [KeccakBitOrdering](SHA3/KeccakBitOrdering.cry) module has helper functions to convert between various representations of bits.

## HashInterface
Some applications require an arbitrary hash function. The `HashInterface` provided is instantiated by both the `SHA2` and `SHA3` hashes.

## Other hash functions
This directory also has proof-of-concept versions several other hashes:
- [The BLAKE2 hash functions](https://www.blake2.net/), a fast and secure cryptographic hash function;
- [The FNV hash](https://www.ietf.org/archive/id/draft-eastlake-fnv-21.html), a non-cryptographic hash with a low collision rate;
- [The MD5 hash](https://www.ietf.org/rfc/rfc1321.txt), a historical hash function with a variety of security issues; and
- [SHA1](https://doi.org/10.6028/NIST.FIPS.180-4), a cryptographically broken hash function.
