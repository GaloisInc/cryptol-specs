This directory includes executable specifications for several hash functions.

| Scheme | [Gold standard](https://github.com/GaloisInc/cryptol-specs/wiki/Reviewing-guidelines)? | Literate |
| --- | --- | --- |
| SHA2 | Yes | No |
| SHA2Internal | | No |
| SHA3 | Yes | No |
| BLAKE (2b and 2s) | | No |
| FNV | | No |
| MD5 | | Yes |
| SHA1 |  | No |

## SHA2
There are two versions of SHA2 here, as defined in [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4). The [`SHA2`](/Primitive/Keyless/Hash/SHA2/) directory contains the spec-adherent version and should be used for the vast majority of applications.

The [`SHA2Internal`](/Primitive/Keyless/Hash/SHA2Internal/) directory contains an equivalent implementation. It was originally written as part of a proof of correctness for a Java implementation of SHA2. It makes public several internal components of SHA2, like the compression function and the state representation, that are not part of the public interface defined in FIPS 180-4.
These are used in the implementation of several other algorithms in this repo, like [HMAC](/Primitive/Keyless/Hash/HMAC.cry) and [SHACAL](/Primitive/Symmetric/Cipher/Block/SHACAL.cry). We've kept the two instantiations that these dependencies use and [checked equivalence of the two versions](SHA2Internal/Equivalence.cry) but recommend using the spec-adherent version where possible.

## SHA3
The SHA3 specification includes one internal algorithm, known as [Keccak](Keccak.cry), and two families of public interfaces: the hash functions [SHA3](SHA3/) and the extendable-output functions [SHAKE](SHAKE/).

One quirk of the Keccak algorithm is that it assumes a particularly unusual bit ordering for the input. In practice, most applications do not want to rearrange inputs to match that bit ordering (indeed, the KATs provided by NIST are not provided with that ordering), so the default `hash` and `xof` functions for the `SHA3` and `SHAKE` algorithms take input in big-endian, or most-significant-bit first, ordering. For applications that have unusual bit-ordering needs, the [KeccakBitOrdering](KeccakBitOrdering.cry) module has helper functions to convert between various representations of bits.

## HashInterface
Some applications require an arbitrary hash function. The `HashInterface` provided is instantiated by both the `SHA2` and `SHA3` hashes.
