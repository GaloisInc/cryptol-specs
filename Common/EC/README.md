# Elliptic curves

Elliptic-curve cryptography uses the structure of elliptic curves over finite fields to solve cryptographic problems. Unlike many algorithms in this repository, elliptic curves do not have a single point of truth specification describing all their potentially useful routines; there are several types of curves that are suitable for use in cryptographic applications and many choices for parameters. The elliptic curve interface in `ECInterface.cry` aims to capture the generic functionality of a curve for use in elliptic-curve cryptography.

There are [many curves that have been proposed](http://safecurves.cr.yp.to/index.html) for use in cryptography. At this time, this repository contains one implementation of the NIST-standardized prime field elliptic curves. These curves are notable because they are the only standardized, non-deprecated curves recommended for use in ECDSA and ECDH, and also because their domain parameters are chosen to allow more optimized implementations of some common curve operations. The specification [SP 800-186](https://doi.org/10.6028/NIST.SP.800-186) sets the domain parameters that define the curve, but does not define concrete routines to implement useful curve operations; these are drawn from various other sources.

Structurally, the curve implementation is generic over concrete parameters but with several assumptions that tie it to the NIST curves specifically. This can be found in `PFEC.cry`. Instantiations for specific parameters are in `Instantiations/` and concrete test vectors for each instantiated curve are in `Tests/`. Additional properties of the NIST curves are specified in the generic implementation and can be checked by loading a specific curve and using `:check-docstrings` to evaluate all the properties.

This is one of many, many implementations of the NIST prime field curves that have been written in Cryptol over the years. One grandparent of particular interest is a 2011 curve implementation that was used to verify a Java implementation of ECDSA in combination with [SAWScript](https://github.com/GaloisInc/saw-script/). This implementation no longer lives in this repo, but it can be seen together with the Java code and the SAW scripts used in the full verification toolchain [in the examples directory of the SAWScript repository](https://github.com/GaloisInc/saw-script/tree/master/examples/ecdsa).

This repository also contains an implementation of [Curve25519](https://datatracker.ietf.org/doc/html/rfc7748), a prime field curve proposed by [Daniel Bernstein](https://cr.yp.to/ecdh/curve25519-20060209.pdf). SP 800-186 allows the use of Curve25519 for some uses, and it is widely used as a fully fledged EC primitive when conformance to the NIST standard is not a concern.

Several other implementations of elliptic curves used to live in this repository. If you would like to explore these, they were removed in the commit with hash:
> [9ae493eeb6eb0df0a149b416c5f1ccb6a1de5fc5](https://github.com/GaloisInc/cryptol-specs/commit/9ae493eeb6eb0df0a149b416c5f1ccb6a1de5fc5)

| Scheme | [Gold standard](https://github.com/GaloisInc/cryptol-specs/wiki/Reviewing-guidelines)? | Literate |
| --- | --- | --- |
| P192 | Yes | No |
| P224 | Yes | No |
| P256 | Yes | No |
| P384 | Yes | No |
| P521 | Yes | No |
| Curve25519 | | No |
