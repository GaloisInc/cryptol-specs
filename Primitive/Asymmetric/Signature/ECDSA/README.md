# Elliptic curve digital signature algorithms

This section contains three indepdendent implementations of ECDSA, each of which uses a different elliptic curve implementation.

The most spec-adherent version includes the following files. `Specification.cry` matches [FIPS-186-5](https://doi.org/10.6028/NIST.FIPS.186-5) as closely as possible; `UnconstrainedSpec.cry` implements the same algorithms but omits some of the top-level domain parameter constraints (e.g. on the size of the curve).
This implementation is instantiated and tested for curve P-256 and SHA256. It relies on the curve implementation in `Common/EC/PrimeField/`.
```
Primitive/Asymmetric/Signature/ECDSA/
+ Specification.cry
+ UnconstrainedSpec.cry
+ Instantiations/
  + ECDSA_P256.cry
+ Tests/
  + ECDSA_P256.cry
```

There is also a first implementation that uses modular arithmetic, which is like a less-spec-adherent version of the previous. It implements its own elliptic curves; it takes a hash digest as a parameter (so it's not parameterized for a specific hash function) and is instantiated for the NIST P-curves. We have an intention to remove this once the spec-adherent version is finalized
```
Primitive/Asymmetric/Signature/ECDSA/
+ Constants.cry
+ ECDSA.cry
+ ECDSA_tests.cry
+ ECDSA_sign_tests.cry
+ p192.cry
+ p224.cry
+ p256.cry
+ p384.cry
+ p521.cry
```

Finally, there is a version formalized from ANSI X9-62 (2005). This uses an implementation of P-384 optimized for SAW proofs against a Java implementation for the curve (see `Common/EC/`) and takes a hash digest as a parameter.
```
Primitive/Asymmetric/Signature/
+ ecdsa.cry
```