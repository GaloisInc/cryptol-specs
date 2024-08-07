# Elliptic curves

Elliptic-curve cryptography uses the structure of elliptic curves over finite fields to solve cryptographic problems. Unlike many algorithms in this repository, elliptic curves do not have a single point of truth specification describing all their potentially useful routines; there are several types of curves that are suitable for use in cryptographic applications and many choices for parameters. The elliptic curve interface in `ECInterface.cry` aims to capture the generic functionality of a curve for use in elliptic-curve cryptography.

There are [many curves that have been proposed](http://safecurves.cr.yp.to/index.html) for use in cryptography. At this time, this repository contains three implementations of the NIST-standardized prime field elliptic curves. These curves are notable because they are the only standardized, non-deprecated curves recommended for use in ECDSA and ECDH, and also because their domain parameters are chosen to allow more optimized implementations of some common curve operations. The specification [SP 800-186](https://doi.org/10.6028/NIST.SP.800-186) sets the domain parameters that define the curve, but does not define concrete routines to implement useful curve operations; these are drawn from various other sources.

The first implementation aims to closely implement the specification and sources for routines. It instantiates the elliptic curve interface.
```
Common/EC/
+ PrimeField/
  + PFEC.cry
  + P192.cry
  + P224.cry
  + P256.cry
  + P384.cry
  + P521.cry
+ Tests/
  + P192.cry
  + P224.cry
  + P256.cry
  + P384.cry
  + P521.cry
```

The second is optimized for SAW proofs against a Java implementation. It has some generic components but is only fully instantiated for the P-384 curve. It has a corresponding ECDSA implementation in `Primitive/Asymmetric/Signature/ecdsa.cry`. It does not instantiate the elliptic curve interface.
```
Common/EC/
+ ec_point_ops.cry
+ p384_ec_mul.cry
+ p384_ec_point_ops.cry
+ p384_field.cry
+ ref_ec_mul.cry
```

The third is standalone. At time of writing, I don't know if it's used for anything. It does not instantiate the elliptic curve interface.
```
Common/EC/
+ EC_P384.cry
```

There is a fourth implementation of the NIST prime field elliptic curves. It lives in `Primitives/Asymmetric/Signature/ECDSA` and is closely entwined with one of the implementations of ECDSA. Many of the routines in this implementation were ported to the more generic `PFEC` implementation above.
