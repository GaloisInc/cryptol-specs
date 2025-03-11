<!---
 - @copyright Galois, Inc.
 - @author Aaron Tomb
 --->
# HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install Cryptol from the website you can run ```cryptol hkdf.md``` in your terminal and all of the definitions will by typechecked, and the test cases can be run.

All text in this document is directly from this [HKDF RFC](https://tools.ietf.org/html/rfc5869). Cryptol code is by Joey Dodds, Galois Inc. 2018.

## Abstract

This document specifies a simple Hashed Message Authentication Code
(HMAC)-based key derivation function (HKDF), which can be used as a
building block in various protocols and applications.  The key
derivation function (KDF) is intended to support a wide range of
applications and requirements, and is conservative in its use of
cryptographic hash functions.

## 1.  Introduction
A key derivation function (KDF) is a basic and essential component of
cryptographic systems.  Its goal is to take some source of initial
keying material and derive from it one or more cryptographically
strong secret keys.

This document specifies a simple HMAC-based [HMAC] KDF, named HKDF,
which can be used as a building block in various protocols and
applications, and is already used in several IETF protocols,
including [IKEv2], [PANA], and [EAP-AKA].  The purpose is to document
this KDF in a general way to facilitate adoption in future protocols
and applications, and to discourage the proliferation of multiple KDF
mechanisms.  It is not intended as a call to change existing
protocols and does not change or update existing specifications using
this KDF.

HKDF follows the "extract-then-expand" paradigm, where the KDF
logically consists of two modules.  The first stage takes the input
keying material and "extracts" from it a fixed-length pseudorandom
key K.  The second stage "expands" the key K into several additional
pseudorandom keys (the output of the KDF).

In many applications, the input keying material is not necessarily
distributed uniformly, and the attacker may have some partial
knowledge about it (for example, a Diffie-Hellman value computed by a
key exchange protocol) or even partial control of it (as in some
entropy-gathering applications).  Thus, the goal of the "extract"
stage is to "concentrate" the possibly dispersed entropy of the input
keying material into a short, but cryptographically strong,
pseudorandom key.  In some applications, the input may already be a
good pseudorandom key; in these cases, the "extract" stage is not
necessary, and the "expand" part can be used alone.

The second stage "expands" the pseudorandom key to the desired
length; the number and lengths of the output keys depend on the
specific cryptographic algorithms for which the keys are needed.

Note that some existing KDF specifications, such as NIST Special
Publication 800-56A [800-56A], NIST Special Publication 800-108
[800-108] and IEEE Standard 1363a-2004 [1363a], either only consider
the second stage (expanding a pseudorandom key), or do not explicitly
differentiate between the "extract" and "expand" stages, often
resulting in design shortcomings.  The goal of this specification is
to accommodate a wide range of KDF requirements while minimizing the
assumptions about the underlying hash function.  The "extract-then-
expand" paradigm supports well this goal (see [HKDF-paper] for more
information about the design rationale).

## 2. HMAC-based Key Derivation Function (HKDF)

```cryptol
module Primitive::Symmetric::KDF::HKDF where
```

### 2.1.  Notation

HMAC-Hash denotes the HMAC function [HMAC] instantiated with hash
function 'Hash'.  HMAC always has two arguments: the first is a key
and the second an input (or message).  (Note that in the extract
step, 'IKM' is used as the HMAC input, not as the HMAC key.)


```cryptol
parameter

    type HashLen : #
    type constraint (fin HashLen)

    // HMAC has limitations on input sizes based on its own
    // limitations and hash limits
    type constraint validHMACSizes KeyLen MsgLen =
      ( fin KeyLen, fin MsgLen
          , 32 >= width MsgLen
          , 64 >= width (8 * KeyLen)
          , 64 >= width (8 * 64 + MsgLen))



    // Hash : {MsgSize} (fin MsgSize) => [MsgSize][8] -> [HashLen][8] The hash will come with the HMAC

    HMAC : {KeyLen, MsgLen} (validHMACSizes KeyLen MsgLen) =>
           [KeyLen][8] -> [MsgLen][8] -> [HashLen][8]
```

### 2.2.  Step 1: Extract

```cryptol
HKDF_Extract : {SaltLen, IKMLen} (validHMACSizes SaltLen IKMLen) => [SaltLen][8] -> [IKMLen][8] -> [HashLen][8]
HKDF_Extract salt IKM = PRK where
```

| Inputs  |                                                                                                           |
|--------:|-----------------------------------------------------------------------------------------------------------|
|  salt   | optional salt value a non-secret random value if not provided, it is set to a string of HashLen zeros.    |
|  IKM    | input keying material                                                                                     |

| Output |                                        |
|-------:|----------------------------------------|
| PRK    | a pseudorandom key (of HashLen octets) |

```cryptol
    PRK = HMAC salt IKM
```

### 2.2.  Step 2: Expand

```cryptol
HKDF_Expand : {PRKLen, InfoLen, L}
              (fin PRKLen, fin InfoLen, fin L
              , PRKLen >= HashLen, 255 * HashLen >= L
              , L >= HashLen + 1
              , validHMACSizes PRKLen (1 + InfoLen + HashLen)) =>
              [PRKLen][8] -> [InfoLen][8] -> [L][8]
HKDF_Expand PRK info = OKM where
```
| Inputs  |                                                                                                           |
|--------:|-----------------------------------------------------------------------------------------------------------|
|  PRK    | a pseudorandom key of at least HashLen octets (usually, the output from the extract step)                 |
|  info   | optional context and application specific information (can be a zero-length string)                       |
|  L      | length of output keying material in octets (<= 255*HashLen)

| Output |                                        |
|-------:|----------------------------------------|
| OKM    |  output keying material (of L octets)  |

```cryptol
    type N   = L /^ HashLen
    (T : [N][HashLen][8]) =
          [(HMAC PRK (info # [0x01]))]
        # [HMAC PRK (t_n # info # [n]) | t_n <- T
                                       | n <- [0x02 ..N]]
    OKM = take (join T)
```

### Appendix A.  Test Vectors

This appendix provides test vectors for SHA-256 and SHA-1 hash
   functions.

See file ```HKDF256Tests.cry```

