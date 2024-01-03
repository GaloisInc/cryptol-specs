# FIPS 46-3: TRIPLE DATA ENCRYPTION STANDARD

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install
Cryptol from the website you can run ```cryptol TripleDES.md``` in your terminal and all of the
definitions will be typecheck, and the test cases can be run.

All text in this document is directly from the
[Data Encryption Standard](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf).

```cryptol
module Primitive::Symmetric::Cipher::Block::TripleDES where

import Primitive::Symmetric::Cipher::Block::DES (DES)

E = DES.encrypt
D = DES.decrypt
```

## TRIPLE DATA ENCRYPTION ALGORITHM

Let *E<sub>K</sub>(I)* and *D<sub>K</sub>(I)* represents the DES encryption and decryption of *I*
using DES key *K* respectively. Each TDEA encryption/decryption operation (as specified in ANSI
X9.52) is a compound operation of DES encryption and decryption operations. The following operations
are used:

1. TDEA encryption operation: the transformation of a 64-bit block *I* into a 64-bit block *O* that
is defined as follows:

```cryptol
encrypt : [3][64] -> [64] -> [64]
encrypt [K1, K2, K3] I = O
    where
        O = E K3 (D K2 (E K1 I))

// Maintain backwards compatibility
blockEncrypt : ([64], [64], [64], [64]) -> [64]
blockEncrypt (k1, k2, k3, data) = encrypt [k1, k2, k3] data
```

2. TDEA decryption operation: the transformation of a 64-bit block *I* into a 64-bit block *O* that
is defined as follows:

```cryptol
decrypt : [3][64] -> [64] -> [64]
decrypt [K1, K2, K3] I = O
    where
        O = D K1 (E K2 (D K3 I))
```

The standard specifies the following keying options for bundle *(K<sub>1</sub>, K<sub>2</sub>,
K<sub>3</sub>)*

1. Keying Option 1: *K<sub>1</sub>*, *K<sub>2</sub>*, and *K<sub>3</sub>* are independent keys;

2. Keying Option 2: *K<sub>1</sub>* and *K<sub>2</sub>* are independent keys and
*K<sub>3</sub> = K<sub>1</sub>*;

3. Keying Option 3: *K<sub>1</sub> = K<sub>2</sub> = K<sub>3</sub>*.

A TDEA mode of operation is backward compatible with its single DES counterpart if, with compatible
keying options for TDEA operations,

1. an encrypted plaintext computed using a single DES mode of operation can be decrypted correctly
be a corresponding TDEA mode of operation; and

2. an encrypted plaintext computed using a TDEA mode of operation can be decrypted correctly by a
corresponding single DES mode of operation.

When using Keying Option 3 (*K<sub>1</sub> = K<sub>2</sub> = K<sub>3</sub>*), TECB, TCBC, TCFB and
TOFB modes are backward compatible with single DES modes of operation ECB, CBC, CFB, OFB
respectively.

The diagram in Appendix 2 illustrates TDEA encryption and TDEA decryption.

## APPENDIX 2: TRIPLE DES BLOCK DIAGRAM (ECB Mode)

**TDEA Encryption Operation:**

*I -> DES E<sub>K1</sub> -> DES D<sub>K2</sub> -> DES E<sub>K2</sub> -> O*

**TDEA Decryption Operation:**

*I -> DES D<sub>K3</sub> -> DES E<sub>K2</sub> -> DES D<sub>K1</sub> -> O*

## Test Vectors

### 2-Key Tests

The following test vectors are pulled from
[Project NESSIE](https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/Triple-Des-2-Key-128-64.unverified.test-vectors).

```cryptol
property test_twokey = encrypt k0' pt0 == ct0
                    /\ encrypt k1' pt1 == ct1
                    /\ encrypt k2' pt2 == ct2
    where
        k0  = 0x80000000000000000000000000000000
        k0' = [take`{64} k0, drop`{64} k0, take`{64} k0]
        pt0 = 0x0000000000000000
        ct0 = 0xFAFD5084374FCE34
        k1  = 0x40000000000000000000000000000000
        k1' = [take`{64} k1, drop`{64} k1, take`{64} k1]
        pt1 = 0x0000000000000000
        ct1 = 0x60CC37B7B537A1DC
        k2  = 0x20000000000000000000000000000000
        k2' = [take`{64} k2, drop`{64} k2, take`{64} k2]
        pt2 = 0x0000000000000000
        ct2 = 0xBE3E7304FE92C2BC
```
