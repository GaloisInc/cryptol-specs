# PRINCE - A Low-latency Block Cipher for Pervasive Computing Applications

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install
Cryptol from the website you can run ```cryptol PRINCE.md``` in your terminal and all of the
definitions will be typecheck, and the test cases can be run.

All text in this document is directly from the
[PRINCE Specification](https://eprint.iacr.org/2012/529.pdf).

```cryptol
module Primitive::Symmetric::Cipher::Block::PRINCE where
```

## 2 Cipher Description

PRINCE is a 64-bit block cipher with a 128-bit key.

```cryptol
type PrinceBlock = [64]
type PrinceKey   = [128]
type PrinceKeyPt = [64]
```

The key is split into two parts of 64 bits each,

```example
k = k0||k1
```

and extended to 192 bits by the mapping

```cryptol
keyExtend : PrinceKey -> [3]PrinceKeyPt
keyExtend k = [k0, k0', k1]
    where
        k0' = (k0 >>> 1) ^ (k0 >> 63)
        [k0, k1] = groupBy`{64} k
```

PRINCE is based on the so-called *FX* construction [7,30]: the first two subkeys k0 and k0' are used
as whitening keys, while the key k1 is the 64-bit key for a 12-round block cipher we refer to as
PRINCE_core. We provide test vectors in Appendix A.

```cryptol
PRINCE : PrinceKey -> PrinceBlock -> PrinceBlock
PRINCE k m = m' ^ k0'
    where
        [k0, k0', k1] = keyExtend k
        m' = PRINCE_core k1 (m ^ k0)
```

### Specification of PRINCE_core

The whole encryption process of PRINCE_core is depicted below.

```cryptol
PRINCE_core : PrinceKeyPt -> PrinceBlock -> PrinceBlock
PRINCE_core k1 pt = c6 ^ k1
    where
        c1 = pt ^ k1
        c2 = (RC@0) ^ c1
        cs = [c2] # [ round c k1 i | c <- cs | i <- [1..5] ]
        c3 = S (last cs)
        c4 = M' c3
        c5 = SInv c4
        cs' = [c5] # [ round' c k1 i | c <- cs' | i <- [6..10] ]
        c6 = (RC@11) ^ (last cs')

PRINCE_core' : PrinceKeyPt -> PrinceBlock -> PrinceBlock
PRINCE_core' k1 ct = c1 ^ k1
    where
        c6 = ct ^ k1
        c5 = (RC@11) ^ c6
        cs' = [c5] # [ round c k1 i | c <- cs' | i <- reverse [6..10] ]
        c4 = S (last cs')
        c3 = M' c4
        c2 = SInv c3
        cs = [c2] # [ round' c k1 i | c <- cs | i <- reverse [1..5] ]
        c1 = (RC@0) ^ (last cs)

property PRINCE_coreInverts k1 pt = PRINCE_core' k1 (PRINCE_core k1 pt) == pt

round : PrinceBlock -> PrinceKeyPt -> [8] -> PrinceBlock
round state k1 i = kiAdd stateR k1
    where
        stateS = S state
        stateM = M stateS
        stateR = (RC@i) ^ stateM

round' : PrinceBlock -> PrinceKeyPt -> [8] -> PrinceBlock
round' state k1 i = SInv stateM'
    where
        stateK  = kiAdd state k1
        stateR  = (RC@i) ^ stateK
        stateM' = MInv stateR

property roundInverts state k1 = state == state''
    where
        state' = round state k1 1
        state'' = round' state' k1 1
```

Each round of PRINCE_core consists of a key addition, an Sbox-layer, a linear layer, and the addition
of a round constant.

**k_i-add**. Here the 64-bit state is xor-ed with the 64-bit subkey.

```cryptol
kiAdd : PrinceBlock -> PrinceKeyPt -> PrinceBlock
kiAdd state k1 = state ^ k1
```

**S-Layer**. The cipher uses one 4-bit Sbox. The action of the Sbox in hexadecimal notation is given
by the following table.

|   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
| - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| x | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
| x | B | F | 3 | 2 | A | C | 9 | 1 | 6 | 7 | 8 | 0 | E | 5 | D | 4 |

```cryptol
sbox : [16][4]
sbox = [ 0xb, 0xf, 0x3, 0x2
       , 0xa, 0xc, 0x9, 0x1
       , 0x6, 0x7, 0x8, 0x0
       , 0xe, 0x5, 0xd, 0x4 ]

sbox' : [16][4]
sbox' = [ 0xb, 0x7, 0x3, 0x2
        , 0xf, 0xd, 0x8, 0x9
        , 0xa, 0x6, 0x4, 0x0
        , 0x5, 0xe, 0xc, 0x1 ]

S : PrinceBlock -> PrinceBlock
S m = join s
    where
        m' = groupBy`{4} m
        s = [ sbox@x | x <- m' ]

SInv : PrinceBlock -> PrinceBlock
SInv m = join s
    where
        m' = groupBy`{4} m
        s = [ sbox'@x | x <- m' ]

property SInverts m = SInv (S m) == m
```

**The Matrices: M/M'-layer**. In the M and M' layer the 64-bit state is multiplied with a 64x64
matrix *M* (resp. *M'*) defined in Section 3.3.

```cryptol
Multiply : PrinceBlock -> [4][4][4][4][4] -> PrinceBlock
Multiply input Ms = join (join out)
    where
        input' = split (split input) : [4][4][4]
        out = [ [ MultiplyBlock in ms' | ms' <- ms ] | in <- input' | ms <- Ms ]

MultiplyBlock : [4][4] -> [4][4][4] -> [4]
MultiplyBlock in ms = join out
    where
        in' = transpose in
        out = [ SingleMultiply xx mm | xx <- in' | mm <- ms ]

SingleMultiply : [4] -> [4][4] -> [1]
SingleMultiply xx mm = foldl (^) zero xm'
    where
        xm = [ (groupBy`{1} xx * groupBy`{1} mm0) | mm0 <- mm ]
        xm' = foldl (+) zero xm
```

**RC_i-add**. In the RC_*i* add step a 64-bit round constant is xor-ed with the state. We define the
constants used below (in hex notation)

```cryptol
RC : [12][64]
RC = [ 0x0000000000000000
     , 0x13198a2e03707344
     , 0xa4093822299f31d0
     , 0x082efa98ec4e6c89
     , 0x452821e638d01377
     , 0xbe5466cf34e90c6c
     , 0x7ef84f78fd955cb1
     , 0x85840851f1ac43aa
     , 0xc882d32f25323c54
     , 0x64a51195e0e3610d
     , 0xd3b5a399ca0c2399
     , 0xc0ac29b7c97c50dd
     ]
```

Note that, for all 0 <= i <= 11, `RC_i ⊕ RC_(11-i)` is the constant `α = c0ac29b7c97c50dd`,
`RC_0 = 0` and that RC_i, ..., RC_5 and `α` are derived from the fraction part of `π = 3.141...`.

```cryptol
property note1 = and [ (RC@i) ^ (RC@(11 - i)) == 0xc0ac29b7c97c50dd
                     | i <- [0..11] ]
```

From the fact that the round constants satisfy `RC_i ⊕ RC_(11-i) = α` and that M' is an involution,
we deduce that the core cipher is such that the inverse of PRINCE_core parameterized with `k` is
equal to PRINCE_core parameterize with (`k ⊕ α`). We call this property of PRINCE_core the
`α-reflection property`. It follows that, for any expanded key `(k0||k0'||k1)`,

```cryptol
property aReflection k m = PRINCE_core' k m == PRINCE_core (k ^ a) m
    where
        a = 0xc0ac29b7c97c50dd

encrypt : PrinceKey -> PrinceBlock -> PrinceBlock
encrypt k pt =  ct ^ k0'
    where
        [k0, k0', k1] = keyExtend k
        ct = PRINCE_core k1 (pt ^ k0)

decrypt : PrinceKey -> PrinceBlock -> PrinceBlock
decrypt k ct = pt ^ k0'
    where
        [k0', k0, k1] = keyExtend k
        a  = 0xc0ac29b7c97c50dd
        pt = PRINCE_core (k1 ^ a) (ct ^ k0)

property EncryptDecrypt k pt = decrypt k (encrypt k pt) == pt
```

where `α` is the 64-bit constant `α=c0ac29b7c97c50dd`. Thus, for decryption one only has to do a
very cheap change to the master key and afterwards reused the exact same circuit.

## 3 Design Decisions

### 3.3 The Linear Layer

In the *M* and *M'*-layer the 64-bit state is multiplied with a 64 x 64 matrix *M* (resp. *M'*)
defined below. We have different requirements for the two different linear layers. The *M'*-layer is
only used in the middle round, thus *M'* has to be an involution to ensure the `α`-reflection
property. This requirement does not apply for the *M*-layer used in the round functions. Here we
want to ensure full diffusion after two rounds. To achieve this we combine the *M'*-mapping with an
application of matrix *S R* which behaves like the AES shift rows and permutes the 16 nibbles in
the following way

```example
|0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15| --> |0|5|10|15|4|9|14|3|8|13|2|7|12|1|6|11|
```

```cryptol
SR : [16][4]
SR = [ 0x0, 0x5, 0xa, 0xf
     , 0x4, 0x9, 0xe, 0x3
     , 0x8, 0xd, 0x2, 0x7
     , 0xc, 0x1, 0x6, 0xb
     ]

SR' : [16][4]
SR' = [ 0x0, 0xd, 0xa, 0x7
      , 0x4, 0x1, 0xe, 0xb
      , 0x8, 0x5, 0x2, 0xf
      , 0xc, 0x9, 0x6, 0x3
      ]
```

Thus `M = SR ◦ M'`.

```cryptol
M : PrinceBlock -> PrinceBlock
M input = join shifted
    where
        output  = Multiply input M'Matrix
        output' = groupBy`{4} output
        shifted = [ output'@sr | sr <- SR ]

MInv : PrinceBlock -> PrinceBlock
MInv input = output
    where
        input' = groupBy`{4} input
        shifted = [ input'@sr | sr <- SR' ]
        output  = Multiply (join shifted) M'Matrix
```

Additionally the implementation costs should be minimized, meaning that the number of ones in the
matrices *M'* and *M* should be minimal, while at the same time it should be guaranteed that at
least 16 Sboxes are active in 4 consecutive rounds (cf. Appendix C.1 for details). Thus, trivially
each output bit of an Sbox has to influence 3 Sboxes in the next round and therefore the minimum
number of ones per row and column is 3. Thus we can use the following four 4 x 4 matrices as
building blocks for the *M'*-layer.

```cryptol
m0 : [4][4]
m0 = [ 0b0000
     , 0b0100
     , 0b0010
     , 0b0001
     ]

m1 : [4][4]
m1 = [ 0b1000
     , 0b0000
     , 0b0010
     , 0b0001
     ]

m2 : [4][4]
m2 = [ 0b1000
     , 0b0100
     , 0b0000
     , 0b0001
     ]

m3 : [4][4]
m3 = [ 0b1000
     , 0b0100
     , 0b0010
     , 0b0000
     ]
```

In the next step we generate a 4 x 4 block matrix M^ where each row and column in a permutation of
the four 4 x 4 matrices M0, ..., M3. The row permutations are chosen such that we obtain a symmetric
block matrix. The choice of the building blocks and the symmetric structure ensures that the
resulting 16 x 16 matrix is an involution. We define

```cryptol
M0 : [4][4][4][4]
M0 = [ [ m0, m1, m2, m3 ]
     , [ m1, m2, m3, m0 ]
     , [ m2, m3, m0, m1 ]
     , [ m3, m0, m1, m2 ]
     ]

M0' : [4][4][4][4]
M0' = reverse (M0 <<< 1)

M1 : [4][4][4][4]
M1 = [ [ m1, m2, m3, m0 ]
     , [ m2, m3, m0, m1 ]
     , [ m3, m0, m1, m2 ]
     , [ m0, m1, m2, m3 ]
     ]

M1' : [4][4][4][4]
M1' = reverse (M1 >>> 1)
```

In order to obtain a permutation for the full 64-bit state, we construct a 64 x 64 block diagonal
matrix *M'* with (M0, M1, M1, M0) as diagonal blocks. The matrix *M'* is an involution with 2^32
fixed points, which is average for a randomly chosen involution. The linear layer *M* is not an
involution anymore due to the composition of *M'* and shift rows, which is not an involution.

```cryptol
M'Matrix : [4][4][4][4][4]
M'Matrix = [ M0', M1', M1', M0' ]

M' : PrinceBlock -> PrinceBlock
M' input = Multiply input M'Matrix

property M'Involutes input = M' (M' input) == input
```

### 3.4 The Key Expansion

The 128-bit key `(k0||k1)` is extended to a 192-bit key

## Appendix

### A Test Vectors

| plaintext | k0 | k1 | ciphertext |
| --------- | -- | -- | ---------- |
| 0x0000000000000000 | 0x0000000000000000 | 0x0000000000000000 | 0x818665aa0d02dfda |
| 0xffffffffffffffff | 0x0000000000000000 | 0x0000000000000000 | 0x604ae6ca03c20ada |
| 0x0000000000000000 | 0xffffffffffffffff | 0x0000000000000000 | 0x9fb51935fc3df524 |
| 0x0000000000000000 | 0x0000000000000000 | 0xffffffffffffffff | 0x78a54cbe737bb7ef |
| 0x0123456789abcdef | 0x0000000000000000 | 0xfedcba9876543210 | 0xae25ad3ca8fa9ccf |

```cryptol
property testsPass = test1 /\ test2 /\ test3 /\ test4 /\ test5

test1 = PRINCE (k0 # k1) pt == ct
    where
        pt = 0x0000000000000000
        k0 = 0x0000000000000000
        k1 = 0x0000000000000000
        ct = 0x818665aa0d02dfda

test2 = PRINCE (k0 # k1) pt == ct
    where
        pt = 0xffffffffffffffff
        k0 = 0x0000000000000000
        k1 = 0x0000000000000000
        ct = 0x604ae6ca03c20ada

test3 = PRINCE (k0 # k1) pt == ct
    where
        pt = 0x0000000000000000
        k0 = 0xffffffffffffffff
        k1 = 0x0000000000000000
        ct = 0x9fb51935fc3df524

test4 = PRINCE (k0 # k1) pt == ct
    where
        pt = 0x0000000000000000
        k0 = 0x0000000000000000
        k1 = 0xffffffffffffffff
        ct = 0x78a54cbe737bb7ef

test5 = PRINCE (k0 # k1) pt == ct
    where
        pt = 0x0123456789abcdef
        k0 = 0x0000000000000000
        k1 = 0xfedcba9876543210
        ct = 0xae25ad3ca8fa9ccf
```

### B All Sboxes for the PRINCE-Family Up To Equivalence

In Table 3 we list all Sboxes for the PRINCE-Family, up to affine equivalence. Note that `S0` is
equivalent to the inverse function `F16` and the Sbox of PRINCE defined in Section 2 is equivalent
to S7.

| | |
| -- | -- |
| S0 | 0x0, 0x1, 0x2, 0xD, 0x4, 0x7, 0xF, 0x6, 0x8, 0xC, 0x5, 0x3, 0xA, 0xE, 0xB, 0x9 |
| S1 | 0x0, 0x1, 0x2, 0xD, 0x4, 0x7, 0xF, 0x6, 0x8, 0xC, 0x9, 0xB, 0xA, 0xE, 0x5, 0x3 |
| S2 | 0x0, 0x1, 0x2, 0xD, 0x4, 0x7, 0xF, 0x6, 0x8, 0xC, 0xB, 0x9, 0xA, 0xE, 0x3, 0x5 |
| S3 | 0x0, 0x1, 0x2, 0xD, 0x4, 0x7, 0xF, 0x6, 0x8, 0xC, 0xB, 0x9, 0xA, 0xE, 0x5, 0x3 |
| S4 | 0x0, 0x1, 0x2, 0xD, 0x4, 0x7, 0xF, 0x6, 0x8, 0xC, 0xE, 0xB, 0xA, 0x9, 0x3, 0x5 |
| S5 | 0x0, 0x1, 0x2, 0xD, 0x4, 0x7, 0xF, 0x6, 0x8, 0xE, 0xB, 0xA, 0x5, 0x9, 0xC, 0x3 |
| S6 | 0x0, 0x1, 0x2, 0xD, 0x4, 0x7, 0xF, 0x6, 0x8, 0xE, 0xB, 0xA, 0x9, 0x3, 0xC, 0x5 |
| S7 | 0x0, 0x1, 0x2, 0xD, 0x4, 0x7, 0xF, 0x6, 0x8, 0xE, 0xC, 0x9, 0x5, 0xB, 0xA, 0x3 |

## Backwards Compatibility

The following cryptol methods are defined to maintain backwards compatibility with previous
implementations of the PRINCE algorithms.

```cryptol
type princeBlockSize = 64
type princeKeySize = 128

princeEncrypt : ([princeKeySize], [princeBlockSize]) -> [princeBlockSize]
princeEncrypt (key, pt) = encrypt key pt

princeDecrypt : ([princeKeySize], [princeBlockSize]) -> [princeBlockSize]
princeDecrypt (key, ct) = decrypt key ct

princeEncrypt64 : ([princeBlockSize], [princeBlockSize]) -> [princeBlockSize]
princeEncrypt64 (key, pt) = encrypt (key # zero) pt

princeDecrypt64 : ([princeBlockSize], [princeBlockSize]) -> [princeBlockSize]
princeDecrypt64 (key, ct) = decrypt (key # zero) ct

property princeCorrectPrime key m = princeDecrypt64 (key, princeEncrypt64 (key, m)) == m

princeEncrypt128 : ([princeKeySize], [princeKeySize]) -> [princeKeySize]
princeEncrypt128 (key, pt) = (encrypt key (take`{64} pt)) # zero
```
