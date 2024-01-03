# The LED Block Cipher

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install
Cryptol from the website you can run ```cryptol LED.md``` in your terminal and all of the
definitions will be typecheck, and the test cases can be run.

All text in this document is directly from the
[LED Specification](https://eprint.iacr.org/2012/600.pdf).

```cryptol
module Primitive::Symmetric::Cipher::Block::LED where

import Common::GF24 (gf24VectorMult)
```

## 2 Design approach and specifications

Like so much in today's symmetric cryptography, an AES-like design appears to be the ideal starting
point for a clean and secure design. The design of LED will inevitably have many parallels with this
established approach, and features such as `Sboxes`, `ShiftRows`, and (a variant of) `MixColumns`
will all take their familiar roles.

For the key schedule we chose to do-away with the "schedule"; instead the user-provided key is used
repeatedly *as is*. As well as giving obvious advantages in hardware implementation, it allows for
simple proofs to be made for the security of the scheme even in the most challenging attack model of
related keys. At first sight the re-use of the encryption key without variation appears dangerous,
certainly to those familiar with slide attacks and some of their advanced variants. But such a
simple key schedule is not without precedent though the treatment here is more complete than
previously.

The `LED` cipher is described in Section 2.1. It is a 64-bit block cipher with two primary instances
taking 64- and 128-bit keys. The cipher state is conceptually arranged in a (4 x 4) grid where each
nibble represents an element from GF(2^4) with the underlying polynomial for field multiplication
given by `X^4 + X + 1`.

```cryptol
type BlockSize = 64
type Nibble = [4]
type State = [4][4]Nibble
type SubKey = [16][4]
```

`Sboxes`. LED cipher re-uses the PRESENT Sbox which has been adopted in many lightweight
cryptographic algorithms. The actions of this box in hexadecimal notation is given by the following
table.

| | | | | | | | | | | | | | | | | |
| ---- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| x    | 0x0 | 0x1 | 0x2 | 0x3 | 0x4 | 0x5 | 0x6 | 0x7 | 0x8 | 0x9 | 0xA | 0xB | 0xC | 0xD | 0xE | 0xF |
| S[x] | 0xC | 0x5 | 0x6 | 0xB | 0x9 | 0x0 | 0xA | 0xD | 0x3 | 0xE | 0xF | 0x8 | 0x4 | 0x7 | 0x1 | 0x2 |

```cryptol
Sbox : [16][4]
Sbox = [ 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 ]

// Inverse of Sbox; Required for decryption.
Sbox' : [16][4]
Sbox' = [ 0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA]
```

`MixColumnSerial`. We re-use the tactic adopted in [23] to define an MDS matrix for linear diffusion
that is suitable for compact serial implementation. The `MixColumnSerial` layer can be viewed as
four applications of a hardware-friendly matrix *A* with the net result being equivalent to using
the MDS matrix *M* where

```example
        [ 0 1 0 0 ] ^ 4  [ 4 1 2 2 ]
(A)^4 = [ 0 0 1 0 ]    = [ 8 6 5 6 ] = M
        [ 0 0 0 1 ]      [ B E A 9 ]
        [ 4 1 2 2 ]      [ 2 2 F B ]
```

```cryptol
M : [4][4][4]
M = [ [0x4, 0x1, 0x2, 0x2]
    , [0x8, 0x6, 0x5, 0x6]
    , [0xB, 0xE, 0xA, 0x9]
    , [0x2, 0x2, 0xF, 0xB]]

// Required for decryption
M' : [4][4][4]
M' = [ [0xC, 0xC, 0xD, 0x4]
     , [0x3, 0x8, 0x4, 0x5]
     , [0x7, 0x6, 0x2, 0xE]
     , [0xD, 0x9, 0x9, 0xD]]
```

The basic component of LED will be a sequence of four identical rounds used without the addition of
any key material. This basic unit, that we later call "step", makes it easy to establish security
bounds for the construction.

### 2.1 Specification of LED

For a 64-bit plaintext *m* the 16 four-bit nibbles `m0||m1||...||m14||m15` are arranged
(conceptually) in a square array:

```example
[  m0,  m1,  m2,  m3
,  m4,  m5,  m6,  m7
,  m8,  m9, m10, m11
, m12, m13, m14, m15 ]
```

This is the initial value of the cipher STATE and note that the state is loaded row-wise rather than
in the column-wise fashion we have come to expect from the AES; this is a more hardware-friendly
choice, as pointed out in [38].

```cryptol
initialState : [64] -> [4][4][4]
initialState m = groupBy`{4} m'
    where
        m' = groupBy`{4} m
```

The key is viewed nibble-wise and we denote *k0, k1, ..., kl* the *l* nibbles of the key. Then the
*i*-th subkey *SK^i*, also arranged (conceptually) in a square way:

```example
[  sk0,  sk1,  sk2,  sk3
,  sk4,  sk5,  sk6,  sk7
,  sk8,  sk9, sk10, sk11
, sk12, sk13, sk14, sk15 ]
```

is simply obtained by setting *sk^i_j = k_(j + i*16 mod l). Note that for a 64-bit key *K*, all
subkeys are equal to *K*, while for a 128-bit key *K*, the subkeys are alternatively equal to the
left part *K1* and the right part *K2* of *K*.

```cryptol
subKeys : {s, l} (l >= 16, 32 >= l, s >= 8, 12 >= s)
       => [4*l] -> [s+1]SubKey
subKeys K = sks
    where
        ks = groupBy`{4} K
        sks = [ [ks@((j + i*16) % `l) | j <- [0..15]] | i <- [0..s] ]

// all subkeys for the 64-bit key case
test_subKey64 : [64] -> Bit
property test_subKey64 key = and [ sk == key' | sk <- sks ]
    where
        sks  = subKeys`{8} key
        key' = groupBy`{4} key

// the two first subkeys for the 80-bit key case
test_subKey80 : [80] -> Bit
property test_subKey80 key = sk@0 == key'@@[0..15]
                          /\ sk@1 == (key'@@[16..19] # key'@@[0..11])
    where
        sk = subKeys`{12} key
        key' = groupBy`{4} key

// all alternating subkeys for the 128-bit key case
test_subKey128 : [128] -> Bit
property test_subKey128 key = and [ sk == k | sk <- sks | k <- ks' ]
    where
        type s = 12
        sks = subKeys`{s} key
        ks  = split (groupBy`{4} key) : [2]SubKey
        ks' = join (repeat ks)
```

The operation `addRoundKey(STATE, SK^i)` combines nibbles of subkey *SK^i* with the state,
respecting array positioning, using bitwise exclusive-or. Encryption is described using
`addRoundKey(STATE, SK^i)` and a second operation, `step(STATE)`. This is illustrated in Figure 1.
The number of steps *s* during encryption depends on the key size. For 64-bit key, *s = 8*. For
bigger key sizes up to 128 bits, *s = 12*.

```cryptol
round : {n} (n >= 64, 128 >= n)
     => State -> SubKey -> [8] -> State
round state SKi i = state''
    where
        state' = addRoundKey state SKi
        state'' = step`{n} state' i

// Required for decryption
round' : {n} (n >= 64, 128 >= n)
      => State -> SubKey -> [8] -> State
round' state SKi i = state''
    where
        state'  = step'`{n} state i
        state'' = addRoundKey state' SKi

property roundInverts st sk i = i < 12 ==> round'`{64}  (round`{64}  st sk i) sk i == st
                                        /\ round'`{128} (round`{128} st sk i) sk i == st

addRoundKey : State -> SubKey-> State
addRoundKey state SKi = state ^ SKi'
    where
        SKi' = groupBy`{4} SKi

encrypt : {s, l} (l >= 16, 32 >= l, s >= 8, 12 >= s)
       => [4*l] -> [64] -> [64]
encrypt key pt = join (join stateS)
    where
        state0 = initialState pt
        ks = subKeys`{s} key
        states = [state0] # [ round`{4*l} state (ks@i) i
                            | state <- states
                            | i <- [0..s-1]
                            ]
        stateS = addRoundKey (states ! 0) (ks@(`s))

// Required for decryption
decrypt : {s, l} (l >= 16, 32 >= l, s >= 8, 12 >= s)
       => [4*l] -> [64] -> [64]
decrypt key ct = join (join (states ! 0))
    where
        state' = initialState ct
        ks = subKeys`{s} key
        stateF = addRoundKey state' (ks@(`s))
        states = [stateF] # [round'`{4*l} state (ks@i) i
                            | state <- states
                            | i <- (reverse [0..s-1])
                            ]

encryptDecryptInverts64 : [64] -> [64] -> Bit
property encryptDecryptInverts64 key pt = decrypt`{8} key (encrypt`{8} key pt) == pt

// Encrypt 64 bit key
ledEncrypt64 : ([64], [64]) -> [64]
ledEncrypt64 (key, pt) = encrypt`{8} key pt

// Encrypt 128 bit key
ledEncrypt128 : ([128], [64]) -> [64]
ledEncrypt128 (key, pt) = encrypt`{12} key pt

```

The operation `step(STATE)` consists of four rounds of encryption of the cipher state. Each of these
four rounds uses, in sequence, the operations `AddConstants`, `SubCells`, `ShiftRows`, and
`MixColumnsSerial` as illustrated in Figure 2.

```cryptol
step : {n} (n >= 64, 128 >= n)
    => State -> [8] -> State
step state i = state3
    where
        state0 = step1`{n} state (4*i)
        state1 = step1`{n} state0 (4*i+1)
        state2 = step1`{n} state1 (4*i+2)
        state3 = step1`{n} state2 (4*i+3)

// Required for decryption
step' : {n} (n >= 64, 128 >= n)
     => State -> [8] -> State
step' state i = state0
    where
        state3 = step1'`{n} state  (4*i+3)
        state2 = step1'`{n} state3 (4*i+2)
        state1 = step1'`{n} state2 (4*i+1)
        state0 = step1'`{n} state1 (4*i)

property stepInverts state i = i < 12 ==> step'`{64}  (step`{64}  state i) i == state
                                       /\ step'`{128} (step`{128} state i) i == state

step1 : {n} (n >= 64, 128 >= n)
    => State -> [8] -> State
step1 state i = state4
    where
        state1 = AddConstants state `n (rcs@i)
        state2 = SubCells state1
        state3 = ShiftRow state2
        state4 = MixColumnsSerial state3

// Required for decryption
step1' : {n} (n >= 64, 128 >= n)
     => State -> [8] -> State
step1' state i = state0
    where
        state3 = MixColumnsSerial' state
        state2 = ShiftRow' state3
        state1 = SubCells' state2
        state0 = AddConstants state1 `n (rcs@i)

property step1Inverts state i = i < 48 ==> step1'`{64}  (step1`{64}  state i) i == state
                                        /\ step1'`{128} (step1`{128} state i) i == state
```

`AddConstants`. A round constant is defined as follows. At each round, six bits (rc5, rc4, rc3, rc3,
rc1, rc0) are shifted one position to the left with the new value to rc0 being computed as
`rc5 ⊕ rc4 ⊕ 1`. The six bits are initialized to zero, and updated *before* use in a given round.
We also denote (ks7, ks6, ...ks0) the 8 bits representing the key size in bits, with ks7 being the
MSB. The constant, when used in a given round, is arranged into an array as follows:

```example
[ 0⊕(ks7||ks6||ks5||ks4) (rc5||rc4||rc3) 0 0
, 1⊕(ks7||ks6||ks5||ks4) (rc2||rc1||rc0) 0 0
, 2⊕(ks3||ks2||ks1||ks0) (rc5||rc4||rc3) 0 0
, 3⊕(ks3||ks2||ks1||ks0) (rc2||rc1||rc0) 0 0
]
```

The round constants are combined with the state, respecting array positioning, using bitwise
exclusive-or. The values of the (rc5, rc4, rc3, rc2, rc1, rc0) constants for each round are given in
the Appendix.

```cryptol
AddConstants : State -> [8] -> [6] -> State
AddConstants state ks rc = state ^ cs
    where
        [ks7, ks6, ks5, ks4, ks3, ks2, ks1, ks0] = split ks
        [rc5, rc4, rc3, rc2, rc1, rc0] = split rc
        cs = [ [ 0 ^ (ks7 # ks6 # ks5 # ks4), (0 # rc5 # rc4 # rc3), 0, 0]
             , [ 1 ^ (ks7 # ks6 # ks5 # ks4), (0 # rc2 # rc1 # rc0), 0, 0]
             , [ 2 ^ (ks3 # ks2 # ks1 # ks0), (0 # rc5 # rc4 # rc3), 0, 0]
             , [ 3 ^ (ks3 # ks2 # ks1 # ks0), (0 # rc2 # rc1 # rc0), 0, 0]
             ]

// Inverse required for decryption and backwards compatibility
property AddConstantsInverts state ks rc = AddConstants (AddConstants state ks rc) ks rc == state
```

`SubCells`. Each nibble in the array STATE is replaced by the nibble generated after using the
PRESENT Sbox.

```cryptol
SubCells : State -> State
SubCells state = state'
    where
        state' = [ [ Sbox@b | b <- row ] | row <- state ]

// Required for LED decryption
SubCells' : State -> State
SubCells' state = state'
    where
        state' = [ [ Sbox'@b | b <- row ] | row <- state ]

property SubCellsInverts state = SubCells' (SubCells state) == state
```

`ShiftRow`. Row *i* of the array STATE is rotated *i* cell positions to the left, for *i* = 0,1,2,3

```cryptol
ShiftRow : State -> State
ShiftRow state = state'
    where
        state' = [ row <<< i | i <- [0,1,2,3] | row <- state ]

// Required for LED decryption
ShiftRow' : State -> State
ShiftRow' state = state'
    where
        state' = [ row >>> i | i <- [0,1,2,3] | row <- state ]

property ShiftRowInverts state = ShiftRow' (ShiftRow state) == state
```

`MixColumnsSerial`. Each column of the array STATE is viewed as a column vector and replaced by the
column vector that results after post-multiplying the vector by the matrix *M* (see earlier
description in this section).

```cryptol
MixColumnsSerial : State -> State
MixColumnsSerial state = transpose [ gf24VectorMult row M
                                   | row <- state'
                                   ]
    where
        state' = transpose state

// Required for decryption
MixColumnsSerial' : State -> State
MixColumnsSerial' state = transpose [ gf24VectorMult row M'
                                    | row <- state'
                                    ]
    where
        state' = transpose state

property MixColumnsSerialInverts state = MixColumnsSerial' (MixColumnsSerial state) == state
```

The final value of the STATE provides the ciphertext with nibbles of the "array" being unpacked in
the obvious way. Test vectors for LED are provided in the Appendix.

## Appendix

`Round constants`. The generating methods of the round constants have been described in Section 2.1.
Below are the list of (rc5, rc4, rc3, rc2, rc1, rc0) encoded to byte values for each round, with rc0
being the least significant bit.

| Rounds | Constants |
| --- | --- |
|  1-24 | 01,03,07,0F,1F,3E,3D,3B,37,2F,1E,3C,39,33,27,0E,1D,3A,35,2B,16,2C,18,30 |
| 25-48 | 21,02,05,0B,17,2E,1C,38,31,23,06,0D,1B,36,2D,1A,34,29,12,24,08,11,22,04 |

```cryptol
rcs : [48][6]
rcs = map drop [ 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E
               , 0x3D, 0x3B, 0x37, 0x2F, 0x1E, 0x3C
               , 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A
               , 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30
               , 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E
               , 0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D
               , 0x1B, 0x36, 0x2D, 0x1A, 0x34, 0x29
               , 0x12, 0x24, 0x08, 0x11, 0x22, 0x04
               ] : [48][6]
```

`Test vectors`. Test vectors for LED with 64-bit and 128-bit key arrays are given below. More test
vectors are provided at https://sites.google.com/site/ledblockcipher/.

```cryptol
property led64_1 = ledEncrypt64 (key, pt) == ct
    where
        pt  = 0x0000000000000000
        key = 0x0000000000000000
        ct  = 0x39C2401003A0C798

property led64_2 = ledEncrypt64 (key, pt) == ct
    where
        pt  = 0x0123456789ABCDEF
        key = 0x0123456789ABCDEF
        ct  = 0xA003551E3893FC58

property led128_1 = ledEncrypt128 (key, pt) == ct
    where
        pt  = 0x0000000000000000
        key = 0x00000000000000000000000000000000
        ct  = 0x3DECB2A0850CDBA1

property led128_2 = ledEncrypt128 (key, pt) == ct
    where
        pt  = 0x0123456789ABCDEF
        key = 0x0123456789ABCDEF0123456789ABCDEF
        ct  = 0xD6B824587F014FC2
```

## Backwards Compatibility

The following functionality has been included to maintain backwards compatibility.

```cryptol
// Helper to run the experiments

ledEncrypt64' : ([64], [64]) -> [64]
ledEncrypt64' (key, ct) = decrypt`{8} key ct

ledEncrypt128' : ([128], [64]) -> [64]
ledEncrypt128' (key, ct) = decrypt`{12} key ct

property encryptDecrypt64 key pt = ledEncrypt64' (key, ct) == pt
    where
        ct = ledEncrypt64 (key, pt)

property encryptDecrypt128 key pt = ledEncrypt128' (key, ct) == pt
    where
        ct = ledEncrypt128 (key, pt)
```
