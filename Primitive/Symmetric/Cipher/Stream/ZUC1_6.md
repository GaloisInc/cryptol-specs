# ZUC Algorithm Specification Version 1.6

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install
Cryptol from the website you can run ```cryptol ZUC1_6.md``` in your terminal and all of the
definitions will be typecheck, and the test cases can be run.

All text in this document is directly from the
[ZUC 1.6 specification](https://www.gsma.com/aboutus/wp-content/uploads/2014/12/eea3eia3zucv16.pdf).

## 1 Introduction

ZUC is a word-oriented stream cipher. It takes a 128-bit initial key and a 128-bit initial vector
(IV) as input, and outputs a keystream of 32-bit words (where each 32-bit word is hence called a
*key-word*). This keystream can be used for encryption/decryption.

The execution of ZUC has two stages: initialization stage and working stage. In the first stage, a
key/IV initialization is performed, i.e., the cipher is clocked without producing output (see
section 3.6.1). The second stage is a working stage. In this stage, with every clock pulse, it
produces a 32-bit word of output (see section 3.6.2).

```cryptol
module Primitive::Symmetric::Cipher::Stream::ZUC1_6 where
```

## 2 Notations and conventions

### 2.1 Radix

In this document, integers are represented as decimal numbers unless specified otherwise. We use the
prefix `0x` to indicate hexadecimal numbers, and the prefix `0b` to indicate a number in binary
representation. [Note: the original document uses the subscript `2` to represent binary numbers].

**Example 1:** Integer a can be written in different representations:

```cryptol
property example1 = a == 0x499602D2      // hexadecimal representation
                     /\ a == 0b01001001100101100000001011010010  // binary representation
    where
        a = 1234567890  // decimal representation
```

### 2.2 Bit ordering

In this document, all data variables are presented with the most significant bit(byte) on the left
hand side and the least significant bit(byte) on the right hand side.

**Example 2:**

```cryptol
property example2 = most_sig == take`{1} a  // the leftmost bit
                       /\ least_sig == (a ! 0)     // the rightmost bit
    where
        a = 0b1001001100101100000001011010010
        most_sig = 1
        least_sig = 0
```

### 2.3 Notations

|  |  |
| -----: | ------ |
| `+` | The addition of two integers |
| `ab` | The product of integers a and b |
| `=` | The assignment operator |
| `mod` | The modulo operator of integers |
| `⊕` | The bit-wise exclusive-OR operation of integers |
| `⊞` | The modulo 2^32 addition |
| `a\|\|b` | The concatenation of strings a and b |
| `a_H` | The leftmost 16 bits of integer a |
| `a_L` | The rightmost 16 bits of integer a |
| `a <<<_n k` | The k-bit cyclic shift of the n bit register a to the left |
| `a >> 1` | The 1-bit right shift of integer a |
| `(a1,a2,...an) → (b1,b2,...bn)` | The assignment of the values of ai to bi in parallel |

**Example 3:** For any two strings a and b, the presentation of the string c created by the
concatenation of a and b also follows the rules defined in section 2.2 i.e., the most significant
digits are on the left hand side and the least significant digits are on the right hand side. For
instance,

```cryptol
property example3 = a # b == 0x12345678
    where
        a = 0x1234
        b = 0x5678
```

**Example 4:**

```cryptol
H : {n} (fin n, n >= 16)
 => [n] -> [16]
H a = take`{16} a

L : {n} (fin n, n >= 16)
 => [n] -> [16]
L a = drop`{back=16} a

property example4 = ah == H a
                 /\ al == L a
    where
        a  = 0b1001001100101100000001011010010
        ah = 0b1001001100101100
        al = 0b0000001011010010
```

**Example 5:**

```cryptol
property example5 = a >> 1 == 0b01100100110010110000000101101001
    where
        a = 0b11001001100101100000001011010010
```

**Example 6:** Let a0, a1, ... a15, b0, b1, ... b15 be all integer variables. Then

```cryptol
example6 : [16]Integer -> Bit
property example6 as = and [ as@i == bs@i | i <- [0..15] ]
    where
        bs = as
```

## 3 Algorithm description

### 3.1 General structure of the algorithm

ZUC has three logical layers, see Fig. 1 in the original document. The top layer is a linear
feedback shift register (LFSR) of 16 stages, the middle layer is for bit-reorganization (BR), and
the bottom layer is a nonlinear function *F*.

### 3.2 The linear feedback shift register (LFSR)

The linear feedback shift register (LFSR) has 16 of 31-bit cells (s0,s1,...,s15). Each cell si
(0<=i<=15) is restricted to take values from the following set:
`{1,2,3,...,2^31-1}`

```cryptol
type LFSR = [16][31]
```

The LFSR has 2 modes of operations: the initialization mode and the working mode.

In the initialization mode, the LFSR receives a 31-bit inputs word *u*, which is obtained by
removing the rightmost bit from the 32-bit output W of the nonlinear function *F*, i.e., `u=W>>1`.
More specifically, the initialization mode works as follows:

```cryptol
LFSRWithInitialisationMode : [31] -> LFSR -> LFSR
LFSRWithInitialisationMode u s = s@@[1..15] # [s16]  //step4
    where
        v = step1 s  //step1
        vu = add v u
        s16 = if vu != 0 then vu     //step2
                            else 2^^31 - 1  // step3
```

In the working mode, the LFSR does not receive any input, and it works as follows:

```cryptol
LFSRWithWorkMode : LFSR -> LFSR
LFSRWithWorkMode s = s@@[1..15] # [s16]  // step3
    where
        v = step1 s //step1
        s16 = if v != 0 then v          // step1
                        else 2^^31 - 1  // step2
```

*Informative note:* Since the multiplication of a 31-bit string *s* by 2^i over GF(2^31-1) can be
implemented by a cyclic shift of *s* to the left by *i* bits, only addition modulo 2^31-1 is needed
in step 1 of the above function. More precisely, step 1 of the function LFSRWithInitialisationMode
can be implemented by

```cryptol
step1 : LFSR -> [31]
step1 s = v
    where
        v = foldl add 0 [ ((s@15) <<< 15)
                        , ((s@13) <<< 17)
                        , ((s@10) <<< 21)
                        , ((s@4)  <<< 20)
                        , ((s@0)  <<< 8)
                        , (s@0) ]
```

and the same implementation is needed for step 1 of the function LFSRWithWorkMode.


*Informative note:* For two elements a, b over GF(2^31-1), the computation of `v=a+b mod (2^31-1)`
can be done by (1) compute `v=a+b`; and (2) if the carry bit is 1, then set `v=v+1`. Alternatively,
(and better if the implementation should resist possible timing attacks): (1) compute `w=a+b`,
where w is a 32-bit value; and (2) set `v = (least significant 31 bits of w)+(most significant bit
of w)`.

```cryptol
add : [31] -> [31] -> [31]
add a b = v'
    where
        v : [32]
        v = ((zero # a) + (zero # b))
        v' = if v@0 then (drop v) + 1
                    else drop v

addAlt : [31] -> [31] -> [31]
addAlt a b = v
    where
        w : [32]
        w = (zero # a) + (zero # b)
        v = (drop w) + (zero # [w@0])

property addEquiv a b = add a b == addAlt a b
```

### 3.3 The bit-reorganization

The middle layer of the algorithm is the bit-reorganization. It extracts 128 bits from the cells of
the LFSR and forms 4 of 32-bit words, where the first three words will be used by the nonlinear
function *F* in the bottom layer, and the last word will be involved in producing the keystream,

Let *s0,s2,s5,s7,s9,s11,s14,s15* by 8 cells of LFSR as in section 3.2. The the bit-reorganization
forms 4 of 32-bit words *X0,X1,X2,X3* from the above cells as follows:

```cryptol
Bitreorganization : LFSR -> [4][32]
Bitreorganization s = [X0, X1, X2, X3]
    where
        X0 = H (s@15) # L (s@14)
        X1 = L (s@11) # H (s@9)
        X2 = L (s@7)  # H (s@5)
        X3 = L (s@2)  # H (s@0)
```

*Note*: That *s_i* are 31-bit integers, so *s_iH* means bits 30..15 and not 31..16 of *s_i*, for
0<=i<=15.

### 3.4 The nonlinear function F

The nonlinear function *F* has 2 of 32-bit memory cells *R1* and *R2*. Let the inputs to *F* be
*X0,X1* and *X2*, which come from the outputs of the bit-reorganization (see section 3.3), then the
function *F* outputs a 32-bit word *W*. The detailed process of *F* is as follows:

```cryptol
F : [2][32] -> [3][32] -> ([32], [2][32])
F [R1, R2] [X0, X1, X2] = (W, [R1', R2'])
    where
        W = (X0 ^ R1) + R2
        W1 = R1 + X1
        W2 = R2 ^ X2
        R1' = S (L1 (L W1 # H W2))
        R2' = S (L2 (L W2 # H W1))
```

where *S* is a 32x32 S-box, see section 3.4.1, *L1* and *L2* are linear transforms as defined in
section 3.4.2.

#### 3.4.1 The S-box *S*

The 32x32 S-box S is composed of 4 juxtaposed 8x8 S-boxes, i.e., *S=(S0,S1,S2,S3)*, where
*S0=S2,S1=S3*. The definitions of *S0* and *S1* can be found in table 3.1 and table 3.2
respectively.

```cryptol
S0 : [8] -> [8]
S0 x = S0Table@h@l
    where
        [h, l] = split x

S1: [8] -> [8]
S1 x = S1Table@h@l
    where
        [h, l] = split x

S2 : [8] -> [8]
S2 = S0

S3 : [8] -> [8]
S3 = S1
```

Let *x* be an 8-bit input to *S0* (or *S1*). Write *x* into two hexadecimal digits as `x=h||l`, then
the entry at the intersection of the *h*-th row and the *l*-th column in table 3.1 (or table 3.2) is
the output of *S0* (or *S1*).

**Example 7:**

```cryptol
property example7 = S0 0x12 == 0xF9
                 /\ S1 0x34 == 0xC0
```

Let the 32-bit input X and the 32-bit output Y of the S-box *S* be as follows:

```cryptol
S : [32] -> [32]
S X =  y0 # y1 # y2 # y3
    where
        [x0, x1, x2, x3] = split X
        y0 = S0 x0
        y1 = S1 x1
        y2 = S2 x2
        y3 = S3 x3
```

**Example 8:**

```cryptol
property example8 = S X == Y
    where
        X = 0x12345678
        Y = 0xF9C05A4E
```

**Table 3.1. The S-box S0**

```cryptol
S0Table : [16][16][8]
S0Table =
    [ [0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB]
    , [0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90]
    , [0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC]
    , [0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38]
    , [0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B]
    , [0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C]
    , [0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD]
    , [0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8]
    , [0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56]
    , [0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE]
    , [0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D]
    , [0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23]
    , [0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1]
    , [0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F]
    , [0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65]
    , [0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60]
    ]
```

**Table 3.2. The S-box S1**

```cryptol
S1Table : [16][16][8]
S1Table =
    [ [0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77]
    , [0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42]
    , [0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1]
    , [0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48]
    , [0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87]
    , [0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB]
    , [0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09]
    , [0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9]
    , [0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9]
    , [0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89]
    , [0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4]
    , [0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE]
    , [0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21]
    , [0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34]
    , [0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28]
    , [0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2]
    ]
```

#### 3.4.2 The linear transforms *L1* and *L2*

Both *L1* and *L2* are linear transforms from 32-bit words to 32-bit words, and are defined as
follows:

```cryptol
L1 : [32] -> [32]
L1 X = X ^ (X <<< 2) ^ (X <<< 10) ^ (X <<< 18) ^ (X <<< 24)

L2 : [32] -> [32]
L2 X = X ^ (X <<< 8) ^ (X <<< 14) ^ (X <<< 22) ^ (X <<< 30)
```

### 3.5 Key loading

The key loading procedure will expand the initial key and the initial vector into 16 of 31-bit
integers as the initial state of the LFSR. Let the 128-bit initial key *k* and the 128-bit initial
vector *iv* be

`k=k0||k1||k2||...||k15`

and

`iv=iv0||iv1||iv2||...||iv15`

respectively, where *k_i* and *iv_i*, 0<=i<=15, are all bytes. Then *k* and *iv* are loaded to the
cells *s0,s1,...,s15* of LFSR as follows:

```cryptol
D : [16][15]
D = [ 0b100010011010111, 0b010011010111100, 0b110001001101011, 0b001001101011110
    , 0b101011110001001, 0b011010111100010, 0b111000100110101, 0b000100110101111
    , 0b100110101111000, 0b010111100010011, 0b110101111000100, 0b001101011110001
    , 0b101111000100110, 0b011110001001101, 0b111100010011010, 0b100011110101100
    ]

KeyLoad : [128] -> [128] -> LFSR
KeyLoad k iv = s
    where
        k' = split`{16} k
        iv' = split`{16} iv
        s = [ ki # di # ivi | ki <- k' | di <- D | ivi <- iv' ]
```

### 3.6 The execution of ZUC

The execution of ZUC has two stages: the initialization stage and the working stage.

```cryptol
ZUC : [128] -> [128] -> [inf][32]
ZUC key iv = WorkStage initZuc
    where
        initZuc = InitializeStage key iv
```

#### 3.6.1 The initialization stage

During the initialization stage, the algorithm calls the key loading procedure (see section 3.5) to
load the 128-bit initial key *k* and the 128-bit initial vector *iv* into the LFSR, and set the
32-bit memory cells *R1* and *R2* to be all 0. The the cipher runs the following operations 32
times:

```cryptol
InitializeStage : [128] -> [128] -> (LFSR, [2][32])
InitializeStage k iv = last s'
    where
        s = KeyLoad k iv
        R0 = zero : [2][32]
        s' = [ (s, R0)] # [ InitializeStep si Ri | (si, Ri) <- s' | i <- [1..32] ]

InitializeStep : LFSR -> [2][32] -> (LFSR, [2][32])
InitializeStep s Rs = (s', Rs')
    where
        [X0, X1, X2, _] = Bitreorganization s
        (w, Rs') = F Rs [X0, X1, X2]
        s' = LFSRWithInitialisationMode (drop (w >> 1)) s
```

#### 3.6.2 The working stage

After the initialization stage, the algorithm moves in the working stage. At the working stage, the
algorithm executes the following operations once, and discards the output *W* of *F*:

```cryptol
WorkStep1 : LFSR -> [2][32] -> (LFSR, [2][32])
WorkStep1 s Rs = (s', Rs')
    where
        [X0, X1, X2, _] = Bitreorganization s
        (_, Rs') = F Rs [X0, X1, X2]
        s' = LFSRWithWorkMode s
```

Then the algorithm goes into the stage of producing keystream, i.e., for each iteration, the
following operations are executed once, and a 32-bit word *Z* is produced as an output:

```cryptol
WorkStep2 : LFSR -> [2][32] -> ([32], LFSR, [2][32])
WorkStep2 s Rs = (Z, s', Rs')
    where
        [X0, X1, X2, X3] = Bitreorganization s
        (w, Rs') = F Rs [X0, X1, X2]
        Z = w ^ X3
        s' = LFSRWithWorkMode s

WorkStage : (LFSR, [2][32]) -> [inf][32]
WorkStage (s, Rs) = zs
    where
        (s', Rs') = WorkStep1 s Rs
        z0 = zero : [32]
        keystream = [ (z0, s', Rs') ]
                  # [ WorkStep2 si Ri | (_, si, Ri) <- keystream | i <- [1...]]
        zs = [ (keystream@i).0 | i <- [1...] ]
```
