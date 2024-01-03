# Salsa20 specification

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install
Cryptol from the website you can run ```cryptol Salsa20.md``` in your terminal and all of the
definitions will be typecheck, and the test cases can be run.

All text in this document is directly from the
[Salsa20 specification](http://cr.yp.to/snuffle/spec.pdf).

## Abstract

This document defines the Salsa20 hash function, the Salsa20 expansion function, and the Salsa20
encryption function.

```cryptol
module Primitive::Symmetric::Cipher::Stream::Salsa20 where
```

## 1 Introduction

The core of Salsa20 is a hash function with 64-byte input and 64-byte output. The hash function is
used in counter mode as a stream cipher: Salsa20 encrypts a 64-byte block of plaintext by hashing
the key, nonce, and block number and xor'ing the result with the plaintext.

This document defines Salsa20 from bottom up, starting with three simple operations on 4-byte words,
continuing through the Salsa20 hash function, and finishing with the Salsa20 encryption function.

In this document, a `byte` is an element of `{0,1,...,255}`. There are many common ways to represent
a byte as a sequence of electrical signals; the details of this representation are of no relevance
to the definition of Salsa20.

## 2 Words

A **word** is an element of {0,1,...,2<sup>32</sup>-1}. Words in the document are often written in
hexadecimal, indicated by the symbols `0x`: for example, ```
0xc0a8787e = 12·2^28 + 0·2^24 + 10·2^20 + 8·2^16 + 7·2^12 + 8·2^8 + 7·2^4 + 14·2^0 = 3232266366```.

The **sum** of two words *u*, *v* is `u+v mod 2^32`. The sum is denoted `u + v`; there is not risk
of confusion. For example,

```cryptol
property exampleSum = 0xc0a8787e + 0x9fd1161d == 0x60798e9b
```

The **exclusive-or** of two words *u*, *v*, denoted by `u^v`, is the sum of *u* and *v* with carries
suppressed. In other words, if *u=∑<sub>i</sub> 2<sup>i</sup>u<sub>i</sub>* and
*v=∑<sub>i</sub> 2<sup>i</sup>v<sub>i</sub>* then
*u⊕v=∑<sub>i</sub> 2<sup>i</sup>(u<sub>i</sub>+v<sub>i</sub>-2u<sub>i</sub>v<sub>i</sub>)*. For
example,

```cryptol
property exampleXor = 0xc0a8787e ^ 0x9fd1161d == 0x5f796e63
```

For each `c ∈ {0,1,2,3...}`, the *c*-**bit left rotation** of a word *u*, denoted `u <<< c`, is the
unique nonzero word congruent to `2^c u modulo 2^32 - 1`, except that `0 <<< c = 0`. In other words,
if *u=∑<sub>i</sub> 2<sup>i</sup>u<sub>i</sub>* then
*u <<< c = ∑<sub>i</sub> 2<sup>i+c mod 32</sup>u<sub>i</sub>*. For example,

```cryptol
property exampleLeftRot = 0xc0a8787e <<< 5 == 0x150f0fd8
property exampleLeftRotZero = (0 : [32]) <<< 5 == 0
```

## 3 The quarterround function

### Inputs and outputs

If *y* is a 4-word sequence then quarterround(y) is a 4-word sequence.

```cryptol
quarterround : [4][32] -> [4][32]
```

### Definitions

If `y = (y0,y1,y2,y3)` then `quarterround(y) = (z0,z1,z2,z3)` where

```cryptol
quarterround [y0, y1, y2, y3] = [z0, z1, z2, z3]
    where
        z1 = y1 ^ ((y0 + y3) <<< 7)
        z2 = y2 ^ ((z1 + y0) <<< 9)
        z3 = y3 ^ ((z2 + z1) <<< 13)
        z0 = y0 ^ ((z3 + z2) <<< 18)
```

### Examples

```cryptol
property quarterroundExamples = quarterround [0x00000000, 0x00000000, 0x00000000, 0x00000000] == [0x00000000, 0x00000000, 0x00000000, 0x00000000]
                             /\ quarterround [0x00000001, 0x00000000, 0x00000000, 0x00000000] == [0x08008145, 0x00000080, 0x00010200, 0x20500000]
                             /\ quarterround [0x00000000, 0x00000001, 0x00000000, 0x00000000] == [0x88000100, 0x00000001, 0x00000200, 0x00402000]
                             /\ quarterround [0x00000000, 0x00000000, 0x00000001, 0x00000000] == [0x80040000, 0x00000000, 0x00000001, 0x00002000]
                             /\ quarterround [0x00000000, 0x00000000, 0x00000000, 0x00000001] == [0x00048044, 0x00000080, 0x00010000, 0x20100001]
                             /\ quarterround [0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137] == [0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3]
                             /\ quarterround [0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b] == [0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c]
```

### Comments

One can visualize the quarterround function as modifying *y* in place: first y1 changes to z1, then
y2 changes to z2, then y3 changes to z3, then y0 changes to z0. Each modification is invertible, so
the entire function is invertible.

```cryptol
property quarterroundInverts y y' = y != y' ==> quarterround y != quarterround y'
```

## 4 The rowround function

### Inputs and outputs

If y is a 16-word sequence then rowround(y) is a 16-word sequence.

```cryptol
rowround : [16][32] -> [16][32]
```

### Definition

If `y = (y0,y1,y2,y3,...,y15)` then `rowround(y) = (z0,z1,z2,z3,...,z15)` where

```cryptol
rowround [y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15] =
         [z0,z1,z2,z3,z4,z5,z6,z7,z8,z9,z10,z11,z12,z13,z14,z15]
    where
        [z0,z1,z2,z3]     = quarterround [y0,y1,y2,y3]
        [z5,z6,z7,z4]     = quarterround [y5,y6,y7,y4]
        [z10,z11,z8,z9]   = quarterround [y10,y11,y8,y9]
        [z15,z12,z13,z14] = quarterround [y15,y12,y13,y14]
```

### Examples

```cryptol
property rowroundExamples = rowround [ 0x00000001, 0x00000000, 0x00000000, 0x00000000
                                     , 0x00000001, 0x00000000, 0x00000000, 0x00000000
                                     , 0x00000001, 0x00000000, 0x00000000, 0x00000000
                                     , 0x00000001, 0x00000000, 0x00000000, 0x00000000 ] ==
                                     [ 0x08008145, 0x00000080, 0x00010200, 0x20500000
                                     , 0x20100001, 0x00048044, 0x00000080, 0x00010000
                                     , 0x00000001, 0x00002000, 0x80040000, 0x00000000
                                     , 0x00000001, 0x00000200, 0x00402000, 0x88000100 ]
                         /\ rowround [ 0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365
                                     , 0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6
                                     , 0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e
                                     , 0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a ] ==
                                     [ 0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86
                                     , 0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1
                                     , 0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8
                                     , 0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d ]
```

### Comments

One can visualize the input (y0,y1,..,y15) as a square matrix:

```example
 y0  y1  y2  y3
 y4  y5  y6  y7
 y8  y9 y10 y11
y12 y13 y14 y15
```

The rowround function modifies the rows of the matrix in parallel by feeding a permutation of each
row through the quarterround function. In the first row, the rowround function modifies y1, then y2,
then y3, then y0; in the second row, the rowround function modifies y6, then y7, then y4, then y5;
in the third row, the rowround function modifies y11, then y8, then y9, then y10; in the fourth row,
the rowround function modifies y12, then y13, then y14, then y15.

## 5 The columnround function

### Inputs and outputs

If x is a 16-word sequence then columnround(x) is a 16-word sequence.

```cryptol
columnround : [16][32] -> [16][32]
```

### Definition

If `x = (x0,x1,x2,...,x15)` then `columnround(x) = (y0,y1,y2,...,y15)` where:

```cryptol
columnround [x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15] =
            [y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15]
    where
        [y0,y4,y8,y12]  = quarterround [x0,x4,x8,x12]
        [y5,y9,y13,y1]  = quarterround [x5,x9,x13,x1]
        [y10,y14,y2,y6] = quarterround [x10,x14,x2,x6]
        [y15,y3,y7,y11] = quarterround [x15,x3,x7,x11]
```

Equivalent formula:

```cryptol
columnround_equiv : [16][32] -> [16][32]
columnround_equiv [x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15] =
                  [y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15]
    where
        [y0,y4,y8,y12,y1,y5,y9,y13,y2,y6,y10,y14,y3,y7,y11,y15] =
            rowround [x0,x4,x8,x12,x1,x5,x9,x13,x2,x6,x10,x14,x3,x7,x11,x15]

property columnroundEquivalent x = columnround x == columnround_equiv x
```

### Examples

```cryptol
property columnroundExamples = columnround [ 0x00000001, 0x00000000, 0x00000000, 0x00000000
                                           , 0x00000001, 0x00000000, 0x00000000, 0x00000000
                                           , 0x00000001, 0x00000000, 0x00000000, 0x00000000
                                           , 0x00000001, 0x00000000, 0x00000000, 0x00000000 ] ==
                                           [ 0x10090288, 0x00000000, 0x00000000, 0x00000000
                                           , 0x00000101, 0x00000000, 0x00000000, 0x00000000
                                           , 0x00020401, 0x00000000, 0x00000000, 0x00000000
                                           , 0x40a04001, 0x00000000, 0x00000000, 0x00000000 ]
                            /\ columnround [ 0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365
                                           , 0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6
                                           , 0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e
                                           , 0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a ] ==
                                           [ 0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a
                                           , 0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69
                                           , 0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c
                                           , 0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8 ]
```

### Comments

One can visualize the inputs `(x0,x1,...,x15)` as a square matrix, as in Section 4:

```example
 x0  x1  x2  x3
 x4  x5  x6  x7
 x8  x9 x10 x11
x12 x13 x14 x15
```

The columnround function is, from this perspective, simply the transpose of the rowround function:
it modifies the columns of the matrix in parallel by feeding a permutation of each column through
the quarterround function. In the first column, the columnround function modifies y4, then y8, then
y12, then y0; in the second column, the columnround function modifies y9, then y13, then y1, then
y5; in the third column, the columnround function modifies y14, then y2, then y6, then y10; in the
fourth column, the columnround function modifies y3, then y7, then y11, then y15.

## 6 The doubleround function

### Inputs and outputs

If x is a 16-word sequence then doubleround(x) is a 16-word sequence.

```cryptol
doubleround : [16][32] -> [16][32]
```

### Definition

A double round is a column round followed by a row round:

```cryptol
doubleround x = rowround (columnround x)
```

### Examples

```cryptol
property doubleroundExamples = doubleround [ 0x00000001, 0x00000000, 0x00000000, 0x00000000
                                           , 0x00000000, 0x00000000, 0x00000000, 0x00000000
                                           , 0x00000000, 0x00000000, 0x00000000, 0x00000000
                                           , 0x00000000, 0x00000000, 0x00000000, 0x00000000 ] ==
                                           [ 0x8186a22d, 0x0040a284, 0x82479210, 0x06929051
                                           , 0x08000090, 0x02402200, 0x00004000, 0x00800000
                                           , 0x00010200, 0x20400000, 0x08008104, 0x00000000
                                           , 0x20500000, 0xa0000040, 0x0008180a, 0x612a8020 ]
                            /\ doubleround [ 0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57
                                           , 0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36
                                           , 0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11
                                           , 0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1 ] ==
                                           [ 0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0
                                           , 0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc
                                           , 0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00
                                           , 0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277 ]
```

### Comments

One can visualize a double round as modifying the columns of the input in parallel, and then
modifying the rows in parallel. Each word is modified twice.

## 7 The littleendian function

### Inputs and outputs

If b is a 4-byte sequence then littleendian(b) is a word.

```cryptol
littleendian : [4][8] -> [32]
```

### Definition

If *b = (b<sub>0</sub>,b<sub>1</sub>,b<sub>2</sub>,b<sub>3</sub>)* then
*littleendian(b) = b<sub>0</sub> + 2<sup>8</sup>b<sub>1</sub> + 2<sup>16</sup>b<sub>2</sub> +
2<sup>24</sup>b<sub>3</sub>*.

```cryptol
littleendian b = join (reverse b)
```

### Examples

```cryptol
property littleendianExamples = littleendian [0,0,0,0] == 0x00000000
                             /\ littleendian [86,75,30,9] == 0x091e4b56
                             /\ littleendian [255,255,255,250] == 0xfaffffff
```

### Comments

Note that littleendian is invertible.

```cryptol
property littleendianInvertible b b' = b != b' ==> littleendian b != littleendian b'

littleendian' : [32] -> [4][8]
littleendian' b = reverse (split b)

property littleendianInverseExamples = littleendian' 0x00000000 == [0,0,0,0]
                                    /\ littleendian' 0x091e4b56 == [86,75,30,9]
                                    /\ littleendian' 0xfaffffff == [255,255,255,250]

property littleendianInverts b = littleendian' (littleendian b) == b
```

## 8 The Salsa20 hash function

### Inputs and outputs

If x is a 64-byte sequence then Salsa20(x) is a 64-byte sequence.

```cryptol
Salsa20 : [64][8] -> [64][8]
```

### Definition

In short: Salsa20(x) = x + doubleround^10 (x), where each 4-byte sequence is viewed as a word in
little-endian form.

In detail:

```cryptol
Salsa20 x = join [ littleendian' y | y <- x' + z@10 ]
    where
        x' = [ littleendian xi | xi <- split x ]
        z  = [x'] # [ doubleround zi | zi <- z]
```

### Examples

```cryptol
property Salsa20Examples = Salsa20 [  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                   ,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                   ,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                   ,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ] ==
                                   [  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                   ,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                   ,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                   ,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
                        /\ Salsa20 [ 211,159, 13,115, 76, 55, 82,183, 3,117,222, 37
                                   , 191,187,234,136, 49,237,179, 48, 1,106,178,219
                                   , 175,199,166, 48, 86, 16,179,207, 31,240, 32, 63
                                   ,  15, 83, 93,161,116,147, 48,113,238, 55,204, 36
                                   ,  79,201,235, 79, 3, 81,156, 47,203, 26,244,243
                                   ,  88, 118,104, 54 ] ==
                                   [ 109, 42,178,168,156,240,248,238,168,196,190,203
                                   ,  26,110,170,154, 29, 29,150, 26,150, 30,235,249
                                   , 190,163,251, 48, 69,144, 51, 57, 118, 40,152,157
                                   , 180, 57, 27, 94,107, 42,236, 35, 27,111,114,114
                                   , 219,236,232,135,111,155,110, 18, 24,232, 95,158
                                   , 179, 19, 48,202 ]
                        /\ Salsa20 [ 88,118,104, 54, 79,201,235, 79, 3, 81,156, 47,203
                                   , 26,244,243,191,187,234,136,211,159, 13,115, 76, 55
                                   , 82,183, 3,117,222, 37, 86, 16,179,207, 49,237,179
                                   , 48, 1,106,178,219,175,199,166, 48,238, 55,204, 36
                                   , 31,240, 32, 63, 15, 83, 93,161,116,147, 48,113 ] ==
                                   [ 179, 19, 48,202,219,236,232,135,111,155,110, 18, 24
                                   , 232, 95,158, 26,110,170,154,109, 42,178,168,156,240
                                   , 248,238,168,196,190,203, 69,144, 51, 57, 29, 29,150
                                   ,  26,150, 30,235,249,190,163,251, 48, 27,111,114,114
                                   , 118, 40,152,157,180, 57, 27, 94,107, 42,236, 35 ]
```

## 9 The Salsa20 expansion function

### Inputs and outputs

*Note: The original document defines the Salsa20 expansion function as Salsa20<sub>k</sub>(n). For*
*clarity it is defined in this document to Salsa20_expansion(k, n).*

If k is a 32-byte or 16-byte sequence and n is a 16-byte sequence then Salsa20_expansion(k, n) is a
64-byte sequence.

```cryptol
Salsa20_expansion : {a} (a >= 1, 2 >= a) => [16*a][8] -> [16][8] -> [64][8]
```

### Definition

```cryptol
Salsa20_expansion k n = Salsa20 x
    where
        [σ0, σ1, σ2, σ3] = σ0σ1σ2σ3
        [τ0, τ1, τ2, τ3] = τ0τ1τ2τ3
        [ k0, k1 ] = split (k # zero) : [2][16][8]
        x = if `a == 2 then σ0 # k0 # σ1 # n # σ2 # k1 # σ3
                       else τ0 # k0 # τ1 # n # τ2 # k0 # τ3
```

### Examples

```cryptol
property Salsa20kExamples = Salsa20_expansion (k0 # k1) n == [ 69, 37, 68, 39, 41, 15,107,193,255,139,122, 6
                                                             ,170,233,217, 98, 89,144,182,106, 21, 51,200, 65
                                                             ,239, 49,222, 34,215,114, 40,126,104,197, 7,225
                                                             ,197,153, 31, 2,102, 78, 76,176, 84,245,246,184
                                                             ,177,160,133,130, 6, 72,149,119,192,195,132,236
                                                             ,234,103,246, 74 ]
                         /\ Salsa20_expansion k0 n        == [ 39,173, 46,248, 30,200, 82, 17, 48, 67,254,239
                                                             , 37, 18, 13,247,241,200, 61,144, 10, 55, 50,185
                                                             ,  6, 47,246,253,143, 86,187,225,134, 85,110,246
                                                             ,161,163, 43,235,231, 94,171, 51,145,214,112, 29
                                                             , 14,232, 5, 16,151,140,183,141,171, 9,122,181
                                                             ,104,182,177,193 ]
    where
        k0 = [1..16]
        k1 = [201..216]
        n  = [101..116]
```

### Comments

"Expansion" refers to the expansion of (k,n) into Salsa20_expansion(k, n). It also refers to the
expansion of k into a long stream of Salsa20_expansion outputs for various n's; see Section 10.

The constants `σ0 # σ1 # σ2 # σ3` and `τ0 # τ1 # τ2 # τ3` are "expand 32-byte k" and
"expand 16-byte k" in ASCII.

```cryptol
σ0σ1σ2σ3 : [4][4][8]
σ0σ1σ2σ3 = split "expand 32-byte k"

τ0τ1τ2τ3 : [4][4][8]
τ0τ1τ2τ3 = split "expand 16-byte k"

property expansionConstants = [σ0, σ1, σ2, σ3] == σ0σ1σ2σ3
                           /\ [τ0, τ1, τ2, τ3] == τ0τ1τ2τ3
    where
        σ0 = [ 101, 120, 112,  97 ]
        σ1 = [ 110, 100,  32,  51 ]
        σ2 = [  50,  45,  98, 121 ]
        σ3 = [ 116, 101,  32, 107 ]
        τ0 = [ 101, 120, 112,  97 ]
        τ1 = [ 110, 100,  32,  49 ]
        τ2 = [  54,  45,  98, 121 ]
        τ3 = [ 116, 101,  32, 107 ]
```

## 10 The Salsa20 encryption function

### Inputs and outputs

*Note: The original document defines the Salsa20 encryption function as Salsa20<sub>k</sub>(v) ⊕ m.*
*For clarity it is defined in this document to Salsa20_encrypt(k, v, m).*

Let k be a 32-byte or 16-byte sequence. Let v be an 8-byte sequence. Let m be an l-byte sequence for
some `l ∈ {0,1,...,2^70}`. The **Salsa20 encryption of** m **with nonce** v **under key** k, denoted
Salsa20_encrypt(k, v, m), is an l-byte sequence.

Normally k is a secret key (preferably 32 bytes); v is a nonce, i.e., a unique message number; m is
a plaintext message; and Salsa20_encrypt(k, v, m) is a ciphertext message. Or m can be a ciphertext message,
in which case Salsa20_encrypt(k, v, m) is the original plaintext message.

```cryptol
Salsa20_encrypt : {a, l} (a >= 1, 2 >= a, l >= 0, 2^^70 >= l)
       => [16*a][8] -> [8][8] -> [l][8] -> [l][8]
```

### Definition

Salsa20_expansion(k, v) is the 2^70-byte sequence

*Salsa20_expansion(k,v#0), Salsa20_expansion(k,v#1), Salsa20_expansion(k,v#2),...,
Salsa20_expansion(k,v#2^64-1)*

Here i is the unique 8-byte sequence (i<sub>0</sub>,i<sub>1</sub>,...,i<sub>7</sub>) such that
*i = i<sub>0</sub> + 2<sup>8</sup>i<sub>1</sub> + 2<sup>16</sup>i<sub>2</sub>+ ...
+2<sup>56</sup>i<sub>7</sub>*.

The formula Salsa20_encrypt(k, v, m) implicitly truncates Salsa20_expansion(k, v) to the same length
as m. In other words,

Salsa20_encrypt(k,v,m) = Salsa20_expansion(k,v) ⊕ (m[0],m[1],...,m[l-1]) = (c[0],c[1],...,c[l-1])

where c[i] = m[i] ⊕ Salsa20_expansion(k,v#⌊i/64⌋)[i mod 64].

```cryptol
Salsa20_encrypt k v m = m ^ s
    where
        s = take (join [ Salsa20_expansion k (v # (reverse (split i))) | i <- [0,1...] ])

Salsa20_encryptDecrypts : [32][8] -> [8][8] -> [32][8] -> Bit
property Salsa20_encryptDecrypts k v m = m == Salsa20_encrypt k0 v c1
                                      /\ m == Salsa20_encrypt k v c2
    where
        [ k0, k1 ] = split k : [2][16][8]
        c1  = Salsa20_encrypt k0 v m  // with 16 bit k
        c2  = Salsa20_encrypt k v m  // with 32 bit k
```

### Comments

The definition of Salsa20 could easily be generalized from byte sequences to bit sequences, given an
encoding of bytes as sequences of bits. However, there is no apparent application of this
generalization.
