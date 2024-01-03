# FIPS 46-3: DATA ENCRYPTION STANDARD

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install
Cryptol from the website you can run ```cryptol DES.md``` in your terminal and all of the
definitions will be typecheck, and the test cases can be run.

All text in this document is directly from the
[Data Encryption Standard](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf).

```cryptol
module Primitive::Symmetric::Cipher::Block::DES where

import Primitive::Symmetric::Cipher::Block::Cipher
```

## Introduction

The algorithm is designed to encipher and decipher blocks of data consisting of 64 bits under
control of a 64-bit key. Deciphering must be accomplished by using the same key as for enciphering,
but with the schedule of addressing the keys bits altered so that the deciphering process is the
reverse of the enciphering process. A block to be enciphered is subjected to an initial permutation
*IP*, then to a complex key-dependent computation and finally to a permutation which is the inverse
of the initial permutation *IP^-1*. The key-dependent computation can be simply defined in terms of
a function *f*, called the cipher function, and a function *KS*, called the key schedule. A
description of the computation is given first, along with details as to how the algorithm is used
for encipherment. Next, the use of the algorithm for decipherment is described. Finally, a
definition of the cipher function *f* is given in terms of primitive functions which are called the
selection functions *S<sub>i</sub>* and the permutation function *P*. *S<sub>i</sub>*, *P*, and *KS*
of the algorithm are contained in Appendix 1.

```cryptol
DES : Cipher 64 64
DES = { encrypt key pt = encipher key pt
      , decrypt key ct = decipher key ct
      }

private
    encipher : [64] -> [64] -> [64]
    encipher K input = IP' (join preoutput)
        where
            LR0 = split (IP input) : [2][32]  // initial permutation
            Ks  = KS K
            LRs = [ LR0 ] # [ round LRn Kn | LRn <- LRs | Kn <- Ks ]
            preoutput = reverse (last LRs)
```

The following notation is convenient: Given two blocks *L* and *R* of bits, *LR* denotes the block
consisting of the bits of *L* followed by the bits of *R*. Since concatenation is associative,
*B<sub>1</sub>B<sub>2</sub>...B<sub>8</sub>* for example, denotes the block consisting of the bits
of *B<sub>1</sub>* followed by the bits of *B<sub>2</sub>*...followed by the bits of
*B<sub>8</sub>*.

## Enciphering

A sketch of the enciphering computation is given in Figure 1.

The 64 bits of the input block to be enciphered are first subjected to the following permutation,
called the initial permutation `IP`:

```cryptol
private
    IPTable : [64][8]
    IPTable = [ 58, 50, 42, 34, 26, 18, 10, 2
              , 60, 52, 44, 36, 28, 20, 12, 4
              , 62, 54, 46, 38, 30, 22, 14, 6
              , 64, 56, 48, 40, 32, 24, 16, 8
              , 57, 49, 41, 33, 25, 17,  9, 1
              , 59, 51, 43, 35, 27, 19, 11, 3
              , 61, 53, 45, 37, 29, 21, 13, 5
              , 63, 55, 47, 39, 31, 23, 15, 7
              ]

    IP : [64] -> [64]
    IP input = [ input@(i-1) | i <- IPTable ]
```

That is the permuted input has bit 58 of the input as its first bit, bit 50 as its second bit, and
so on with bit 7 as its last bit. The permuted input block is then the input to a complex
key-dependent computation described below. The output of that computation, called the preoutput, is
then subjected to the following permutation which is the inverse of the initial permutation:

```cryptol
private
    IPTable' : [64][8]
    IPTable' = [ 40, 8, 48, 16, 56, 24, 64, 32
               , 39, 7, 47, 15, 55, 23, 63, 31
               , 38, 6, 46, 14, 54, 22, 62, 30
               , 37, 5, 45, 13, 53, 21, 61, 29
               , 36, 4, 44, 12, 52, 20, 60, 28
               , 35, 3, 43, 11, 51, 19, 59, 27
               , 34, 2, 42, 10, 50, 18, 58, 26
               , 33, 1, 41,  9, 49, 17, 57, 25
               ]

    IP' : [64] -> [64]
    IP' preoutput = [ preoutput@(i-1) | i <- IPTable' ]
```

That is, the output of the algorithm has bit 40 of the preoutput block as its first bit, bit 8 as
its second bit, and so on, until bit 25 of the preoutput block is the last bit of the output.

The computation which used the permuted input block as its input to produce the preoutput block
consists, but for a final interchange of blocks, of 16 iterations of a calculation that is described
below in terms of the cipher function `f` which operates on two blocks, one of 32 bits and one of 48
bits, and produces a block of 32 bits.

*Note: defined below in [The Cipher Function f](#the-cipher-function-f)*.

```cryptol
private
    f : [32] -> [48] -> [32]
```

Let the 64 bits of the input block to an iteration consist of a 32 bit block `L` followed by a 32
bit block `R`. Using the notation defined in the introduction, the input block is then `LR`.

Let `K` be a block of 48 bits chosen from the 64-bit key. Then the output `L'R'` of an iteration
with input `LR` is defined by:

(1)
```cryptol
private
    initial : [64] -> [48] -> [64]
    initial LR K = L' # R'
        where
            [L, R] = split LR : [2][32]
            L' = R
            R' = L ^ (f R K)
```

where `^` denotes bit-by-bit addition modulo 2.

As remarked before, the input of the first iteration of the calculation is the permuted input block.
If `L'R'` is the output of the 16th iteration then `R'L'` is the preoutput block. At each iteration
a different block `K` of key bits is chosen from the 64-bit key designated by `KEY`.

With more notation we can describe the iterations of the computation in more detail. Let `KS` be a
function which takes an integer `n` in the range from 1 to 16 and a 64-bit block `KEY` as input and
yields as output a 48-bit block *K<sub>n</sub>* which is permuted selection of bits from `KEY`. That
is

(2)

*Note: Defined below in
[Appendix 1](#appendix-1-primitive-functions-for-the-data-encryption-algorithm).*

```cryptol
private
    KS : [64] -> [16][48]
```

with *K<sub>n</sub>* determined by the bits in 48 distinct bit positions of `KEY`. `KS` is called
the key schedule because the block `K` used in the *n*'th iteration of (1) is the block
*K<sub>n</sub>* determined by (2).

As before, let the permuted input block be `LR`. Finally, let *L<sub>0</sub>* and *R<sub>0</sub>* be
respectively `L` and `R` and let *L<sub>n</sub>* and *R<sub>n</sub>* be respectively `L'` and `R'`
of (1) when `L` and `R` are respectively *L<sub>n-1</sub>* and *R<sub>n-1</sub>* and `K` is
*K<sub>n</sub>*; that is, when *n* is in the range from 1 to 16,

(3)
```cryptol
private
    round : [2][32] -> [48] -> [2][32]
    round [L, R] K = [L', R']
        where
            L' = R
            R' = L ^ (f R K)
```

The preoutput block is then *R<sub>16</sub>L<sub>16</sub>*.

The key schedule `KS` of the algorithm is described in detail in the Appendix. The key schedule
produces the 16 *K<sub>n</sub>* which are required by the algorithm.

## Deciphering

The permutation `IP'` applied to the preoutput block is the inverse of the initial permutation `IP`
applied to the input. Further, from (1) it follows that:

(4)
```cryptol
private
    initial' : [64] -> [48] -> [64]
    initial' L'R' K = L # R
        where
            [L', R'] = split L'R' : [2][32]
            R = L'
            L = R' ^ (f L' K)
```

Consequently, to *decipher* it is only necessary to apply the *very same algorithm to an enciphered
message block*, taking care that at each iteration of the computation *the same block of key bits K
is used* during decipherment as was used during the encipherment of the block. Using the notation of
the previous section, this can be expressed by the equations:

(5)
```cryptol
private
    round' : [2][32] -> [48] -> [2][32]
    round' [L, R] K = [L', R']
        where
            R' = L
            L' = R ^ (f L K)
```

where now *R<sub>16</sub>L<sub>16</sub>* is the permuted input block for the deciphering calculation
and *L<sub>0</sub>R<sub>0</sub>* is the preoutput block. That is, for the decipherment calculation
with *R<sub>16</sub>L<sub>16</sub>* as the permuted input, *K<sub>16</sub>* is used in the first
iteration, *K<sub>15</sub>* in the second, and so on, with *K<sub>1</sub>* used in the 16th
iteration.

```cryptol
private
    decipher : [64] -> [64] -> [64]
    decipher K output = IP' (join LR0)
        where
            LR16 = reverse (split (IP output) : [2][32])
            Ks' = reverse (KS K)
            LRs' = [ LR16 ] # [ round' LRn' Kn | LRn' <- LRs' | Kn <- Ks' ]
            LR0 = last LRs'

    property DecipherInvertsEncipher input key = decipher key (encipher key input) == input
    property DESCorrect key msg = DES.decrypt key (DES.encrypt key msg) == msg
```

## The Cipher Function *f*

A sketch of the calculation of `f(R, K)` is given in **Figure 2**.

Let `E` denote a function which takes a block of 32 bits as input and yields a block of 48 bits as
output. Let `E` be such that the 48 bits of its output, written as 8 blocks of 6 bits each, are
obtained by selecting the bits in its inputs in order according to the following table:

```cryptol
private
    // E BIT-SELECTION TABLE
    Ebits : [48][8]
    Ebits = [ 32,  1,  2,  3,  4,  5
            ,  4,  5,  6,  7,  8,  9
            ,  8,  9, 10, 11, 12, 13
            , 12, 13, 14, 15, 16, 17
            , 16, 17, 18, 19, 20, 21
            , 20, 21, 22, 23, 24, 25
            , 24, 25, 26, 27, 28, 29
            , 28, 29, 30, 31, 32,  1
            ]

    E : [32] -> [48]
    E R = R'
        where
            R' = [ R@(ebit - 1) | ebit <- Ebits]
```

Thus the first three bits of `E(R)` are the bits in positions 32, 1, and 2 of `R` while the last 2
bits of `E(R)` are the bits in positions 32 and 1.

Each of the unique selection functions *S<sub>1</sub>,S<sub>2</sub>,...,S<sub>8</sub>* takes a 6-bit
block as input and yields a 4-bit block as output and is illustrated by using a table containing the
recommended *S<sub>1</sub>*:

**S<sub>1</sub>**

| Row No | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
| ------ | - | - | - | - | - | - | - | - | - | - | -- | -- | -- | -- | -- | -- |
| 0 | 14 |  4 | 13 |  1 |  2 | 15 | 11 |  8 |  3 | 10 |  6 |  12 |  5 |  9 |  0 |  7 |
| 1 |  0 | 15 |  7 |  4 | 14 |  2 | 13 |  1 | 10 |  6 | 12 |  11 |  9 |  5 |  3 |  8 |
| 2 |  4 |  1 | 14 |  8 | 13 |  6 |  2 | 11 | 15 | 12 |  9 |   7 |  3 | 10 |  5 |  0 |
| 3 | 15 | 12 |  8 |  2 |  4 |  9 |  1 |  7 |  5 | 11 |  3 |  14 | 10 |  0 |  6 | 13 |

If *S<sub>1</sub>* is the function defined in this table and *B* is a block of 6 bits, then
*S<sub>1</sub>(B)* is determined as follows: The first and last bits of *B* represent in base 2 a
number in the range 0 to 3. Let that number be `i`. The middle 4 bits of *B* represent in base 2 a
number in the range 0 to 15. Let that number be `j`. Look up in the table the number in the `i`'th
row and `j`'th column. It is a number in the range 0 to 15 and is uniquely represented by a 4 bit
block. That block is the output *S<sub>1</sub>(B)* of *S<sub>1</sub>* for the input *B*. For
example, for input `011011` the row is `01`, that is row 1, and the column is determined by `1101`,
that is column 12. In row 1 column 13 appears 5 so that the output is `0101`. Selection functions
*S<sub>1</sub>,S<sub>2</sub>,...,S<sub>8</sub>* of the algorithm appear in Appendix 1.

```cryptol
private
    S : [6] -> [8] -> [4]
    S B idx = (Si@i@j)
        where
            ss = [s1, s2, s3, s4, s5, s6, s7, s8]
            Si = (ss@(idx - 1))
            i = [(B@0), (B@5)]
            j = B@@[1..4]

    property example_s1 = S input 1 == output
        where
            input  = 0b011011
            output = 0b0101
```

The permutation function *P* yields a 32-bit output from a 32-bit input by permuting the bits of the
input block. Such a function is defined by the following table:

```cryptol
private
    Ptable : [32][8]
    Ptable = [ 16,  7, 20, 21
             , 29, 12, 28, 17
             ,  1, 15, 23, 26
             ,  5, 18, 31, 10
             ,  2,  8, 24, 14
             , 32, 27,  3,  9
             , 19, 13, 30,  6
             , 22, 11,  4, 25
             ]
```

The output *P(L)* for the function *P* defined by this table is obtained from the input *L* by
taking the 16th bit of *L* as the first bit of *P(L)*, the 7th bit as the second bit of *P(L)*, and
so on until the 25th bit of *L* is taken as the 32nd bit of *P(L)*. The permutation function *P* of
the algorithm is repeated in Appendix 1.

```cryptol
private
    P : [32] -> [32]
    P L = [ L@(p-1) | p <- Ptable ]
```

Now let *S<sub>1</sub>,...,S<sub>8</sub>* be eight distinct selection functions, let *P* be the
permutation function and let *E* be the function defined above.

To define *f(R, K)* we first define *B<sub>1</sub>,...,B<sub>8</sub>* to be blocks of 6 bits each
for which

(6)
```example
B = K ^ (E R)
```

The block *f(R, K)* is then defined to be

(7)
```cryptol
private
    f R K = P Ss
        where
            Bs = split`{8} (K ^ (E R))
            Ss = join [ S B i | B <- Bs | i <- [1..8] ]
```

Thus *K ^ E(R)* is first divided into the 8 blocks as indicated in (6). Then each *B<sub>i</sub>* is
taken as an input to *S<sub>i</sub>* and the 8 blocks
*S<sub>1</sub>(B<sub>1</sub>),S<sub>2</sub>(B<sub>2</sub>),...,S<sub>8</sub>(B<sub>8</sub>)* of 4
bits each are consolidated into a single block of 32 bits which forms the input to *P*. The output
(7) is then the output of the function *f* for the inputs *R* and *K*.

## APPENDIX 1: PRIMITIVE FUNCTIONS FOR THE DATA ENCRYPTION ALGORITHM

The choice of the primitive functions *KS*, *S<sub>1</sub>,...,S<sub>8</sub>* and *P* is critical to
the strength of an encipherment resulting from the algorithm. Specified below is the recommended set
of functions describing *S<sub>1</sub>,...,S<sub>8</sub>* and *P* in the same way they are described
in the algorithm. for the interpretation of the tables describing these functions, see the
discussion in the body of the algorithm.

The primitive functions *S<sub>1</sub>,...,S<sub>8</sub>* are:

```cryptol
private
    s1 : [4][16][4]
    s1 = [ [14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7]
         , [ 0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8]
         , [ 4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0]
         , [15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13]
         ]

    s2 : [4][16][4]
    s2 = [ [15,  1,  8, 14,  6, 11,  3,  4,  9, 7,  2, 13, 12, 0,  5, 10]
         , [ 3, 13,  4,  7, 15,  2,  8, 14, 12, 0,  1, 10,  6, 9, 11,  5]
         , [ 0, 14,  7, 11, 10,  4, 13,  1,  5, 8, 12,  6,  9, 3,  2, 15]
         , [13,  8, 10,  1,  3, 15,  4,  2, 11, 6,  7, 12,  0, 5, 14,  9]
         ]

    s3 : [4][16][4]
    s3 = [ [10,  0,  9, 14, 6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8]
         , [13,  7,  0,  9, 3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1]
         , [13,  6,  4,  9, 8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7]
         , [ 1, 10, 13,  0, 6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
         ]

    s4 : [4][16][4]
    s4 = [ [ 7, 13, 14, 3,  0,  6,  9, 10,  1, 2, 8,  5, 11, 12,  4, 15]
         , [13,  8, 11, 5,  6, 15,  0,  3,  4, 7, 2, 12,  1, 10, 14,  9]
         , [10,  6,  9, 0, 12, 11,  7, 13, 15, 1, 3, 14,  5,  2,  8,  4]
         , [ 3, 15,  0, 6, 10,  1, 13,  8,  9, 4, 5, 11, 12,  7,  2, 14]
         ]

    s5 : [4][16][4]
    s5 = [ [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13, 0, 14,  9]
         , [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3, 9,  8,  6]
         , [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6, 3,  0, 14]
         , [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10, 4,  5,  3]
         ]

    s6 : [4][16][4]
    s6 = [ [12,  1, 10, 15, 9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11]
         , [10, 15,  4,  2, 7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8]
         , [ 9, 14, 15,  5, 2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6]
         , [ 4,  3,  2, 12, 9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
         ]

    s7 : [4][16][4]
    s7 = [ [ 4, 11,  2, 14, 15, 0,  8, 13,  3, 12, 9,  7,  5, 10, 6,  1]
         , [13,  0, 11,  7,  4, 9,  1, 10, 14,  3, 5, 12,  2, 15, 8,  6]
         , [ 1,  4, 11, 13, 12, 3,  7, 14, 10, 15, 6,  8,  0,  5, 9,  2]
         , [ 6, 11, 13,  8,  1, 4, 10,  7,  9,  5, 0, 15, 14,  2, 3, 12]
         ]

    s8 : [4][16][4]
    s8 = [ [13,  2,  8, 4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7]
         , [ 1, 15, 13, 8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2]
         , [ 7, 11,  4, 1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8]
         , [ 2,  1, 14, 7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]
         ]
```

The primitive function *P* is:

*Note: Previously defined above in [The Cipher Function f](#the-cipher-function-f)*.

```example
[ 16,  7, 20, 21
, 29, 12, 28, 17
,  1, 15, 23, 26
,  5, 18, 31, 10
,  2,  8, 24, 14
, 32, 27,  3,  9
, 19, 13, 30,  6
, 22, 11,  4, 25 ]
```

Recall that *K<sub>n</sub>* for `1<=n<=16`, is the blokc of 48 bits in (2) of the algorithm. Hence,
to describe *KS*, it is sufficient to describe the calculation of *K<sub>n</sub>* from `KEY` for
`n=1, 2,..., 16`. That calculation is illustrated in **Figure 3**. To complete the definition of
*KS* it is therefore sufficient to describe the two permuted choices, as well as the schedule of
left shifts. One bit in each 8-bit byte of the `KEY` may be utilized for error detection in key
generation, distribution and storage. Bits 8, 16, ..., 64 are for use in assuring that each byte is
of odd parity.

Permuted choice 1 is determined by the following table:

```cryptol
private
    PC1Table : [2][28][8]
    PC1Table = [C, D]
        where
            C = [ 57, 49, 41, 33, 25, 17,  9
                ,  1, 58, 50, 42, 34, 26, 18
                , 10,  2, 59, 51, 43, 35, 27
                , 19, 11,  3, 60, 52, 44, 36
                ]
            D = [ 63, 55, 47, 39, 31, 23, 15
                ,  7, 62, 54, 46, 38, 30, 22
                , 14,  6, 61, 53, 45, 37, 29
                , 21, 13,  5, 28, 20, 12,  4
                ]
```

The table has been divided into two parts, with the first part determining how the bits of *C* are
chosen, and the second part determining how the bits of *D* are chosen. The bits of `KEY` are
numbered 1 through 64. The bits of *C* are respectively bits 57, 49, 41,...,44 and 36 of `KEY`, with
the bits of of *D* being bits 63, 55, 47,..., 12 and 4 of `KEY`.

```cryptol
private
    PC1 : [64] -> [2][28]
    PC1 K = [join C0, join D0]
        where
            [C, D] = PC1Table
            C0 = [ [(K@((C@i)-1))] | i <- [0..27]]
            D0 = [ [(K@((D@i)-1))] | i <- [0..27]]
```

With *C* and *D* defined, we now define how the blocks *C<sub>n</sub>* and *D<sub>n</sub>* are
obtained from the blocks *C<sub>n-1</sub>* and *D<sub>n-1</sub>*, respectively, for
`n = 1,2,...,16`. That is accomplished by adhering to the following schedule of left shifts of the
individual blocks:

```cryptol
private
    KS K = [ PC2 (join cd) | cd <- drop CnDns ]
        where
            C0D0  = PC1 K
            CnDns = [C0D0] # [ [Cn <<< (shifts@i), Dn <<< (shifts@i) ]
                             | [Cn, Dn] <- CnDns
                             | i <- [0..15]]
```

| Iteration Number | Number of Left Shifts |
| :--------------: | :-------------------: |
|  1 | 1 |
|  2 | 1 |
|  3 | 2 |
|  4 | 2 |
|  5 | 2 |
|  6 | 2 |
|  7 | 2 |
|  8 | 2 |
|  9 | 1 |
| 10 | 2 |
| 11 | 2 |
| 12 | 2 |
| 13 | 2 |
| 14 | 2 |
| 15 | 2 |
| 16 | 1 |

```cryptol
private
    shifts : [16][8]
    shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
```

For example, *C<sub>3</sub>* and *D<sub>3</sub>* are obtained from *C<sub>2</sub>* and
*D<sub>2</sub>*, respectively, by two left shifts, and *C<sub>16</sub>* and *D<sub>16</sub>* are
obtained from *C<sub>15</sub>* and *D<sub>15</sub>*, respectively, by one left shift. In all cases,
by a single left shift is meant a rotation of the bits one place to the left, so that after one left
shift the bits in the 28 positions are the bits that were previously in positions 2, 3,..., 28, 1.

Permuted choice 2 is determined by the following table:

```cryptol
private
    PC2Table : [48][8]
    PC2Table = [ 14, 17, 11, 24,  1,  5
               ,  3, 28, 15,  6, 21, 10
               , 23, 19, 12,  4, 26,  8
               , 16,  7, 27, 20, 13,  2
               , 41, 52, 31, 37, 47, 55
               , 30, 40, 51, 45, 33, 48
               , 44, 49, 39, 56, 34, 53
               , 46, 42, 50, 36, 29, 32
               ]
```

Therefore, the first bit of *K<sub>n</sub>* is the 14th bit of *C<sub>n</sub>D<sub>n</sub>* the
second bit the 17th, and so on with the 47th bit the 29th, and the 48th bit the 32nd.

```cryptol
private
    PC2 : [56] -> [48]
    PC2 CnDn = join Kn
        where
            Kn = [ [CnDn@(i-1)] | i <- PC2Table ]
```

## Test Vectors

The following test vectors are pulled from the appendix of
[NIST 800-17](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-17.pdf).

### Appendix B: Tables of Values for the Known Answer Tests

Table 1. Resulting Ciphertext from the Variable Plaintext Known Answer Test for DES

(*NOTE: KEY = 01 01 01 01 01 01 01 01 (odd parity set)*)

```cryptol
private
    property test_tbl1 = DES.encrypt key pt0 == ct0
                      /\ DES.encrypt key pt1 == ct1
                      /\ DES.encrypt key pt2 == ct2
        where
            key = 0x0101010101010101
            pt0 = 0x8000000000000000
            ct0 = 0x95f8a5e5dd31d900
            pt1 = 0x4000000000000000
            ct1 = 0xdd7f121ca5015619
            pt2 = 0x2000000000000000
            ct2 = 0x2e8653104f3834ea
```

Table 2. Resulting Ciphertext from the Variable Key Known Answer Test for DES

(*NOTE: Plaintext/text = 00 00 00 00 00 00 00 00 and, where applicable,
IV = 00 00 00 00 00 00 00 00*)

```cryptol
private
    property test_tbl2 = DES.encrypt k0 pt == ct0
                      /\ DES.encrypt k1 pt == ct1
                      /\ DES.encrypt k2 pt == ct2
        where
            pt  = 0x0000000000000000
            k0  = 0x8001010101010101
            ct0 = 0x95a8d72813daa94d
            k1  = 0x4001010101010101
            ct1 = 0x0eec1487dd8c26d5
            k2  = 0x2001010101010101
            ct2 = 0x7ad16ffb79c45926
```

Table 3. Values To Be Used for the Permutation Operation Known Answer Test

(*NOTE: Plaintext/text = 00 00 00 00 00 00 00 00 for each round and, where applicable,
IV = 00 00 00 00 00 00 00 00*)

```cryptol
private
    property test_tbl3 = DES.encrypt k0 pt == ct0
                      /\ DES.encrypt k1 pt == ct1
                      /\ DES.encrypt k2 pt == ct2
        where
            pt  = 0x0000000000000000
            k0  = 0x1046913489980131
            ct0 = 0x88d55e54f54c97b4
            k1  = 0x1007103489988020
            ct1 = 0x0c0cc00c83ea48fd
            k2  = 0x10071034c8980120
            ct2 = 0x83bc8ef3a6570183
```

Table 4. Values To Be Used for the Substitution Table Known Answer Test

```cryptol
private
    property test_tbl4 = DES.encrypt k0 pt0 == ct0
                      /\ DES.encrypt k1 pt1 == ct1
                      /\ DES.encrypt k2 pt2 == ct2
                      /\ DES.encrypt k3 pt3 == ct3
        where
            k0  = 0x7ca110454a1a6e57
            pt0 = 0x01a1d6d039776742
            ct0 = 0x690f5b0d9a26939b
            k1  = 0x0131d9619dc1376e
            pt1 = 0x5cd54ca83def57da
            ct1 = 0x7a389d10354bd271
            k2  = 0x07a1133e4a0b2686
            pt2 = 0x0248d43806f67172
            ct2 = 0x868ebb51cab4599a
            k3  = 0x3849674c2602319e
            pt3 = 0x51454b582ddf440a
            ct3 = 0x7178876e01f19b2a
```
