<!---
 - @copyright Galois, Inc.
 - @author Alannah Carr
 --->
# The MD5 Message-Digest Algorithm

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install
Cryptol from the website you can run ```cryptol MD5.md``` in your terminal and all of the
definitions will be typechecked, and the test cases can be run.

All text in this document is directly from the [MD5 Specification](https://www.ietf.org/rfc/rfc1321.txt).

```cryptol
module Primitive::Keyless::Hash::MD5 where
```

## 2 Terminology and Notation

In this document, a "word" is a 32-bit quantity and a "byte" is an 8-bit quantity. A sequence of
bits can be interpreted in a natural manner as a sequence of bytes, where each consecutive group of
eight bits is interpreted as a byte with the high-order (most significant) bit of each byte listed
first. Similarly, a sequence of bytes can be interpreted as a sequence of 32-bit words, where each
consecutive group of four bytes is interpreted as a word with the low-order (least significant)
byte given first.

```cryptol
convert_length : [64] -> [64]
convert_length msg = join (reverse (groupBy`{8} msg))

convert : {n} (fin n) => [n*32] -> [n*32]
convert msg = join (join (map reverse msg''))
    where
        msg'  = groupBy`{8} msg
        msg'' = groupBy`{4} msg'

property test_convert_length_1 = convert_length msg == 0x0800000000000000
    where
        msg = 8 : [64]

property test_convert_initial = initialize == output
    where
        output = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

property test_convert_msg = convert msg == output
    where
        msg    = 0xd98c1dd404b2008f980980e97e42f8ec
        output = 0xd41d8cd98f00b204e9800998ecf8427e
```

Let x_i denote "x sub i". If the subscript is an expression, we surround it in braces, as in
x_{i+1}. Similarly, we use ^ for superscripts (exponentiation), so that x^i denotes x to the
i-th power.

Let the symbol "+" denote addition of words (i.e., modulo-2^32 addition). Let `X <<< s` denote the
32-bit value obtained by circularly shifting (rotating) X left by s bit positions. Let `not(X)`
denote the bit-wise complement of X, and let `X v Y` denote the bit-wise OR of X and Y. Let
`X xor Y` denote the bit-wise XOR of X and Y, and let `XY` denote the bit-wise AND of X and Y.

## 3 MD5 Algorithm Description

We begin by supposing that we have a b-bit message as input, and that we wish to find its message
digest. Here `b` is an arbitrary nonnegative integer; `b` may be zero, it need not be a multiple of
eight, and it may be arbitrarily large. We imagine the bits of the message written down as follows:

```example
m_0 m_1 ... m_{b-1}
```

The following five steps are performed to compute the message digest of the message.

### 3.1 Step 1. Append Padding Bits

The message is "padded" (extended) so that its length (in bits) is congruent to 448 modulo 512.
That is, the message is extended so that it is just 64 bits shy of being a multiple of 512 bits
long. Padding is always performed, even if the length of the message is already congruent to 448
modulo 512.

Padding is performed as follows: a single "1" bit is appended to the message, and then "0" bits are
appended so that the length in bits of the padded message becomes congruent to 448 modulo 512. In
all, at least one bit and at most 512 bits are appended.

```cryptol
pad : {b, p} (fin p, p >= 0, 64 >= width b) => [b] -> [b + p + 1]
pad msg = msg # [1] # zero
```

### 3.2 Step 2. Append Length

A 64-bit representation of b (the length of the message before padding bits were added) is appended
to the result of the previous step. In the unlikely event that b is greater than 2^64, then only the
low-order 64 bits of b are used. (These bits are appended as two 32-bit words and appended low-order
word first in accordance with the previous conventions.)

```cryptol
appendLength : {b, p} (fin p, p >= 0, 64 >= width b)
            => [b + p + 1] -> [b + p + 65]
appendLength msg = msg # b'
    where
        b' = convert_length (`b : [64])

prepMsg : {b} (64 >= width b)
       => [b] -> [((b + 65)/^ 512)][16][32]
prepMsg msg = groupBy`{16} (groupBy`{32} msgL)
    where
        type p = (b + 65) %^ 512  // how much padding is needed in addition to the [1]
        msgP   = pad`{b, p} msg
        msgL   = appendLength`{b, p} msgP
```

At this point the resulting message (after padding with bits and with b) has a length that is an
exact multiple of 512 bits. Equivalently, this message has a length that is an exact multiple of
16 (32-bit) words. Let `M[0...N-1]` denote the words of the resulting message, where N is a multiple
of 16.

### 3.3 Step 3. Initialize MD Buffer

A four-word buffer (A,B,C,D) is used to compute the message digest. Here each of A, B, C, D is a
32-bit register. There registers are initialized to the following values in hexadecimal, low-order
bytes first:

```cryptol
type Buffer = [4][32]

initialize : Buffer
initialize = [A', B', C', D']
    where
        A = [0x01, 0x23, 0x45, 0x67]
        B = [0x89, 0xab, 0xcd, 0xef]
        C = [0xfe, 0xdc, 0xba, 0x98]
        D = [0x76, 0x54, 0x32, 0x10]
        A' = convert (join A)
        B' = convert (join B)
        C' = convert (join C)
        D' = convert (join D)
```

### 3.4 Step 4. Process Message in 16-Word Blocks

We first define four auxiliary functions that each take as input three 32-bit words and produce as
output one 32-bit word.

```cryptol
F : [32] -> [32] -> [32] -> [32]
F X Y Z = (X && Y) || (~X && Z)  // XY v not(X) Z

G : [32] -> [32] -> [32] -> [32]
G X Y Z = (X && Z) || (Y && ~Z)  // XZ v Y not(Z)

H : [32] -> [32] -> [32] -> [32]
H X Y Z = X ^ Y ^ Z // X xor Y xor Z

I : [32] -> [32] -> [32] -> [32]
I X Y Z = Y ^ (X || ~Z) // Y xor (X v not(Z))
```

In each bit position F acts as a conditional: if X then Y else Z. The function F could have been
defined using + instead of v since XY and not(X)Z will never have 1's in the same bit position. It
is interesting to not that if the bits of X, Y and Z are independent and unbiased, then each bit of
F(X, Y, Z) will be independent and unbiased.

```cryptol
F_add : [32] -> [32] -> [32] -> [32]
F_add X Y Z = (X && Y) + (~X && Z)  // XY + not(X) Z

property f_equiv x y z = F x y z == F_add x y z
```

The functions G, H and I are similar to the function F, in that they act in "bitwise parallel" to
produce their output from the bits of X, Y, and Z, in such a manner that if the corresponding bits
of X, Y, and Z are independent and unbiased, then each bit of G(X,Y,Z), H(X,Y,Z), and I(X,Y,Z) will
be independent and unbiased. Note that the function H is the bit-wise "xor" or "parity" function of
its inputs.

This step uses a 64-element table T[1...64] constructed from the sine function. Let T[i] denote the
i-th element of the table, which is equal to the integer part of `4294967296 times abs(sin(i))`,
where `i` is in radians. The elements of the table are given in the appendix.

```cryptol
T : [64][32]
T =
    [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF,
     0x4787C62A, 0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF,
     0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E,
     0x49B40821, 0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
     0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8, 0x21E1CDE6,
     0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8,
     0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122,
     0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
     0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039,
     0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665, 0xF4292244, 0x432AFF97,
     0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D,
     0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
     0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391]
```

Do the following:

```cryptol
round1_op : Buffer -> [32] -> [5] -> [32] -> Buffer
round1_op [a, b, c, d] Xk s Ti = [a', b, c, d]
    where
        a' = b + ((a + (F b c d) + Xk + Ti) <<< s)

round1_alt : Buffer -> [16][32] -> Buffer
round1_alt [a0, b0, c0, d0] X = [a16, b16, c16, d16]
    where
        [ a1, b1, c1, d1] = round1_op [ a0,  b0,  c0,  d0]  (X@0)  7  (T@0)
        [ d2, a2, b2, c2] = round1_op [ d1,  a1,  b1,  c1]  (X@1) 12  (T@1)
        [ c3, d3, a3, b3] = round1_op [ c2,  d2,  a2,  b2]  (X@2) 17  (T@2)
        [ b4, c4, d4, a4] = round1_op [ b3,  c3,  d3,  a3]  (X@3) 22  (T@3)
        [ a5, b5, c5, d5] = round1_op [ a4,  b4,  c4,  d4]  (X@4)  7  (T@4)
        [ d6, a6, b6, c6] = round1_op [ d5,  a5,  b5,  c5]  (X@5) 12  (T@5)
        [ c7, d7, a7, b7] = round1_op [ c6,  d6,  a6,  b6]  (X@6) 17  (T@6)
        [ b8, c8, d8, a8] = round1_op [ b7,  c7,  d7,  a7]  (X@7) 22  (T@7)
        [ a9, b9, c9, d9] = round1_op [ a8,  b8,  c8,  d8]  (X@8)  7  (T@8)
        [d10,a10,b10,c10] = round1_op [ d9,  a9,  b9,  c9]  (X@9) 12  (T@9)
        [c11,d11,a11,b11] = round1_op [c10, d10, a10, b10] (X@10) 17 (T@10)
        [b12,c12,d12,a12] = round1_op [b11, c11, d11, a11] (X@11) 22 (T@11)
        [a13,b13,c13,d13] = round1_op [a12, b12, c12, d12] (X@12)  7 (T@12)
        [d14,a14,b14,c14] = round1_op [d13, a13, b13, c13] (X@13) 12 (T@13)
        [c15,d15,a15,b15] = round1_op [c14, d14, a14, b14] (X@14) 17 (T@14)
        [b16,c16,d16,a16] = round1_op [b15, c15, d15, a15] (X@15) 22 (T@15)

round1 : Buffer -> [16][32] -> Buffer
round1 abcd X = last abcds
    where
        ss = [7, 12, 17, 22]
        abcds = [ abcd ]
              # [ (round1_op abcd' (X@i) (ss@(i % 4)) (T@i)) >>> 1
                | abcd' <- abcds | i <- [0..15]
                ]

property round1_equiv x = round1 abcd x == round1_alt abcd x
    where
        abcd = initialize

round2_op : Buffer -> [32] -> [8] -> [32] -> Buffer
round2_op [a, b, c, d] Xk s Ti = [a', b, c, d]
    where
        a' = b + ((a + (G b c d) + Xk + Ti) <<< s)

round2 : Buffer -> [16][32] -> Buffer
round2 abcd X = last abcds
    where
        ss = [5, 9, 14, 20]
        abcds = [ abcd ]
              # [ (round2_op abcd' (X@((i*5+1)%16)) (ss@(i % 4)) (T@(16+i)) >>> 1)
                | abcd' <- abcds | i <- [0..15]
                ]

round3_op : Buffer -> [32] -> [8] -> [32] -> Buffer
round3_op [a, b, c, d] Xk s Ti = [a', b, c, d]
    where
        a' = b + ((a + (H b c d) + Xk + Ti) <<< s)

round3 : Buffer -> [16][32] -> Buffer
round3 abcd X = last abcds
    where
        ss = [4, 11, 16, 23]
        abcds = [ abcd ]
              # [ (round3_op abcd' (X@((i*3+5)%16)) (ss@(i % 4)) (T@(32+i)) >>> 1)
                | abcd' <- abcds | i <- [0..15]
                ]

round4_op : Buffer -> [32] -> [8] -> [32] -> Buffer
round4_op [a, b, c, d] Xk s Ti = [a', b, c, d]
    where
        a' = b + ((a + (I b c d) + Xk + Ti) <<< s)

round4 : Buffer -> [16][32] -> Buffer
round4 abcd X = last abcds
    where
        ss = [6, 10, 15, 21]
        abcds = [ abcd ]
              # [ (round4_op abcd' (X@((i*7)%16)) (ss@(i % 4)) (T@(48+i)) >>> 1)
                | abcd' <- abcds | i <- [0..15]
                ]

rounds : Buffer -> [16][32] -> Buffer
rounds abcd0 X = abcd0 + abcd4
    where
        abcd1 = round1 abcd0 X
        abcd2 = round2 abcd1 X
        abcd3 = round3 abcd2 X
        abcd4 = round4 abcd3 X

processMsg : {n} (fin n, n > 0) => [n][16][32] -> Buffer
processMsg M = last abcd'
    where
        abcd0 = initialize
        abcd' = [ abcd0 ]
              # [ rounds abcd (groupBy`{32} (convert (join X)))
                | abcd <- abcd' | X <- M ]
```

### 3.5 Step 5. Output

The message digest produced as output is A, B, C, D. That is, we begin with the low-order byte of A,
and end with the high-order byte of D.

```cryptol
md5 : {a} (64 >= width (a)) => [a] -> [128]
md5 msg = convert (join abcd)
    where
        msg' = prepMsg msg
        abcd = processMsg msg'
```

This completes the description of MD5. A reference implementation in C is given in the appendix.

## Appendix

### A.5 Test suite

```cryptol
test1 = md5 (join "") == 0xd41d8cd98f00b204e9800998ecf8427e
test2 = md5 (join "a") == 0x0cc175b9c0f1b6a831c399e269772661
test3 = md5 (join "abc") == 0x900150983cd24fb0d6963f7d28e17f72
test4 = md5 (join "message digest") == 0xf96b697d7cb7938d525a2f31aaf161d0
test5 = md5 (join "abcdefghijklmnopqrstuvwxyz") == 0xc3fcd3d76192e4007dfb496cca67e13b
test6 = md5 (join "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == 0xd174ab98d277d9f5a5611c2c9f419d9f
test7 = md5 (join "12345678901234567890123456789012345678901234567890123456789012345678901234567890") == 0x57edf4a22be3c955ac49da2e2107b67a

property tests_pass = test1 /\ test2 /\ test3 /\ test4
                   /\ test5 /\ test6 /\ test7
```

## Backwards Compatibility

The functions defined below maintain backwards compatibility with previous versions of the `MD5`
cryptol module.

```cryptol
// Test driver. Given a sequence of bytes, calculate the MD5 sum.
test s = md5 (join s)

// Reference implementation of MD5 on exactly 16 bytes
md5_ref : [16][8] -> [16][8]
md5_ref msg = map reverse (groupBy`{8} (md5 (join (map reverse msg))))

md5_ref' : [128] -> [128]
md5_ref' msg = join (md5_ref msg')
    where
        msg' = groupBy`{8} msg
```
