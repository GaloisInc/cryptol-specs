# SPHINCS+ in Cryptol

[SPHINCS+](https://sphincs.org) is an asymmetric hash-based signature scheme developed for the NIST post-quantum project.

This Markdown document is *literate Cryptol*,
and can be loaded like any other Cryptol module.
Cryptol only sees the contents of triple-backtick code blocks;
all other text here is strictly for human eyes.

```
module Primitive::Asymmetric::Signature::SphincsPlus where
```

The present document's heading structure follows the SPHINCS+ [specification](https://sphincs.org/data/sphincs+-specification.pdf),
and can be read as a supplement to that document.

---

## 2. Notation

This section shows the Cryptol equivalent of each basic operation used in the spec.

### 2.1 Data Types

The spec uses the blackboard bold **B** symbol ("𝔹") to mean *bytes*,
rather than the more standard mathematical meaning of *boolean* or *bit* values.

Byte string literals are written as "0x" followed by
an even number of hexadecimal digits, as in `0xe534f0`.
Arrays of byte strings have uniform element length,
determined by the longest element:
`[0x34, 5, 6] == [0x34, 0x05, 0x06]`.
Cryptol's built-in bit-string and array types are big-endian.

### 2.2 Functions

Cryptol doesn't have even an approximate notion of real or rational numbers,
and thus lacks *floor* and *ceiling* functions.
All the built-in operations on integer values return integers.

In particular, the base-2 logarithm returns the *ceiling* of its real-valued equivalent:
`(lg2 7, lg2 8, lg2 9) == (3, 3, 4)`.

| **Name** | **Spec syntax** | **Cryptol syntax** | **Example** |
| -------- | --------------- | ------------------ | ----------- |
| base-2 logarithm | ⌈ *log(x)* ⌉ | `lg2 x`     | `lg2 15 == 4` |

Truncation of a bit string is accomplished with Cryptol's `take` function,
writing *Trunc<sub>len</sub>(x)* as "take\`{*len*} *x*",
where "*len*" (in bits) is the function's first type-level parameter:
<pre>take`{16} 0x12345678 == 0x1234</pre>

### 2.3 Operators

The usual integer operators mostly have familiar notations,
and respect the standard precedence ordering.
Cryptol has no rational number type, so `/` means integer division.

The postfix `++` increment operator from C-like languages does not exist in Cryptol,
and can't be simulated by the divergent recursive binding `let a = a + 1`,
where variable `a` is already bound.
That Cryptol expression defines an infinite integer,
which cannot be evaluated in any useful way.
Instead of a destructive update, we must use a fresh variable: `let a' = a + 1`.

Cryptol's "logical" shift operators are defined on bit strings
rather than integers.
The `toInteger` and `fromInteger` functions convert between the two types.

Reading an array element at a given index
is accomplished with Cryptol's infix `@` operator,
rather than postfix square brackets.
We use `update` to create a new array from an existing one,
replacing a single indexed element.
Cryptol regards the byte strings defined above as
sequences of *bits* rather than bytes,
so we define another infix operator to access a whole byte at a particular index.

```
(~@) : {n} (fin n) => [n * 8] -> [n] -> [8]
(~@) bytestring index = (split`{each=8} bytestring) @ index
```

Cryptol's bitwise logical operators for our byte strings
are written in a somewhat C-like syntax.
Byte string concatenation is written with `#`.

The table below summarizes Cryptol's operator syntax relative to the SPHINCS+ specification.

| **Name** | **Spec syntax** | **Cryptol syntax** | **Example** |
| -------- | --------------- | ------------------ | ----------- |
| exponent | *a<sup>b</sup>* | `a ^^ b`           | `4 ^^ 3 == 64` |
| product  | *a · b* or *ab* | `a * b`            | `4 * 3 == 12` |
| integer quotient | ⌊ *a / b* ⌋ | `a / b`        | `5 / 3 == 1` |
| remainder | *a % b*        | `a % b`            | `5 % 3 == 2` |
| sum      | *a + b*         | *a + b*            | `4 + 3 == 7` |
| difference  | *a - b*      | *a - b*            | `3 - 4 == -1` |
| left shift  | *a << b* | `a << b` | `0x00ff00 << 8 == 0xff0000` |
| right shift | *a >> b* | `a >> b` | `0x00ff00 >> 8 == 0x0000ff` |
| read array at index | *A[i]* | `A @ i` | `[0x0a, 0x0b, 0x0c] @ 1 == 0x0b` |
| write array at index | *A[i] = e* | `update A i e` | `update [0x0a, 0x0b, 0x0c] 1 0xff == [0x0a, 0xff, 0x0c]` |
| read byte string at index | *X[i]* | `X ~@ i` | `0x0a0b0c ~@ 2 == 0x0c` |
| bitwise conjunction | *A* AND *B* | `A && B` | `0xffff00 && 0x00ffff == 0x00ff00` |
| bitwise exclusive disjunction | *A* XOR *B* (or *A ⊕ B*) | `A ^ B` | `0xffff00 ^ 0x00ffff == 0xff00ff` |
| concatenation | *A \|\| B* | `A # B` | `0x0123 # 0xab == 0x0123ab` |

### 2.4 Integer to Byte Conversion

Cryptol uses a type-level function parameter
to determine the length of the resulting bit string.

| **Name** | **Spec syntax** | **Cryptol syntax** | **Example** |
| -------- | --------------- | ------------------ | ----------- |
| conversion | `toByte`(*x,y*) | `(fromInteger x) : [y*8]` | `((fromInteger 255) : [3*8]) == 0x0000ff` |

This type can often be inferred from the argument value,
but it can also be written as an explicit parameter using the backtick notation:
<pre> fromInteger`{[y*8]} x </pre>

### 2.5 Strings of Base-*w* Numbers

The specified function `base_w` does two things:
splitting a byte string into an array, and truncating the array.
Since our "byte strings" are really bit strings,
and *w* is always one of three specific powers of 2,
we can just use type-level arguments to Cryptol's built-in `split` and `take`.

| **Name** | **Spec syntax** | **Cryptol syntax** | **Example** where X = 0x1234 |
| -------: | --------------- | ------------------ | ----------- |
| base   4 | `base_w(X, 4, out_len)`   | take\`{out_len} (split\`{each=2} X) | out_len = 4 ==> [0x0, 0x1, 0x0, 0x2] |
| base  16 | `base_w(X, 16, out_len)`  | take\`{out_len} (split\`{each=4} X) | out_len = 4 ==> [0x1, 0x2, 0x3, 0x4] |
| base 256 | `base_w(X, 256, out_len)` | take\`{out_len} (split\`{each=8} X) | out_len = 1 ==> [0x1234] |

Note that the value of `split`'s argument `each` is the base-2 log of the spec's function parameter `w`.

### 2.6 Member Functions

Cryptol has record types, and uses a dot syntax for accessing record components.

| **Name** | **Spec syntax** | **Cryptol syntax** | **Example** where PK = {X = 0x12, Y = 0x34} |
| -------: | --------------- | ------------------ | ----------- |
| get member | `PK.getX()`     | `PK.X`             | `PK.X == 0x12` |
| set member | `PK.setX(new_val)` | `PK' = {X = new_val, ... } ` | `PK' = {X = 0x56, Y = PK.Y}` |

Instead of destructive updates, we must construct a whole new record and give it a new name.

We treat the the WOTS+ address structures (**ADRS**) as flat byte strings,
and define explicit member functions for them in Section 2.7.3.

### 2.7 Hash Function Families

See Section 7 for the definition of specific *tweakable* hash functions,
which abstract over the implementations of SHA2 or SHAKE.

**TODO**: module parameters go here!

#### 2.7.1 Tweakable Hash Functions

The spec describes `T_l` as a function that takes a byte-string of
length `l*n`. In the pseudocode that appears later in the spec, the
argument to `T_l` is generally given as a length-`l` array of `n`-byte
strings, so we express its type accordingly.

The spec describes the seed argument to `T_l` as an `n`-byte string.
However, the spec doesn't actually depend on the representation of the
seed, so we make it into an abstract module parameter.

Translating the given function signatures:

```
parameter

  /** A seed for a tweakable hash function or pseudo-random function. */
  type Seed : *

  /** A tweakable hash function that takes an n-byte public seed, an
  address, and an n*l-byte message to produce an n-byte hash. */
  T_l : {l} (fin l) => Seed -> Address -> [l]NBytes -> NBytes

F : Seed -> Address -> NBytes -> NBytes
F seed adrs x = T_l`{1} seed adrs [x]

H : Seed -> Address -> [2]NBytes -> NBytes
H seed adrs = T_l`{2} seed adrs
```

#### 2.7.2 PRF and Message Digest

Specific pseudo-random functions will be defined (or imported?) later.
Translating their signatures, and guessing at the type constraints:

```
parameter
  /** Pseudorandom function for pseudorandom key generation. */
  PRF : Seed -> Address -> NBytes

  /** Pseudorandom function to generate randomness for message compression. */
  PRF_msg : {k} (fin k) => NBytes -> NBytes -> [k][8] -> NBytes

  // /** Keyed hash function that can process arbitrary-length messages. */
  //H_msg : {k} (fin k) => NBytes -> NBytes -> NBytes -> [k][8] -> [m][8]
  // (?) result type? Paper says "B^m" without defining m.
```

#### 2.7.3 Hash Function Address Scheme

To facilitate working with the five different types of address,
we define member access and update functions for each field,
including type checks as appropriate.

```
type Address     = [256]
type AddressWord = [32]
type TreeAddress = [96]
type TreeHeight  = [32]

WOTS_HASH  = 0 : AddressWord
WOTS_PK    = 1 : AddressWord
TREE       = 2 : AddressWord
FORS_TREE  = 3 : AddressWord
FORS_ROOTS = 4 : AddressWord

getLayer : Address -> AddressWord
getLayer = take

setLayer : AddressWord -> Address -> Address
setLayer layer adrs = layer # (take adrs)

getTree : Address -> TreeAddress
getTree adrs = take (drop`{32} adrs)

setTree : TreeAddress -> Address -> Address
setTree tree adrs = take`{32} adrs # tree # drop`{128} adrs

getType : Address -> AddressWord
getType adrs = take (drop`{128} adrs)

// Setting the type field implicitly zeros out
// the subsequent three address words
setType : AddressWord -> Address -> Address
setType typ adrs = take`{128} adrs # typ # zero

wat = error "wrong address type"

getKeyPair : Address -> AddressWord
getKeyPair adrs =
    if t == WOTS_HASH then kp
     | t == WOTS_PK   then kp
    else wat
    where
    t  = getType adrs
    kp = take (drop`{160} adrs)

setKeyPair : AddressWord -> Address -> Address
setKeyPair kp adrs =
    if t == WOTS_HASH then adrs'
     | t == WOTS_PK   then adrs'
    else wat
    where
    t     = getType adrs
    adrs' = take adrs # kp # drop`{160} adrs

getChain : Address -> AddressWord
getChain adrs =
    if getType adrs == WOTS_HASH
    then take (drop`{192} adrs)
    else wat

setChain : AddressWord -> Address -> Address
setChain chn adrs =
    if getType adrs == WOTS_HASH
    then take`{192} adrs # chn # drop adrs
    else wat

getHash : Address -> AddressWord
getHash adrs =
    if getType adrs == WOTS_HASH
    then drop`{224} adrs
    else wat

setHash : AddressWord -> Address -> Address
setHash hash adrs =
    if getType adrs == WOTS_HASH
    then take adrs # hash
    else wat

getTreeHeight : Address -> TreeHeight
getTreeHeight adrs =
    if t == FORS_TREE  then height
     | t == FORS_ROOTS then height
    else wat
    where
    t      = getType adrs
    height = take (drop`{192} adrs)

setTreeHeight : TreeHeight -> Address -> Address
setTreeHeight height adrs =
    if t == FORS_TREE  then adrs'
     | t == FORS_ROOTS then adrs'
    else wat
    where
    t     = getType adrs
    adrs' = take adrs # height # drop`{224} adrs

getTreeIndex : Address -> AddressWord
getTreeIndex adrs =
    if t == FORS_TREE  then ix
     | t == FORS_ROOTS then ix
    else wat
    where
    t  = getType adrs
    ix = drop adrs

setTreeIndex : AddressWord -> Address -> Address
setTreeIndex ix adrs =
    if t == FORS_TREE  then adrs'
     | t == FORS_ROOTS then adrs'
    else wat
    where
    t     = getType adrs
    adrs' = take adrs # ix

```


## 3. WOTS+ One-Time Signatures

This section contains the Cryptol implementations of the specified algorithms for
chaining, key generation, signing, and computing public keys.

### 3.1 WOTS+ Parameters

WOTS+ is parameterized by `n`, which is "the security parameter; it is
the message length as well as the length of a private key, public key,
or signature element in bytes." In this Cryptol version, we don't make
`n` a parameter directly, but instead use a type parameter `NBytes`
for some type representing an `n`-byte array, such as `[n][8]` or
`[n*8]`.

In the spec, the length `len1` is defined as `floor(n/log(w))`, which
(if correct) would be the number of base-`w` digits required to
represent a string of `n` bits. However, elsewhere in the spec it is
clear that a message of `n` *bytes* is supposed to be represented in
`len1` base-`w` digits. In the Cryptol version we avoid the confusion
by making `len1` a parameter, along with a function `base_w` which
converts from `NBytes` to an array of `len1` base-`w` digits.

```
parameter

  /** An array of bytes of length n, where n is the security
      parameter. A block may represent a message, private key, public
      key, or signature element. */
  type NBytes : *

  /** The number of base-w digits necessary to represent a block. */
  type len1 : #
  type constraint (fin len1, len1 >= 1)

  /** A message, usually an array of bytes of length `n`. */
  type Message : *

  /** Split a message into a sequence of `len1` base-`w` digits. */
  base_w : Message -> [len1][log_w]

  /** The base-2 log of the Winternitz parameter w. (Section 3.1) */
  type log_w : #
  type constraint (fin log_w, log_w >= 1)

  // needed for wots_PKgen
  type constraint (32 >= width len)


/** "w: the Winternitz parameter; it is an element of the set {4, 16,
    256}." (Section 3.1) */
type w = 2 ^^ log_w

/** The number of base-w digits necessary to represent the number
    `len1 * (w - 1)`. */
type len2 = width (len1 * (w - 1)) /^ log_w

/** The number of base-w digits in a WOTS+ private key, public key, or
    signature. */
type len = len1 + len2
```

The formula to compute values `len = len_1 + len2` are given in the spec
using real-valued division and logarithm operators.
We can't easily define an equivalent formula using Cryptol's integer-valued `lg2` function,
because the numerator in `len_2` would be rounded up before dividing,
losing information.
(The information lost by integer division can be recovered with the modulus operator,
but there is no equivalent of `(%)` for `lg2`.)

Parameter *w* can take only 3 values.
In the example parameter sets given in section 7.1 of the spec,
`n` takes only 3 values as well; 16, 24, or 32.

The following table gives correct values for these 9 distinct cases.

| **n** | **w** | **len** | **len1** | **len2** |
| ----: | ----- | ------- | -------- | -------- |
|  16   |    4  |   11    |     8    |     3    |
|  16   |   16  |    6    |     4    |     2    |
|  16   |  256  |    4    |     2    |     2    |
|  24   |    4  |   15    |    12    |     3    |
|  24   |   16  |    8    |     6    |     2    |
|  24   |  256  |    5    |     3    |     2    |
|  32   |    4  |   19    |    16    |     3    |
|  32   |   16  |   10    |     8    |     2    |
|  32   |  256  |    6    |     4    |     2    |

### 3.2 WOTS+ Chaining Function

Function **F** is a global parameter not yet defined.
(See Section 7.2 for concrete instances of
**F**, **H**, **H_msg**, **PRF**, and **PRF_msg**.)
Similarly, public key **PK** is not yet defined.

The return value "NULL" is used by the spec pseudocode, but never defined.
We'll assume it is intended to indicate an error.

```
chain : NBytes -> Integer -> Integer -> Seed -> Address -> NBytes
chain X i s seed adrs =
    if i + s > `w - 1 then error "spec says NULL"
                     else chain' s adrs X
    where
    chain' : Integer -> Address -> NBytes -> NBytes
    chain' s' adrs' X' =
        if s' == 0 then X'
        else chain' (s' - 1)
                    (setHash (fromInteger (i + s' - 1)) adrs')
                    (F seed adrs' X')
```

### 3.3 WOTS+ Private Key

This algorithm is not used anywhere else in the spec,
but we include a Cryptol implementation here for completeness.

The spec's pseudocode iterates over an array `sk`,
but never declares or initializes it.
We'll assume it initially contains all-zero bytestrings.

```
wots_SKgen : Seed -> Address -> [len]NBytes
wots_SKgen seed adrs =
  [ PRF seed (setChain i adrs) | i <- take`{len} [0...] ]
```

### 3.4 WOTS+ Public Key Generation

The `T_len` function in the specification's pseudocode
denotes tweakable hash function `T_l` as defined in Section 2.7.1,
instantiated at `len`.

We infer the type of a public key from the final call to `T_l`,
as the spec does not define it directly.

```
wots_PKgen : Seed -> Seed -> Address -> NBytes
wots_PKgen sk_seed pk_seed adrs =
    T_l`{len} pk_seed wotspkADRS tmp
  where
    tmp = [ mkTmp i | i <- take`{len} [0...] ]
    wotspkADRS = setKeyPair (getKeyPair adrs) (setType WOTS_PK adrs)
    mkTmp i = chain sk 0 (`w - 1) pk_seed adrs'
      where
        adrs' = setChain i adrs
        sk = PRF sk_seed adrs'
```

Similarly, where the pseudocode has `sk[i]` as the first argument to `chain`,
we have `sk`. Since `sk` is the result of a call to **PRF**,
it must be an *n*-byte string.
Function `chain` only accepts values of that type as its first argument:
a single-byte argument (denoted by `sk[i]`) does not type-check.


### 3.5 WOTS+ Signature Generation


```
wots_sign : Message -> Seed -> Seed -> Address -> [len]NBytes
wots_sign M sk_seed pk_seed adrs = sig
  where
    msg : [len1][log_w]
    msg = base_w M

    csum : [len2 * log_w]
    csum = sum [ zext (~ msg_i) | msg_i <- msg ]

    msg' : [len][log_w]
    msg' = msg # split`{parts=len2} csum // FIXME: this fails without the type application

    sig = [ mkSig i msg_i | i <- take`{len} [0...] | msg_i <- msg' ]
    mkSig i msg_i = chain sk 0 (toInteger msg_i) pk_seed adrs'
      where
        adrs' = setChain i adrs
        sk = PRF sk_seed adrs'
```


### 3.6. WOTS+ Compute Public Key from Signature

```
wots_pkFromSig : [len]NBytes -> Message -> Seed -> Address -> NBytes
wots_pkFromSig sig M pk_seed adrs =
    T_l`{len} pk_seed wotspkADRS tmp
  where
    msg : [len1][log_w]
    msg = base_w M

    csum : [len2 * log_w]
    csum = sum [ zext (~ msg_i) | msg_i <- msg ]

    msg' : [len][log_w]
    msg' = msg # split`{parts=len2} csum

    tmp : [len]NBytes
    tmp = [ mkTmp i sig_i msg_i | i <- take`{len} [0...] | sig_i <- sig | msg_i <- msg' ]

    mkTmp : [32] -> NBytes -> [log_w] -> NBytes
    mkTmp i sig_i msg_i =
        chain sig_i (toInteger msg_i) (toInteger (~ msg_i)) pk_seed adrs'
      where
        adrs' = setChain i adrs

    wotspkADRS : Address
    wotspkADRS = setKeyPair (getKeyPair adrs) (setType WOTS_PK adrs)
```


## 4. The SPHINCS+ Hypertree

### 4.1 (Fixed Input-Length) XMSS

#### 4.1.1. XMSS Parameters

```
parameter
  /** The height (number of levels - 1) of the tree. There are 2^h'
      leaves in the tree. */
  type h' : #
  type constraint (32 >= h')
```

#### 4.1.3. TreeHash (Function `treehash`)

The specification document describes `treehash` in an imperative style
using a stack of intermediate results. For the Cryptol version we
translate it into a simpler recursive functional style.

Function `treehash` has a precondition: `s` should be a multiple of
`2^^z`. All recursive calls in the Cryptol implementation maintain
this invariant.

```
treehash : Seed -> [32] -> TreeHeight -> Seed -> Address -> NBytes
treehash sk_seed s z pk_seed adrs =
    if z == 0 then
      // leaf case
      wots_PKgen sk_seed pk_seed adrs0
    else
      // internal node case
      H pk_seed adrs' [hashL, hashR]
  where
    adrs0 = setKeyPair s (setType WOTS_HASH adrs)
    adrs' = setTreeHeight z (setTreeIndex (s >> z) (setType TREE adrs))
    z' = z - 1
    hashL = treehash sk_seed s z' pk_seed adrs
    hashR = treehash sk_seed (s + (1<<z')) z' pk_seed adrs
```

#### 4.1.4. XMSS Public Key Generation (Function `xmss_PKgen`)

```
xmss_PKgen : Seed -> Seed -> Address -> NBytes
xmss_PKgen sk_seed pk_seed adrs = pk
  where pk = treehash sk_seed 0 `h' pk_seed adrs
```

#### 4.1.5. XMSS Signature

"The authentication path is an array of h′ n-byte strings. It contains
the siblings of the nodes in on the path from the used leaf to the
root. It does not contain the nodes on the path itself."

```
AUTH : Seed -> [32] -> Seed -> Address -> [h']NBytes
AUTH sk_seed idx pk_seed adrs = [ mkAuth j | j <- take`{h'} [0...] ]
  where
    mkAuth j = treehash sk_seed (k << j) j pk_seed adrs
      where k = (idx >> j) ^ 1
// TODO : convert to lhs-indexing when we add that feature to cryptol.
```

An XMSS signature is a `(len + h') * n`-byte string consisting of
  * a WOTS+ signature sig taking `len*n` bytes,
  * the authentication path AUTH for the leaf associated with the used
    WOTS+ key pair taking `h'*n` bytes.

```
type SIG_XMSS = ([len]NBytes, [h']NBytes)
```

#### 4.1.6. XMSS Signature Generation (Function `xmss_sign`)

```
xmss_sign : Message -> Seed -> [32] -> Seed -> Address -> SIG_XMSS
xmss_sign M sk_seed idx pk_seed adrs = (sig, auth)
  where
    sig : [len]NBytes
    sig = wots_sign M sk_seed pk_seed adrs

    auth : [h']NBytes
    auth = AUTH sk_seed idx pk_seed adrs
```

#### 4.1.7. XMSS Compute Public Key from Signature (Function `xmss_pkFromSig`)

```
xmss_pkFromSig : [32] -> SIG_XMSS -> Message -> Seed -> Address -> NBytes
xmss_pkFromSig idx (sig, auth) M pk_seed adrs = last nodes
  where
    adrs0 : Address
    adrs0 = setKeyPair idx (setType WOTS_HASH adrs)

    node0 : NBytes
    node0 = wots_pkFromSig sig M pk_seed adrs0

    adrs' : TreeHeight -> Address
    adrs' k = setTreeHeight k (setTreeIndex (idx >> k) (setType TREE adrs))

    nodes : [1 + h']NBytes
    nodes =
      [ node0 ] #
      [ if idx!k then H pk_seed (adrs' k) [sib, prev]
                 else H pk_seed (adrs' k) [prev, sib]
      | sib <- auth
      | prev <- nodes
      | k <- take`{h'} [0...]
      ]
```

### 4.2. HT: The Hypertee [sic]

#### 4.2.1. HT Parameters

```
parameter

  /** The number or tree layers. */
  type d : #
  type constraint (fin d, 32 >= width d)
```

#### 4.2.2. HT Key Generation (Function `ht_PKgen`)

```
ht_PKgen : Seed -> Seed -> NBytes
ht_PKgen sk_seed pk_seed = root
  where
    adrs = setTree 0 (setLayer (`d-1) zero)
    root = xmss_PKgen sk_seed pk_seed adrs
```
