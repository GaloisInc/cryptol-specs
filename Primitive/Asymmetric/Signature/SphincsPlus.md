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

Translating the given function signatures:

<pre>
T_l : {l, n} (fin n, fin l, Arith n, Arith l) =>
      [n*8] -> [32*8] -> [l*n*8] -> [n*8]
//   PK.seed    ADRS        M        md
F = T_l`{1}
H = T_l`{2}
</pre>

#### 2.7.2 PRF and Message Digest

Specific pseudo-random functions will be defined (or imported?) later.
Translating their signatures, and guessing at the type constraints:

<pre>
PRF : {n} (fin n) => [n] -> [32] -> [n]

PRF_msf : {n, x} (fin n) => [n] -> [n] -> [x] -> [n]

H_msg : {n, x, m} (fin n, fin m) => [n] -> [n] -> [n] -> [x] -> [m]
</pre>

#### 2.7.3 Hash Function Address Scheme

To facilitate working with the five different types of address,
we define member access and update functions for each field,
including type checks as appropriate.

```
type Address     = [256]
type AddressWord = [32]
type TreeAddress = [96]

WOTS_HASH  = 0 : AddressWord
WOTS_PK    = 1 : AddressWord
TREE       = 2 : AddressWord
FORS_TREE  = 3 : AddressWord
FORS_ROOTS = 4 : AddressWord

getLayer : Address -> AddressWord
getLayer = take

setLayer : Address -> AddressWord -> Address
setLayer adrs layer = layer # (take adrs)

getTree : Address -> TreeAddress
getTree adrs = take (drop`{32} adrs)

setTree : Address -> TreeAddress -> Address
setTree adrs tree = take`{32} adrs # tree # drop`{128} adrs

getType : Address -> AddressWord
getType adrs = take (drop`{128} adrs)

// Setting the type field implicitly zeros out
// the subsequent three address words
setType : Address -> AddressWord -> Address
setType adrs typ = take`{128} adrs # typ # zero

wat = error "wrong address type"

getKeyPair : Address -> AddressWord
getKeyPair adrs =
    if t == WOTS_HASH then kp
     | t == WOTS_PK   then kp
    else wat
    where
    t  = getType adrs
    kp = take (drop`{160} adrs)

setKeyPair : Address -> AddressWord -> Address
setKeyPair adrs kp =
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

setChain : Address -> AddressWord -> Address
setChain adrs chn =
    if getType adrs == WOTS_HASH
    then take`{192} adrs # chn # drop adrs
    else wat

getHash : Address -> AddressWord
getHash adrs =
    if getType adrs == WOTS_HASH
    then drop`{224} adrs
    else wat

setHash : Address -> AddressWord -> Address
setHash adrs hash =
    if getType adrs == WOTS_HASH
    then take adrs # hash
    else wat

getTreeHeight : Address -> AddressWord
getTreeHeight adrs =
    if t == FORS_TREE  then height
     | t == FORS_ROOTS then height
    else wat
    where
    t      = getType adrs
    height = take (drop`{192} adrs)

setTreeHeight : Address -> AddressWord -> Address
setTreeHeight adrs height =
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

setTreeIndex : Address -> AddressWord -> Address
setTreeIndex adrs ix =
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

```
// TODO: make these into type-level module parameters
//       and adjust type signatures as needed

(n : Integer, w : Integer) = (24, 16) 

// TODO: All these will have to be available at type level
(len : Integer, len1 : Integer, len2 : Integer) =
    if (n, w) == (16,   4) then (11,  8, 3)
     | (n, w) == (16,  16) then ( 6,  4, 2)
     | (n, w) == (16, 256) then ( 4,  2, 2)
     | (n, w) == (24,   4) then (15, 12, 3)
     | (n, w) == (24,  16) then ( 8,  6, 2)
     | (n, w) == (24, 256) then ( 5,  3, 2)
     | (n, w) == (32,   4) then (19, 16, 3)
     | (n, w) == (32,  16) then (10,  8, 2)
     | (n, w) == (32, 256) then ( 6,  4, 2)
     else error "unsupported n or w parameter"
```

### 3.2 WOTS+ Chaining Function

Function **F** is a global parameter not yet defined.
(See Section 7.2 for concrete instances of
**F**, **H**, **H_msg**, **PRF**, and **PRF_msg**.)
Similarly, public key **PK** is not yet defined.

The return value "NULL" is used by the spec pseudocode, but never defined.
We'll assume it is intended to indicate an error.

```
// TODO: Replace with parameterized F
F : {k} (fin k) => [k] -> Address -> [k] -> [k]
F _ _ x = x

// TODO: Replace with actual private key structure,
//       make n a module parameter
type NBytes = [24*8]
type Seed = NBytes
type Pk = { seed : Seed }
pk = ({ seed = zero } : Pk)

chain : NBytes -> Integer -> Integer -> Seed -> Address -> NBytes
chain X i s seed adrs =
    if i + s > w - 1 then error "spec says NULL"
                     else chain' s adrs X
    where
    chain' : Integer -> Address -> NBytes -> NBytes
    chain' s' adrs' X' =
        if s' == 0 then X'
        else chain' (s' - 1)
                    (setHash adrs' (fromInteger (i + s' - 1)))
                    (F pk.seed adrs' X')
```

### 3.3 WOTS+ Private Key

This algorithm is not used anywhere else in the spec,
but we include a Cryptol implementation here for completeness.

The spec's pseudocode iterates over an array `sk`,
but never declares or initializes it.
We'll assume it initially contains all-zero bytestrings.

```
// TODO: Replace with parameterized PRF
PRF : Seed -> Address -> NBytes
PRF s _ = s

// TODO: replace [8] with type parameter [len]
//       and use demoted value in body
wots_SKgen : Seed -> Address -> [8]NBytes
wots_SKgen seed adrs =
    kgen 0 adrs zero
    where
    kgen i address sk =
        if i >= fromInteger len then sk
        else kgen (i + 1) (setChain address i)
                  (update sk i (PRF seed address))

```

### 3.4 WOTS+ Public Key Generation

The `T_len` function in the specification's pseudocode
denotes tweakable hash function `T_l` as defined in Section 2.7.1,
instantiated at `len`.

We infer the type of a public key from the final call to `T_len`,
as the spec does not define it directly.

In the pseudocode, the last argument of that call, `tmp`,
is clearly a length-`len` array of *n*-byte strings,
although the signature of `T_l` specifies a single flat bytestring.
We respect that signature, and amend the pseudocode algorithm,
by joining the array before passing it to `T_len`.

```
// TODO: Replace with parameterized T_l
// T_len : [n*8] -> [32*8] -> [len*n*8] -> [n*8]
// T_len : [24*8] -> [32*8] -> [8*24*8] -> [24*8]
T_len : Seed -> Address -> [8*24*8] -> NBytes
T_len x _ _ = x

// TODO: use demoted `len and `w values
wots_PKgen : Seed -> Seed -> Address -> NBytes
wots_PKgen sk_seed pk_seed adrs =
    T_len pk_seed wotspkADRS tmp
    where
    tmp = join (mkTmp 0 zero)
    wotspkADRS = setKeyPair (setType adrs WOTS_PK) (getKeyPair adrs)
    mkTmp i tmp' =
        if i >= fromInteger len then tmp'
        else mkTmp (i + 1) (update tmp' i tmp_i)
        where
        tmp_i = chain sk 0 (w - 1) pk_seed adrs'
        adrs' = setChain adrs i
        sk = PRF sk_seed adrs'
```

Similarly, where the pseudocode has `sk[i]` as the first argument to `chain`,
we have `sk`. Since `sk` is the result of a call to **PRF**,
it must be an *n*-byte string.
Function `chain` only accepts values of that type as its first argument:
a single-byte argument (denoted by `sk[i]`) does not type-check.
