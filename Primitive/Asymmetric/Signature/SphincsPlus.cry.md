# SPHINCS+ in Cryptol

[SPHINCS+](https://sphincs.org) is an asymmetric hash-based signature scheme developed for the NIST post-quantum project.

This Markdown document is *literate Cryptol*,
and can be loaded like any other Cryptol module.
Cryptol only sees the contents of triple-backtick code blocks;
all other text here is strictly for human eyes.

```
module SphincsPlus where
```

The present document's heading structure follows the SPHINCS+ [specification](https://sphincs.org/data/sphincs+-specification.pdf),
and can be read as a supplement to that document.

---

## 2. Notation

This section shows the Cryptol equivalent of each basic operation used in the spec.

### 2.1 Data Types

Byte string literals are written as "0x" followed by a positive even number of hexadecimal digits,
as in `0xe534f0`.
Arrays of byte strings have uniform element length, determined by the longest element:
`[0x34, 5, 6] == [0x34, 0x05, 0x06]`.
Cryptol's built-in bit-string and array types are big-endian.

### 2.2 Functions

Cryptol doesn't have even an approximate notion of real or rational numbers,
and thus lacks *floor* and *ceiling* functions.
All the built-in operations on integer values return integers.

In particular, the base-2 logarithm returns the *ceiling* of its real-valued equivalent:
`(lg2 7, lg2 8, lg2 9) == (3, 3, 4)`.

Truncation of a bit string is accomplished with Cryptol's `take` function, writing *Trunc<sub>l</sub>(x)* as "take\`{l} x", where "l" (in bits) is the function's type-level parameter "front":
<pre>take`{16} 0x12345678 == 0x1234</pre>.

### 2.3 Operators

The usual integer operators mostly have familiar notations,
and respect the standard precedence ordering.
Note that Cryptol has no rational numbers, so `/` means integer division.

| **Name** | **Spec syntax** | **Cryptol syntax** | **Example** |
| -------- | --------------- | ------------------ | ----------- |
| exponent | *a<sup>b</sup>* | `a ^^ b`           | `4 ^^ 3 == 64` |
| product  | *a · b* or *ab* | `a * b`            | `4 * 3 == 12` |
| integer quotient | ⌊ *a / b* ⌋ | `a / b`        | `5 / 3 == 1` |
| remainder | *a % b*        | `a % b`            | `5 % 3 == 2` |
| sum      | *a + b*         | *a + b*            | `4 + 3 == 7` |
| difference  | *a - b*      | *a - b*            | `3 - 4 == -1` |

The postfix `++` increment operator from C-like languages does not exist in Cryptol,
and can't be simulated by the divergent recursive binding `let a = a + 1`,
where variable `a` is already bound.
That Cryptol expression defines an infinite integer,
which cannot be evaluated in any useful way.
Instead of a destructive update, we must use a fresh name: `let a' = a + 1`.

Cryptol's "logical" shift operators are defined on bit strings
rather than integers, a distinction not made by the spec:

| left shift  | *a << b* | `a << b` | `0x00ff00 << 8 == 0xff0000` |
| right shift | *a >> b* | `a >> b` | `0x00ff00 >> 8 == 0x0000ff` |

Array indexing is accomplished with Cryptol's infix `@` operator
rather than postfix square brackets.
Moreover, because Cryptol regards the byte strings defined above as
sequences of *bits* rather than bytes,
we define a helper function to index a whole byte.

```
byte : {n} (fin n) => [n] -> [n * 8] -> [8]
byte index bytestring = (split`{each=8} bytestring) @ index
```

| array index | *A[i]* | `A @ i` | `[0x0a, 0x0b, 0x0c] @ 1 == 0x0b` |
| byte string index | *X[i]* | `byte i X` | `byte 2 0x0a0b0c == 0x0c` |


