# AEGIS Cryptol Specification

The AEGIS directory specifies the AEGIS family described in RFC 10032.
It includes authenticated encryption, MAC computation, stream generation,
ciphertext/tag encoding, regression tests, and selected correctness proofs.

The RFC is available locally as [rfc10032.pdf](rfc10032.pdf).
File links below are relative to this README; commands run from the
repository root.

## Modules

| AEAD module | Key and nonce size, each | Input block size |
|----|----|----|
| [AEGIS128L.cry](../spec/AEGIS128L.cry) | 128 bits | 32 bytes |
| [AEGIS256.cry](../spec/AEGIS256.cry) | 256 bits | 16 bytes |
| [AEGIS128X.cry](../spec/AEGIS128X.cry) | 128 bits | 32 * D bytes |
| [AEGIS256X.cry](../spec/AEGIS256X.cry) | 256 bits | 16 * D bytes |

The parallel modules use degree D. Degrees 2 and 4 implement the
corresponding X2 and X4 variants.

Additional modules:

- [Common.cry](../spec/Common.cry): shared types, constants, AES round adapter,
  and byte ordering.
- [AEGISMAC128L.cry](../spec/AEGISMAC128L.cry),
  [AEGISMAC256.cry](../spec/AEGISMAC256.cry),
  [AEGISMAC128X.cry](../spec/AEGISMAC128X.cry), and
  [AEGISMAC256X.cry](../spec/AEGISMAC256X.cry): MAC computation.
- [Stream.cry](../spec/Stream.cry): stream generation.
- [Encoding.cry](../spec/Encoding.cry): ciphertext/tag concatenation and separation.

`Common.cry` imports the repository's existing AES specification under
`Primitive/Symmetric/Cipher/Block/AES`. Run the commands below from
the repository root so these imports resolve.

## AEAD interface

Each AEAD module provides these operations:

```text
EncryptTag128 msg ad key nonce -> (ciphertext, tag)
EncryptTag256 msg ad key nonce -> (ciphertext, tag)

DecryptTag128 ciphertext tag ad key nonce -> Ok plaintext or Err "verification failed"
DecryptTag256 ciphertext tag ad key nonce -> Ok plaintext or Err "verification failed"
```

The suffix selects the tag size in bits. The module determines the key
and nonce sizes.

Messages, ciphertexts, and associated data use `Bytes n`, which means
`[n][8]`: a sequence of `n` bytes. Ciphertext has the same length as the
message. Message and associated-data lengths must each be less than
`2^^61` bytes.

Decryption returns `Result (Bytes m) AuthError`, where `m` is the ciphertext
length in bytes. Successful decryption returns `Ok plaintext`. Authentication
failure returns `Err "verification failed"`, with no plaintext value, using
the error wording from RFC Sections 3.2, 4.2, and 5.3. `Common.cry` defines
`AuthError` as `String 19` and the shared `verificationFailed` error text.
For an empty message, successful decryption returns `Ok []`.

Select the parallel degree explicitly:

```cryptol
EncryptTag128`{2} msg ad key nonce
```

### Example

Start Cryptol from the repository root:

```sh
cryptol --ignore-cryptolrc
```

Then enter:

```text
:load Primitive/Symmetric/Cipher/Authenticated/AEGIS/spec/AEGIS128X.cry
let key = 0x000102030405060708090a0b0c0d0e0f : [128]
let nonce = 0x101112131415161718191a1b1c1d1e1f : [128]
let msg = [0 .. 34] : Bytes 35
let ad = [] : Bytes 0
let sealed = EncryptTag128`{2} msg ad key nonce
DecryptTag128`{2} sealed.0 sealed.1 ad key nonce == Ok msg
DecryptTag128`{2} sealed.0 (sealed.1 ^ 1) ad key nonce == Err "verification failed"
```

The final two expressions each return `True`.

These fixed inputs are for demonstration. Encryption callers must ensure
nonce uniqueness for each key.

## MAC, stream, and encoding interfaces

Each MAC module provides:

```text
MacTag128 data key nonce -> 128-bit tag
MacTag256 data key nonce -> 256-bit tag
```

MAC input lengths are measured in bytes and must be less than `2^^61`.
Parallel MAC calls select the degree explicitly, for example:

```cryptol
MacTag256`{4} data key nonce
```

The stream functions are:

```cryptol
Stream128L`{len} key nonce
Stream256`{len} key nonce
Stream128X`{D, len} key nonce
Stream256X`{D, len} key nonce
```

Here `len` is measured in bits, and the result has type `[len]`.
The bound is `len <= 2^^64 - 8`. Stream generation encrypts zero blocks
and truncates the result without computing a final authentication tag.
Pass `zero` for the RFC's omitted-nonce case.

`Encoding.cry` provides `encode128`, `decode128`, `encode256`, and
`decode256`. Encoding places the ciphertext first, followed by the tag:
16 tag bytes for the 128-bit functions and 32 for the 256-bit functions.

Decoding only separates these fields. Authentication requires calling
the appropriate AEAD decryption function. Decoder input lengths are
constrained by their Cryptol types.

## Running verification

The commands have been checked with Cryptol 3.5.0. The proof script uses
the `w4-z3` prover and requires Z3.

From the repository root, run the regression suite:

```sh
cryptol --ignore-cryptolrc --stop-on-error --batch=Primitive/Symmetric/Cipher/Authenticated/AEGIS/tests/Regression.icry
```

Run the selected symbolic proofs:

```sh
cryptol --ignore-cryptolrc --stop-on-error --batch=Primitive/Symmetric/Cipher/Authenticated/AEGIS/tests/Proofs.icry
```

For individual regression-group results, enter:

```text
:load Primitive/Symmetric/Cipher/Authenticated/AEGIS/tests/AllTests.cry
testResults
```

All fields should be `True`.

Regression coverage includes RFC AEAD and MAC vectors, selected
intermediate states, authentication rejection cases, message and
associated-data block boundaries, stream/ciphertext consistency checks,
and concrete encoding layouts.

[Proofs.icry](../tests/Proofs.icry) contains 28 proof commands covering:

- Base block round trips and empty partial-block behavior.
- Parallel updates matching independent base updates.
- Parallel block round trips and selected partial-block lengths.
- Degree-one MAC finalization.
- Encoding round trips at selected ciphertext lengths.

These proofs quantify over the input values at the selected type
instantiations. They do not establish correctness for every message
length or parallel degree, or establish cryptographic security.

## Specification choices and scope

The parallel APIs accept degrees from 1 through 256. Regression coverage
focuses on degrees 2 and 4; degree-one MAC finalization has separate
proofs. Other degrees do not have equivalent verification coverage.

RFC Sections 5.4.3–5.4.5 apparently use `Split(input, R)` where the
128X update requires two halves. This specification splits at
`128 * D` bits, consistent with Section 5.4.6 and the checked ciphertext
vectors. This is an interpretation of an apparent typo, not a claim
of an officially confirmed erratum.

For AEGISMAC-128X with 128-bit tags, intermediate tags are packed in
pairs. At odd degrees greater than one, the current implementation
discards the final unpaired tag, following the RFC's definition of
`Split`. Degrees 2 and 4 avoid this incomplete-pair case.

Low-level finalization lengths are measured in bits. MAC finalization
uses the tag size in the second length field. Parallel MAC processing
also includes the RFC's lane-combination and finalization stages.

Empty partial-block decryption is defined as an identity operation.
Public AEAD and MAC inputs are byte sequences; stream output may have
a non-byte-aligned length.

This is a functional specification. It does not enforce nonce freshness
or model execution timing, memory erasure, or side-channel resistance.
