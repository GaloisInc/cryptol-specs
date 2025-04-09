Symmetric ciphers that work on a block at a time.

| Scheme | [Gold standard](https://github.com/GaloisInc/cryptol-specs/wiki/Reviewing-guidelines)? | Literate |
| --- | --- | --- |
| AES | Yes | No |
| DES | | No |
| GOST | | No |
| KATAN | | No |
| LED | | No |
| McMambo | | No |
| PRESENT | | No |
| PRINCE | | No |
| SHACAL | | No |
| Simon | | No |
| Speck | | No |
| TEA | | No |
| Threefish | | No |
| TripleDES | | No |

## AES Migration Guide
In [PR #79](https://github.com/GaloisInc/cryptol-specs/pull/79), we simplified the AES modules and in doing so changed the public API used for AES.
To update to the new module structure, you may need to make changes to your cryptol specs that use AES.
The new module structure provides concrete instantiations for `AES128`, `AES192`, and `AES256`.
It also provides a spec `AES_specification` that is generic over the key size, in case you want to implement something that supports multiple key sizes.
Note that these are only the block cipher, operating over a single block at a time.
For encryption over longer plaintexts, use a mode of operation.

If you previously used `AES.cry`, you were implicitly using AES256. Update your import line to use `AES256.cry`, and update your encrypt and decrypt functions to change the name and order of arguments.
Before:
```haskell
import Primitive::Symmetric::Cipher::Block::AES
ct = aesEncrypt(data, key)
pt = aesDecrypt(ct, key)
```
After:
```haskell
import Primitive::Symmetric::Cipher::Block::AES256 as AES256
ct = AES256::encrypt key data
pt = AES256::decrypt key ct
```

If you previously used `AES_parameterized.cry`, or if you want to implement something using AES with an arbitrary key length, update your import line to use `AES_specification.cry`, parameterized
with your own key length parameter. The remaining API is unchanged, although we added a publicly accessible `KeySize` type.
Before:
```haskell
import Primitive::Symmetric::Cipher::Block::AES_parameterized as AES

parameter
  /** 0: use AES128, 1: use AES192, 2: use AES256 */
  type Mode : #
  type constraint (2 >= Mode)
```
After:
```haskell
parameter
  // This constraint enforces the standard key sizes of 128, 192, and 256 bits.
  type KeySize : #
  type constraint (fin KeySize, KeySize % 64 == 0, KeySize / 64 >= 2, KeySize / 64 <= 4)

import Primitive::Symmetric::Cipher::Block::AES::Specification as AES where
  type KeySize' = KeySize
```