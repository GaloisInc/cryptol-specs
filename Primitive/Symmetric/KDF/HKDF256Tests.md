```cryptol
module Primitive::Symmetric::KDF::HKDF256Tests where

import Primitive::Symmetric::KDF::HKDF256
```

### A.1. Test Case 1 

Basic test case with SHA-256

```cryptol
/**
 * ```repl
 * :prove test1
 * ```
 */
test1 : Bit
test1 = result where
  IKM  = split 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b // (22 octets)
  salt = split 0x000102030405060708090a0b0c                   // (13 octets)
  info = split 0xf0f1f2f3f4f5f6f7f8f9                         // (10 octets)
  //L    = 42 L will be inferred by the length of OKM
  PRK  = split ( 0x077709362c2e32df0ddc3f0dc47bba63 
               # 0x90b6c73bb50f9c3122ec844ad7c2b3e5)
                                                              // (32 octets)
  OKM  = split ( 0x3cb25f25faacd57a90434f64d0362f2a
               # 0x2d2d0a90cf1a5a4c5db02d56ecc4c5bf 
               # 0x34007208d5b887185865 )                     // (42 octets)
  PRKc = PRK == HKDF_Extract salt IKM
  OKMc = OKM == HKDF_Expand PRK info
  result = PRKc /\ OKMc
```

### A.2. Test Case 2 

Test with SHA-256 and longer inputs/outputs

```cryptol
/**
 * ```repl
 * :prove test2
 * ```
 */
test2 : Bit
test2 = result where
  IKM  = split ( 0x000102030405060708090a0b0c0d0e0f
               # 0x101112131415161718191a1b1c1d1e1f
               # 0x202122232425262728292a2b2c2d2e2f
               # 0x303132333435363738393a3b3c3d3e3f
               # 0x404142434445464748494a4b4c4d4e4f)  // (80 octets) 
  salt = split ( 0x606162636465666768696a6b6c6d6e6f
               # 0x707172737475767778797a7b7c7d7e7f
               # 0x808182838485868788898a8b8c8d8e8f
               # 0x909192939495969798999a9b9c9d9e9f
               # 0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf)  // (80 octets)
  info = split ( 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
               # 0xc0c1c2c3c4c5c6c7c8c9cacbcccdcecf
               # 0xd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
               # 0xe0e1e2e3e4e5e6e7e8e9eaebecedeeef
               # 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff)  // (10 octets)
  //L    = 82 L will be inferred by the length of OKM
  PRK  = split ( 0x06a6b88c5853361a06104c9ceb35b45c
               # 0xef760014904671014a193f40c15fc244)  // (32 octets)
  OKM  = split ( 0xb11e398dc80327a1c8e7f78c596a4934
               # 0x4f012eda2d4efad8a050cc4c19afa97c
               # 0x59045a99cac7827271cb41c65e590e09
               # 0xda3275600c2f09b8367793a9aca3db71
               # 0xcc30c58179ec3e87c14c01d5c1f3434f
               # 0x1d87)                              // (82 octets)
  PRKc = PRK == HKDF_Extract salt IKM
  OKMc = OKM == HKDF_Expand PRK info
  result = PRKc /\ OKMc
```
