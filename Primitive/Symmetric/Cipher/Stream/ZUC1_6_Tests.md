# ZUC Algorithm Specification: Implementor's Test Data

## Welcome

This document is a literate [Cryptol](https://cryptol.net/) document. This means that if you install
Cryptol from the website you can run ```cryptol ZUC1_6_Tests.md``` in your terminal and all of the
definitions will be typecheck, and the test cases can be run.

All text in this document is directly from the
[ZUC Test Data](https://www.gsma.com/security/wp-content/uploads/2019/05/eea3eia3testdatav11.pdf).


## 3 ZUC

```cryptol
module Primitive::Symmetric::Cipher::Stream::ZUC1_6_Tests where

import Primitive::Symmetric::Cipher::Stream::ZUC1_6
```

### 3.1 Overview

The test data sets presented here are for the ZUC stream cipher algorithm.

### 3.2 Format

Each test set starts by showing the input and output data values.

This is followed by a table showing the state of the LFSR at the beginning of the computation.

Then for the first 10 steps of the initialization the content of X0,X1,X2,X3,R1,R2 is given in a
table. Steps are indexed by *t* (for "time").

Then the state of the LFSR and the nonlinear function F at the end of the initialization is given.

For the first 3 steps of keystream generation X0,X1,X2,X3,R1,R2 are given in a table.

### 3.3 Test Set 1

```cryptol
property test1 = KeyLoad key iv == sKeyLoad
              /\ InitializeStage key iv == (sAfterInit, RAfterInit)
              /\ take (WorkStage (sAfterInit, RAfterInit)) == [z1, z2]
    where
        key = 0x00000000000000000000000000000000
        iv  = 0x00000000000000000000000000000000
        R0 = zero : [2][32]
        z1 = 0x27bede74
        z2 = 0x018082da
        sKeyLoad = map drop [ 0x0044d700, 0x0026bc00, 0x00626b00, 0x00135e00
                            , 0x00578900, 0x0035e200, 0x00713500, 0x0009af00
                            , 0x004d7800, 0x002f1300, 0x006bc400, 0x001af100
                            , 0x005e2600, 0x003c4d00, 0x00789a00, 0x0047ac00
                            ] : LFSR
        sAfterInit = map drop [ 0x7ce15b8b, 0x747ca0c4, 0x6259dd0b, 0x47a94c2b
                              , 0x3a89c82e, 0x32b433fc, 0x231ea13f, 0x31711e42
                              , 0x4ccce955, 0x3fb6071e, 0x161d3512, 0x7114b136
                              , 0x5154d452, 0x78c69a74, 0x4f26ba6b, 0x3e1b8d6a
                              ] : LFSR
        RAfterInit = [ 0x14cfd44c, 0x8c6de800 ]
```

### 3.4 Test Set 2

```cryptol
property test2 = KeyLoad key iv == sKeyLoad
              /\ InitializeStage key iv == (sAfterInit, RAfterInit)
              /\ take (WorkStage (sAfterInit, RAfterInit)) == [z1, z2]
    where
        key = 0xffffffffffffffffffffffffffffffff
        iv  = 0xffffffffffffffffffffffffffffffff
        z1 = 0x0657cfa0
        z2 = 0x7096398b
        R0 = zero : [2][32]
        sKeyLoad = map drop [ 0x7fc4d7ff, 0x7fa6bcff, 0x7fe26bff, 0x7f935eff
                            , 0x7fd789ff, 0x7fb5e2ff, 0x7ff135ff, 0x7f89afff
                            , 0x7fcd78ff, 0x7faf13ff, 0x7febc4ff, 0x7f9af1ff
                            , 0x7fde26ff, 0x7fbc4dff, 0x7ff89aff, 0x7fc7acff
                            ] : LFSR
        sAfterInit = map drop [ 0x09a339ad, 0x1291d190, 0x25554227, 0x36c09187
                              , 0x0697773b, 0x443cf9cd, 0x6a4cd899, 0x49e34bd0
                              , 0x56130b14, 0x20e8f24c, 0x7a5b1dcc, 0x0c3cc2d1
                              , 0x1cc082c8, 0x7f5904a2, 0x55b61ce8, 0x1fe46106
                              ] : LFSR
        RAfterInit = [ 0xb8017bd5, 0x9ce2de5c ]
```

### 3.5 Test Set 3

```cryptol
property test3 = KeyLoad key iv == sKeyLoad
              /\ InitializeStage key iv == (sAfterInit, RAfterInit)
              /\ take (WorkStage (sAfterInit, RAfterInit)) == [z1, z2]
    where
        key = 0x3d4c4be96a82fdaeb58f641db17b455b
        iv  = 0x84319aa8de6915ca1f6bda6bfbd8c766
        z1  = 0x14f1c272
        z2  = 0x3279c419
        R0 = zero : [2][32]
        sKeyLoad = map drop [ 0x1ec4d784, 0x2626bc31, 0x25e26b9a, 0x74935ea8
                            , 0x355789de, 0x4135e269, 0x7ef13515, 0x5709afca
                            , 0x5acd781f, 0x47af136b, 0x326bc4da, 0x0e9af16b
                            , 0x58de26fb, 0x3dbc4dd8, 0x22f89ac7, 0x2dc7ac66
                            ] : LFSR
        sAfterInit = map drop [ 0x10da5941, 0x5b6acbf6, 0x17060ce1, 0x35368174
                              , 0x5cf4385a, 0x479943df, 0x2753bab2, 0x73775d6a
                              , 0x43930a37, 0x77b4af31, 0x15b2e89f, 0x24ff6e20
                              , 0x740c40b9, 0x026a5503, 0x194b2a57, 0x7a9a1cff
                              ] : LFSR
        RAfterInit = [ 0x860a7dfa, 0xbf0e0ffc ]
```

### 3.6 Test Set 4

```cryptol
property test4 = KeyLoad key iv == sKeyLoad
              /\ InitializeStage key iv == (sAfterInit, RAfterInit)
              /\ (keystream@@[0..1] # [keystream@1999]) == [z1, z2, z2000]
    where
        key = 0x4d320bfad4c285bfd6b8bd00f39d8b41
        iv  = 0x52959daba0bf176ece2dc315049eb574
        z1  = 0xed4400e7
        z2  = 0x0633e5c5
        z2000 = 0x7a574cdb
        sKeyLoad = map drop [ 0x26c4d752, 0x1926bc95, 0x05e26b9d, 0x7d135eab
                            , 0x6a5789a0, 0x6135e2bf, 0x42f13517, 0x5f89af6e
                            , 0x6b4d78ce, 0x5c2f132d, 0x5eebc4c3, 0x001af115
                            , 0x79de2604, 0x4ebc4d9e, 0x45f89ab5, 0x20c7ac74
                            ] : LFSR
        sAfterInit = map drop [ 0x1f808882, 0x4fc08639, 0x246a9891, 0x1f77c16f
                              , 0x50f0e1c9, 0x723e8fac, 0x24334616, 0x4471b734
                              , 0x7dba1992, 0x25180096, 0x4637117c, 0x2a92aac8
                              , 0x7da8d7b5, 0x58f45afe, 0x42814800, 0x56d7e7d8
                              ] : LFSR
        RAfterInit = [ 0x52761a25, 0x38f712e1 ]
        keystream = WorkStage (sAfterInit, RAfterInit)
```

## Backwards Compatibility

Test vectors from the original ZUC implementation are included to ensure backwards compatibility is
maintained.

```cryptol
property ZUC_TestVectors =
    t1 /\ t2 /\ t3 /\ t4
    where
      t1 = take (ZUC zero    zero   ) == [0x27BEDE74, 0x018082DA]
      t2 = take (ZUC (~zero) (~zero)) == [0x0657CFA0, 0x7096398B]
      t3 = take (ZUC (join [ 0x3D, 0x4C, 0x4B, 0xE9, 0x6A, 0x82, 0xFD, 0xAE
                           , 0xB5, 0x8F, 0x64, 0x1D, 0xB1, 0x7B, 0x45, 0x5B
                           ])
                     (join [ 0x84, 0x31, 0x9A, 0xA8, 0xDE, 0x69, 0x15, 0xCA
                           , 0x1F, 0x6B, 0xDA, 0x6B, 0xFB, 0xD8, 0xC7, 0x66
                           ])) == [0x14F1C272, 0x3279C419]
      t4 = take ks # [ks @ 1999] == [0xED4400E7, 0x0633E5C5, 0x7A574CDB]
        where
          ks = ZUC (join [ 0x4D, 0x32, 0x0B, 0xFA, 0xD4, 0xC2, 0x85, 0xBF
                         , 0xD6, 0xB8, 0xBD, 0x00, 0xF3, 0x9D, 0x8B, 0x41
                         ])
                   (join [ 0x52, 0x95, 0x9D, 0xAB, 0xA0, 0xBF, 0x17, 0x6E
                         , 0xCE, 0x2D, 0xC3, 0x15, 0x04, 0x9E, 0xB5, 0x74
                         ])
```
