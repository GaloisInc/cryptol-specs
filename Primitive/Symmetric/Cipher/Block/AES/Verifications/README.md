Some of the properties in AES cannot be proven natively by Cryptol (or at least, the proofs are slow enough that we haven't waited to see them complete). These properties are currently:
- `mixColumnsInverts`: this property shows that the `mixColumns` and `InvMixColumns` properties are each others inverse
- `aesIsCorrect`: this property shows that the AES `encrypt` and `decrypt` functions are each others inverses.

To provide a stronger assurance case, the SAW scripts in this folder prove the `aesIsCorrect` property. A side effect of this proof is a proof that `mixColumnsInverts` is also true.

If you have a [working SAW installation](https://github.com/GaloisInc/saw-script/), version 1.3 or later, you can get assurance of these properties:
```
$ cd Primitive/Symmetric/Cipher/Block/AES/Verifications
$ saw AES128.saw

[16:08:13.949] Loading file "Primitive/Symmetric/Cipher/Block/AES/Verifications/AES128.saw"
[16:08:14.082] Verifying that cipher unrolls
[16:08:14.157] Verifying that invCipher unrolls
[16:08:14.248] Loading file "Primitive/Symmetric/Cipher/Block/AES/Verifications/Common.saw"
[16:08:14.248] Verifying that SBox unfolds
[16:08:14.529] Verifying that InvSBox unfolds
[16:08:14.747] Verifying that SBoxInv inverts SBox
[16:08:14.980] Verifying that InvSubBytes inverts SubBytes
[16:08:15.012] Verifying that InvShiftRows inverts ShiftRows
[16:08:15.028] Verifying that InvMixColumns inverts MixColumns
[16:08:15.627] Verifying that msgToState inverts stateToMsg
[16:08:15.643] Verifying that stateToMsg inverts msgToState
[16:08:15.658] Verifying that AddRoundKey is involutive
[16:08:15.674] Verifying that invCipher inverts cipher
[16:08:15.697] Verifying that decrypt inverts encrypt
```
