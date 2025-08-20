# AES Mode of Operation Instantiations

This directory defines concrete instantiations of modes of operation for a given block cipher.

This is not intended to be exhaustive; there may be modes that can be instantiated with other ciphers than those included here. This is mainly here to provide convenient instantiations for ciphers and modes that are commonly used or particularly interesting.

At this time, this directory does not contain all the instantiations included in the repo; they're scattered in multiple locations. As modes of operation are refactored to use the `CipherInterface`, we'll aim to add or move their instantiations here.

| Mode          | AES Instantiations                                                                    |
| ------------- | ------------------------------------------------------------------------------------- |
| AES key wrap (with and without padding) | [AES-256](./AES256_KeyWrap.cry)                             |
| CBC           | [AES-128](./AES128_CBC.cry), [AES-192](./AES192_CBC.cry), [AES-256](./AES256_CBC.cry) |
| CFB           | [AES-128](./AES128_CFB.cry), [AES-192](./AES192_CFB.cry), [AES-256](./AES256_CFB.cry) |
| CTR           | [AES-128](./AES128_CTR.cry), [AES-192](./AES192_CTR.cry), [AES-256](./AES256_CTR.cry) |
| XTS           | [AES-128](./AES128_XTS.cry), [AES-256](./AES256_XTS.cry)
