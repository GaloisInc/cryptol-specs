This directory defines concrete instantiations of modes of operation for a given block cipher.

This is not intended to be exhaustive; there may be modes that can be instantiated with other ciphers than those included here. This is mainly here to provide convenient instantiations for ciphers and modes that are commonly used or particularly interesting.

At this time, this directory does not contain all the instantiations included in the repo; they're scattered in multiple locations. As modes of operation are refactored to use the `CipherInterface`, we'll aim to add or move their instantiations here.

Test vectors for these instantiations can be found in the `Primitive/Symmetric/Cipher/Block/Tests/` directory.