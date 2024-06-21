:l AES_GCM.cry

:prove AES_GCM_test_vector_0
:prove AES_GCM_test_vector_1
:prove AES_GCM_test_vector_2
:prove AES_GCM_test_vector_3
:prove AES_GCM_test_vector_4
:prove AES_GCM_invalid_test_vector

// The following checks do not really provide any significant formal
// verification because they check so little of the sample space.
// They each take a long time to `:prove` and would likely require
// manual modification to prove in a reasonable amount of time.

// These properties can be checked manually; one of the APIs calls the other.
// They take more than an hour to `:prove`.
:check aesGcmDecryptionApisAreEquivalent
:check aesGcmEncryptionApisAreEquivalent

// This property is independent of the type parameters but we have to specify
// them anyway.
// It takes more than 25 minutes to `:prove`.
:check dotAndMultAreEquivalent `{K=128, IV=96, AAD=0, T=128} {E=AES::encrypt}

// Make sure that decryption is the inverse of encryption
// This property takes more than 20 minutes to `:prove`.
// It's also spot-checked in the test vectors
:check aesGcmIsSymmetric