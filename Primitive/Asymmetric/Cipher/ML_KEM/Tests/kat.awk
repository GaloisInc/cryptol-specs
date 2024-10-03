# Create a batch file from ML-KEM known answer tests
# The input is the *.rsp file.
# Example input file: https://raw.githubusercontent.com/post-quantum-cryptography/KAT/main/MLKEM/kat_MLKEM_512.rsp
#
# @copyright Galois, Inc
# @author Marios Georgiou <marios@galois.com>
#

BEGIN { print ":load ml_kem.cry" }

$1 == "count" { print "let count =", $3; print "count:Integer" }

$1 == "z" { print "let z =", "0x" $3 }

$1 == "d" { print "let d =", "0x" $3 }

$1 == "msg" { print "let msg =", "0x" $3 }

$1 == "pk" { print "let ek_expected =", "0x" $3 }

$1 == "sk" { print "let dk_expected =", "0x" $3 }

$1 == "ct" { print "let c_expected =", "0x" $3 }

$1 == "ss" { print "let K_expected =", "0x" $3 }

$1 == "ss" { print "let (ek_actual, dk_actual) = ML_KEM_KeyGen(groupBy z, groupBy d)"
             print "let (K, c_actual) = ML_KEM_Encaps(ek_actual, groupBy msg)"
             print "let K_actual = ML_KEM_Decaps(c_actual, dk_actual)"
             print "(ek_expected == join ek_actual) && (dk_expected == join dk_actual) && (c_expected == join c_actual) && (K_expected == join K_actual)"
           }
