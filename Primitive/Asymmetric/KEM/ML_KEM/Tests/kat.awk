# Create a batch file from ML-KEM known answer tests
# The input is the *.rsp file.
# Example input file: https://raw.githubusercontent.com/post-quantum-cryptography/KAT/main/MLKEM/kat_MLKEM_512.rsp
#
# @copyright Galois, Inc
# @author Marios Georgiou <marios@galois.com>
#

BEGIN { print ":load Primitive/Asymmetric/KEM/ML_KEM/Instantiations/ML_KEM512.cry" }

$1 == "count" { print "let count =", $3; print "count:Integer" }

$1 == "z" { print "let z =", "0x" $3 }

$1 == "d" { print "let d =", "0x" $3 }

$1 == "msg" { print "let msg =", "0x" $3 }

$1 == "pk" { print "let ek_expected =", "0x" $3 }

$1 == "sk" { print "let dk_expected =", "0x" $3 }

$1 == "ct" { print "let c_expected =", "0x" $3 }

$1 == "ss" { print "let K_expected =", "0x" $3 }

$1 == "ss" { print "let (ek_actual, dk_actual) = KeyGen (Some (groupBy d)) (Some (groupBy z))"
             print "let (K, c_actual) = Encaps ek_actual (Some (groupBy msg))"
             print "let K_actual = Decaps dk_actual c_actual"
             print "(ek_expected == join ek_actual) && (dk_expected == join dk_actual) && (c_expected == join c_actual) && (K_expected == join K_actual)"
           }
