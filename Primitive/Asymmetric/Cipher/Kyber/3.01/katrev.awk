# Create a batch file from Kyber known answer tests for decryption
# The input is the *.rsp file.

BEGIN { print ":load kyber512.cry" }

$1 == "count" { print "let count =", $3; print "count:Integer" }

$1 == "sk" { print "let sk =", "0x" $3 }

$1 == "ct" { print "let ct =", "0x" $3 }

$1 == "ss" { print "0x" $3
             print "BytesToBits (map reverse (take`{32} (CDec (groupBy`{8} ct, groupBy`{8} sk))))"
           }
