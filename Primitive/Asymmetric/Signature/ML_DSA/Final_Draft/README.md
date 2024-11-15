# Dilithium Final Draft

DilithiumParameterized.cry contains Algorithms 1-36 of the FIPS204 final draft.
Dilithium2.cry, Dilithium3.cry, Dilithium4.cry are the 3 different parameter
sets that use DilithiumParameterized.cry. The code is well commented. There are
also numerous properties that check.

Running `make` in this directory will check all the properties in the
DilithiumParameterized.cry for each parameter set. The last property for each
parameter set checks that keygen, sign, and verify are correct.  This property
will take quite a few minutes to run.

Note: It is possible that randomly checking the properties may never actually
run the code being tested as correct.  This is because the randomly generated
inputs must meet specific constraints, and if it doesn't the result is
automatically true.
