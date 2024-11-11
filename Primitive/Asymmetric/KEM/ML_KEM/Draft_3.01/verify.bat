// @copyright Galois Inc
// @author Marios Georgiou <marios@galois.com>

:l kyber.tex

:set tests=3

:! printf "\nRunning 'check' commands for concatPlusCorrect property\n\n"
:check concatPlusCorrect`{x=4, y=4}

:! printf "\nRunning 'prove' commands for concatPlusCorrect property\n\n"
:prove concatPlusCorrect`{x=0, y=0}
:prove concatPlusCorrect`{x=1, y=1}
:prove concatPlusCorrect`{x=4, y=4}
:prove concatPlusCorrect`{x=16, y=16}
:prove concatPlusCorrect`{x=32, y=32}

:! printf "\nRunning 'prove' command for rounding property\n\n"
:prove rounding

:! printf "\nRunning 'prove' command for CorrectnessCompress property\n\n"
:prove CorrectnessCompress

:! printf "\nRunning 'prove' command for QMinusOne property\n\n"
:prove QMinusOne

:! printf "\nRunning 'exhaust' command for Is256thRootOfq property\n\n"
:exhaust Is256thRootOfq

:! printf "\nRunning 'prove' command for CorrectnessNTT property\n\n"
:prove CorrectnessNTT

:! printf "\nRunning 'prove' command for TestMult property\n\n"
:prove TestMult

:! printf "\nRunning 'prove' command for CorrectnessEncodeBytes' property\n\n"
:prove CorrectnessEncodeBytes'

:! printf "\nRunning 'prove' command for CorrectnessEncodeBytes property\n\n"
:prove CorrectnessEncodeBytes

:! printf "\nRunning 'check' command for CorrectnessEncodeDecode' property\n\n"
:check CorrectnessEncodeDecode'

:! printf "\nRunning 'check' command for CorrectnessEncodeDecode property\n\n"
:check CorrectnessEncodeDecode

:! printf "\nRunning 'check' command for CorrectnessPKE property\n\n"
:check CorrectnessPKE

:! printf "\nRunning 'check' command for CorrectnessKEM property\n\n"
:check CorrectnessKEM
