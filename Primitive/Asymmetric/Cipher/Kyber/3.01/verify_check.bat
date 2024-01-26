:l kyber.tex

:set tests=3

:! printf "\nRunning 'check' commands for concatPlusCorrect property\n\n"
:check concatPlusCorrect`{x=4, y=4}

:! printf "\nRunning 'check' command for CorrectnessEncodeDecode' property\n\n"
:check CorrectnessEncodeDecode'

:! printf "\nRunning 'check' command for CorrectnessEncodeDecode property\n\n"
:check CorrectnessEncodeDecode

:! printf "\nRunning 'check' command for CorrectnessPKE property\n\n"
:check CorrectnessPKE

:! printf "\nRunning 'check' command for CorrectnessKEM property\n\n"
:check CorrectnessKEM
