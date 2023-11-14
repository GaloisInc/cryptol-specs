:l Dilithium2.cry

:set tests=3
:! printf "\nRunning 'check' on properties for Dilithium2\n\n"

:! printf "\nRunning 'check' commands for bitIntegerCorrect property\n\n"
:check bitIntegerCorrect`{a=10}

:! printf "\nRunning 'check' commands for bitsToBytesCorrect property\n\n"
:check bitsToBytesCorrect`{e=10}

:! printf "\nRunning 'check' command for simpleBitPackUnpackCorrect property\n\n"
:check simpleBitPackUnpackCorrect

:! printf "\nRunning 'check' command for bitPackUnpackCorrect property\n\n"
:check bitPackUnpackCorrect

:! printf "\nRunning 'check' command for hintBitPackUnpackCorrect property\n\n"
:check hintBitPackUnpackCorrect

:! printf "\nRunning 'check' command for pkEncodeDecodeCorrect property\n\n"
:check pkEncodeDecodeCorrect

:! printf "\nRunning 'check' command for skEncodeDecodeCorrect property\n\n"
:check skEncodeDecodeCorrect

:! printf "\nRunning 'check' command for sigEncodeDecodeCorrect property\n\n"
:check sigEncodeDecodeCorrect

:! printf "\nRunning 'check' command for nttCorrect property\n\n"
:check nttCorrect

:set tests=1

:! printf "\nRunning 'check' command for dilithiumCorrect property"
:! printf "\nThis will take a little bit, should finish in a couple of min"
:! printf "\nOnly doing one test\n"
:check dilithiumCorrect`{mbytes = 100}

