:load ntt.cry
:! printf "\nProve the base NTT is correct.\n"
:prove ntt_correct
:! printf "\n\nProve the connection with naive ntt "
:! printf "and recursive ntt is correct.\n"
:! printf "\nProve the NTT agrees with naive NTT.\n"
:prove fntt_correct
:! printf "\nProve the inv NTT agrees with naive inv NTT.\n"
:prove fivntt_correct
:! printf "\nProve the NTT is correct.\n"
:prove ffivntt_correct
