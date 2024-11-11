# Cryptol Specifications for ML-KEM (FIPS 203)

## Description
This directory contains the Cryptol specifications for the ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) as outlined in the final draft of FIPS 203. Although the original LaTeX files from the standard were not available during this development, the Cryptol code in this executable specification was carefully developed to closely resemble the standard.

The full specification is available at:
https://doi.org/10.6028/NIST.FIPS.203

## Requirements
- Cryptol Version: 3.2.0 or later
- Environment variable CRYPTOLPATH should contain the path to the Cryptol specs repo.

## References
- [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)
- [Known Answer Tests (KATs) for ML-KEM](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM) (produced by a third party).
- [CAVP KATs](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files).

## Testing and Correctness
The Cryptol specifications have been tested to ensure correctness. All properties related to correctness of the algorithms (such as decryption of encryption equaling identity and decoding of encoding equaling identity) pass successfully. Internal properties and other correctness checks can be run by loading any instantiation of ML-KEM and checking the docstrings (it will take some time to run, but should be less than 10 minutes) in the Cryptol REPL:
```
:load Primitive/Asymmetric/KEM/ML_KEM/Instantiations/ML_KEM512.cry
:check-docstrings
```

Also included is an `.awk` file designated to generate a Cryptol batch file that runs the known answer tests (KATs) provided by NIST and other developers. This facilicates alignment of our specs with both the published KATs and the intermediate KATs available on the NIST website. Note that most KAT files default to 999 test vectors each; you may wish to run a subset. A sample run might look like:
```bash
$ cd cryptol-specs
$ curl -O "https://raw.githubusercontent.com/post-quantum-cryptography/KAT/main/MLKEM/kat_MLKEM_512.rsp"
$ awk -f Primitive/Asymmetric/KEM/ML_KEM/Tests/kat.awk kat_MLKEM_512.rsp > kat_MLKEM_512.bat
$ cryptol -b kat_MLKEM_512.bat
Loading [...]
0
True
1
True
[...]
```
The `kat.awk` file runs ML_KEM-512 by default; to test other instantiations you will have to modify that script and download the corresponding RSPs.
