# README

These are the Cryptol specs of FALCON as defined in [1]. These specs are written in Literate Cryptol so that the same .tex files can:
1. Generate a PDF with Literate Cryptol in it,
1. Be executed directly by Cryptol.

The original .tex files were obtained via communication with the FALCON authors.

# Requirements

- Cryptol Version: 2.13 or later
- Environment variable CRYPTOLPATH should contain the path to the Cryptol specs repo.
- A LaTeX distribution (e.g. TeX Live, MiKTeX) installed on the system.

# Getting Started
To load the specs simply run

```
$ cryptol falcon.tex
```

# Known Issues
- The Correctness of FALCON is not currently tested.

# References
[1]. Prest, Thomas, Pierre-Alain Fouque, Jeffrey Hoffstein, Paul Kirchner, Vadim Lyubashevsky, Thomas Pornin, Thomas Ricosset, Gregor Seiler, William Whyte, and Zhenfei Zhang. "Falcon." Post-Quantum Cryptography Project of NIST (2020).
