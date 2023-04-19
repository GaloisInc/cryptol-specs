# README

These are the Cryptol specs of SPHINCS+ as defined in [1]. Version 3.1 of the specs is written in Literate Cryptol so that the same .tex files can:
1. Generate a PDF with Literate Cryptol in it,
1. Be executed directly by Cryptol.

The original .tex files were obtained via communication with the SPHINCS+ authors.

# Requirements

- Cryptol Version: 2.12
- Environment variable CRYPTOLPATH should contain the path to the Cryptol specs repo.
- A LaTeX distribution (e.g. TeX Live, MiKTeX) installed on the system.

# Getting Started
To load the specs simply run

```
$ cd 3.1
$ cryptol sphincs.tex
```

# References
[1]. Bernstein, Daniel J., Andreas Hülsing, Stefan Kölbl, Ruben Niederhagen, Joost Rijneveld, and Peter Schwabe. "The SPHINCS+ signature framework." In Proceedings of the 2019 ACM SIGSAC conference on computer and communications security, pp. 2129-2146. 2019.

# Note for Later Cryptol Version
To make the specs compatible with the new module system of Cryptol 2.13+, some type variable declarations need to be moved from the parameterized module to the top module.