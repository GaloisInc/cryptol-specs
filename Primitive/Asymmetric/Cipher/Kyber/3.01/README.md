# README

These are the Cryptol specs of Crystals Kyber as defined in [1]. These specs are written in Literate Cryptol so that the same .tex files can:
1. Generate a PDF with Literate Cryptol in it,
1. Be executed directly by Cryptol.

The original .tex files were obtained via communication with the Crystals Kyber authors.

# Requirements

- Cryptol Version: 2.12 or later
- Environment variable CRYPTOLPATH should contain the path to the Cryptol specs repo.
- A LaTeX distribution (e.g. TeX Live, MiKTeX) installed on the system.

# Getting Started
To build the PDF, run `make` in the command line. To check the properties, run `make test`.

# References
[1]. Avanzi, R., Bos, J., Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schanck, J.M., Schwabe, P., Seiler, G. and Stehlé, D., 2017. Crystals-kyber. NIST, Tech. Rep.