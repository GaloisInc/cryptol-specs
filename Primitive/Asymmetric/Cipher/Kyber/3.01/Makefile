kyber.pdf: kyber.tex macros.tex specification.tex collection.bib
	pdflatex kyber.tex
	-bibtex kyber
	pdflatex kyber.tex
	pdflatex kyber.tex

.PHONY: clean

test:
	cryptol -b verify.bat

clean:
	-rm *.pdf
	-rm *.log
	-rm *.aux
	-rm *.bbl
	-rm *.blg
	-rm *.brf
	-rm *.out
