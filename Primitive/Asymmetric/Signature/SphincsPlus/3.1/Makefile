sphincs.pdf: sphincs.tex
	pdflatex sphincs.tex
	-bibtex sphincs
	pdflatex sphincs.tex
	pdflatex sphincs.tex

.PHONY: clean

clean:
	-rm *.pdf
	-rm *.log
	-rm *.aux
	-rm *.out
