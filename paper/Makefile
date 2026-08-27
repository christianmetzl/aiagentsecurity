# Build the preprint PDF. Requires a TeX Live install (pdflatex).
# Embedded bibliography (thebibliography) -> no bibtex step needed; run twice for refs.
MAIN=main

.PHONY: all clean
all: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex
	pdflatex -interaction=nonstopmode -halt-on-error $(MAIN).tex
	pdflatex -interaction=nonstopmode -halt-on-error $(MAIN).tex

clean:
	rm -f $(MAIN).aux $(MAIN).log $(MAIN).out $(MAIN).pdf
