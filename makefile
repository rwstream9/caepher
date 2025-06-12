
reverse-run:
	gcc -O3 -o reverse reverse.c
	./reverse 5 15 reversible.csv

specrule-rule:
	gcc -O3 -o specrule specrule.c
	./specrule

reverse-dedup:
	wc -l reversible.csv
	cp reversible.csv reversible-bak.csv
	uniq reversible-bak.csv > reversible.csv
	wc -l reversible.csv


test-python:
	pytest


caepher_test: caepher_test.c caepher.h
	gcc -O3 -o $@ caepher_test.c


# A convenience target to run your tests
test-caepher: caepher_test
	./caepher_test
