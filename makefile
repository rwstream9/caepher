
reverse-run:
	gcc -O3 -o reverse reverse.c
	./reverse 5 15 reversible.csv

reverse-dedup:
	wc -l reversible.csv
	cp reversible.csv reversible-bak.csv
	uniq reversible-bak.csv > reversible.csv
	wc -l reversible.csv


test-python:
	pytest


test-caepher:
	gcc -O3 -o caepher_test caepher_test.c
	./caepher_test
