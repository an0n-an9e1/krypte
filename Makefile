all:
	g++ main.cpp -o krypte -g -Wall

run:
	./encrypt

install:
	mv krypte /usr/bin
