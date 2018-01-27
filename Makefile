all: trial.cpp
	g++ -std=c++98 trial.cpp -I/usr/include/pbc/ -lpbc -lgmpxx -lgmp -lcrypto
	./a.out

tags:
	./ctags-generator.sh
