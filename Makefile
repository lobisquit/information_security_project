all: trial.cpp
	g++ trial.cpp -I/usr/include/pbc/ -lpbc -lgmpxx -lgmp
	./a.out
