#include <iostream>

#include <gmp.h>
#include <gmpxx.h> // needed for C++ adapter
// #include <pbc.h>

int main(int argc, char** argv) {
	gmp_randclass rng(gmp_randinit_default);
	rng.seed(time(NULL));
	mpf_class number = rng.get_f();
	std::cout << number << "\n";
}
