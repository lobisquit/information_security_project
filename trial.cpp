#include <iostream>

#include <gmp.h>
#include <gmpxx.h> // needed for C++ adapter
#include <pbc.h>

int main(int argc, char** argv) {
	// cannot construct with string directly, lol
	// only assignment works
	mpz_class integ, other;
	integ = 100;
	other = "10";

	std::cout << (integ + other) << "\n";

	// need to pre-multiply and assign, otherwise does
	// not work (laziness probably for performance)
	integ = integ * 2;
	gmp_printf("Integer %Zd\n", integ.get_mpz_t());
}
