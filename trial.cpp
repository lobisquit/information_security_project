#include <fstream>
#include <iostream>

#include <gmp.h>
#include <gmpxx.h> // needed for C++ adapter
#include <pbc.h>

using namespace std;

typedef unsigned int uint;

inline uint to_uint(mpz_class input) {
	return mpz_get_ui(input.get_mpz_t());
}

void generate_pairing_file(unsigned int rbits, unsigned int qbits, unsigned int seed) {
	bool found = false;

	mpz_class q, r, h;

	mpz_class exp1 = 0;
	mpz_class exp2 = 0;
	uint sign0 = 0;
	uint sign1 = 0;

	// setup randomness
	gmp_randclass rng(gmp_randinit_default);
	rng.seed(seed);

	do {
		// build Solinas prime starting from 0
		// r = 2^exp2 + sign0 2^b + sign1
		r = 0;

		// pick positive or negative sign for b randomly
		if (rng.get_f() < 0.5) {
			exp2 = rbits - 1;
			sign1 = 1;
		} else {
			exp2 = rbits;
			sign1 = -1;
		}

		// r = 2^exp2
		mpz_setbit(r.get_mpz_t(), to_uint(exp1));

		q = 0;
		// find a suitable exponent index in [2, exp2)
		mpz_class temp = rng.get_z_range(exp2 - 1);
		exp1 = temp + 1;
		mpz_setbit(q.get_mpz_t(), to_uint(exp2));

		r = r + sign1 * q;

		sign0 = rng.get_f() < 0.5 ? 1 : -1;
		r = r + sign0;

		// enstablish wheather r is NOT prime
		// with probability less than 4^-50
		if (mpz_probab_prime_p(r.get_mpz_t(), 50)) {
			for (int i=0; i<10; i++) {
				// set q = 2^bit
				q = 0;
				int bit = qbits - rbits - 4 + 1;
				mpz_setbit(q.get_mpz_t(), bit >= 3 ? bit : 3);

				// randomly build q, given h
				h = rng.get_z_range(q) * 12;
				q = h * r - 1;

				// assess q prime too
				if (mpz_probab_prime_p(q.get_mpz_t(), 50)) {
					found = true;
					break;
				}
			}
		}
	} while(!found);

	// build output file name using seed as parameter
	char name_buf[50];
	sprintf(name_buf, "a-seed=%d.param", seed);

	ofstream conf_file;
	conf_file.open(name_buf);

	// create conf file, suitable for PBC parameter
	// specification
	conf_file << "type a" << "\n";
	conf_file << "q "      << q     << "\n";
	conf_file << "r "      << r     << "\n";
	conf_file << "h "      << h     << "\n";
	conf_file << "exp1 "   << exp1  << "\n";
	conf_file << "exp2 "   << exp2  << "\n";
	conf_file << "sign0 "  << sign0 << "\n";
	conf_file << "sign1 "  << sign1 << "\n";

	conf_file.close();
}


int main(int argc, char** argv) {
	gmp_randclass rng(gmp_randinit_default);
	rng.seed(time(NULL));
	mpf_class number = rng.get_f();
	std::cout << number << "\n";

	generate_pairing_file(100, 200, 1);
}
