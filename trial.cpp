#include <fstream>
#include <iostream>

#include <gmp.h>
#include <gmpxx.h> // needed for C++ adapter
#include <pbc.h>

#include <openssl/sha.h>

using namespace std;

typedef unsigned char uchar;

inline uint to_uint(mpz_class input) {
	return mpz_get_ui(input.get_mpz_t());
}

string generate_pairing_file(uint rbits, uint qbits, uint seed) {
	bool found = false;

	mpz_class q, r, h, exp1, exp2;
	mpz_class temp;
	int sign0 = 0;
	int sign1 = 0;

	// setup randomness
	gmp_randclass rng(gmp_randinit_default);
	rng.seed(seed);

	do {
		// build Solinas prime r = 2^exp2 + sign0 2^exp1 + sign1
		r = 0;

		// pick positive or negative sign for b randomly
		// as well as exp2 value
		if (rng.get_f() < 0.5) {
			exp2 = rbits - 1;
			sign1 = 1;
		} else {
			exp2 = rbits;
			sign1 = -1;
		}

		// set r = 2^exp2
		mpz_setbit(r.get_mpz_t(), to_uint(exp2));

		// find a suitable (second) exponent index in [1, exp2)
		exp1 = rng.get_z_range(exp2 - 1) + 1;
		temp = 0;
		mpz_setbit(temp.get_mpz_t(), to_uint(exp1));

		// add or subtract temp = 2^exp1 to r according to sign1
		r = r + sign1 * temp;

		// add or subtract random sign0 = +/- 1
		sign0 = rng.get_f() < 0.5 ? 1 : -1;
		r = r + sign0;

		// r is NOT prime with probability less than 4^-50
		// so probably it is prime
		if (mpz_probab_prime_p(r.get_mpz_t(), 50)) {
			/* try to find h such that
			 * - r*h=q+1
			 * - r, q are primes
			 * - h is multiple of 12
			 */
			for (int i = 0; i < 10; i++) {
				// set temp = 2^bit as the highest possible value of h / 12
				// avoid choosing bit too small, that will lead to small h
				int bit = qbits - rbits - 4 + 1;
				temp = 0;
				mpz_setbit(temp.get_mpz_t(), bit > 3 ? bit : 3);
				h = rng.get_z_range(temp) * 12;

				q = h * r - 1;

				// assess q prime too, if so exit
				if (mpz_probab_prime_p(q.get_mpz_t(), 50)) {
					found = true;
					break; // exit for
				}
			}
		}
	} while(!found);

	// build output file name using seed as parameter
	char name_buf[50];
	sprintf(name_buf, "a-seed=%d.param", seed);

	ofstream conf_file;
	conf_file.open(name_buf);

	// create conf file, suitable for PBC parameter specification
	conf_file << "type a" << "\n";
	conf_file << "q "      << q     << "\n";
	conf_file << "r "      << r     << "\n";
	conf_file << "h "      << h     << "\n";
	conf_file << "exp1 "   << exp1  << "\n";
	conf_file << "exp2 "   << exp2  << "\n";
	conf_file << "sign0 "  << sign0 << "\n";
	conf_file << "sign1 "  << sign1 << "\n";

	conf_file.close();

	return string(name_buf);
}

mpz_class sha256(mpz_class input) {
	// initialize suitable hasher
	uchar hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	// compute against input
	string input_string = input.get_str();
	SHA256_Update(&sha256, input_string.c_str(), input_string.length());
	SHA256_Final(hash, &sha256);

	// read hash bitstream and convert to mpz_class directly
	mpz_class output;
	mpz_import(output.get_mpz_t(), sizeof(hash), 1,
			   sizeof(hash[0]), 0, 0, hash);
	return output;
}

int main (int argc, char** argv) {
	uint seed = 1;
	string output_file = generate_pairing_file(100, 200, seed);
	// cout << "'" << output_file << "'\n";

	// setup crypto pairing given generated spec
	pairing_t pairing;

	// read configuration file in a C-style buffer
	ifstream conf_file;
	conf_file.open(output_file.c_str());

	string line, content;
	while (getline(conf_file, line)) {
		content += line + "\n";
	}

	pairing_init_set_buf(pairing, content.c_str(), content.length());

	element_t P;
	element_init_G1(P, pairing);
	element_random(P);
	// element_printf("P = %B\n", P);

	mpz_class x = 11;
	cout << "input: " << x.get_str() << "\n";
	cout << hex << sha256(x) << "\n";

	// precomputed
	mpz_class other;
	other = "0x4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8";
	cout << hex << other << "\n";

}
