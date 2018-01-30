#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <gmp.h>
#include <gmpxx.h> // needed for C++ adapter
#include <math.h>
#include <pbc.h>

#include <openssl/sha.h>

using namespace std;

inline uint to_uint(mpz_class input) {
	return mpz_get_ui(input.get_mpz_t());
}

string generate_pairing_file(uint rbits, uint qbits, uint seed) {
	bool found = false;

	mpz_class q, r, h, exp1, exp2;
	mpz_class temp;
	int sign0;
	int sign1;

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
			/* try ten times to find h such that
			 * - r * h = q + 1
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

void sha256(unsigned char output[SHA256_DIGEST_LENGTH],
			unsigned char* input, size_t input_length) {
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, input, input_length);
	SHA256_Final(output, &sha256);
}

void sha256(mpz_class* output, mpz_class input) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	string input_str = input.get_str();
	sha256( hash,
			(unsigned char*) input_str.c_str(),
			input_str.length() );

	// read hash bitstream and convert to mpz_class directly
	mpz_import(output->get_mpz_t(), sizeof(hash), 1,
			   sizeof(hash[0]), 0, 0, hash);
}

void sha256(element_t output, element_t input) {
	// setup output buffer, of length fixed by SHA256 output
	unsigned char output_buffer[SHA256_DIGEST_LENGTH];
	memset(output_buffer, '\0', SHA256_DIGEST_LENGTH);

	// read input and save it to buffer
	uint input_length = element_length_in_bytes(input);
	unsigned char input_buffer[input_length];
	element_to_bytes(input_buffer, input);

	// actually compute hash and save to output element
	sha256(output_buffer, input_buffer, input_length);
	element_from_hash(output, output_buffer, 64);
}

void setup_pairing(pairing_t pairing, string pairing_file) {
	ifstream conf_stream;
	conf_stream.open(pairing_file.c_str());

	// collect all file content
	string line, content;
	while (getline(conf_stream, line)) {
		content += line + "\n";
	}
	conf_stream.close();

	pairing_init_set_buf(pairing, content.c_str(), content.length());
}

uint encode_string(element_t element, string message) {
	size_t rbits = mpz_sizeinbase(element->field->order, 2);

	const char* msg_c_str = message.c_str();
	size_t msg_length = message.length();

	// check string is not too long to encrypt, i.e. rbits chars
	if (msg_length * sizeof(msg_c_str[0]) * 8 > rbits) {
		stringstream ss;
		ss <<  "Message is too long to be transmitted: ";
		ss << msg_length * sizeof(msg_c_str[0]) * 8 << " bits";
		ss << " > rbits = " << rbits << " bits";
		throw invalid_argument(ss.str());
	}

	mpz_t msg_mpz; mpz_init(msg_mpz);
	mpz_import(msg_mpz, msg_length, 1, sizeof(msg_c_str[0]), 0, 0, msg_c_str);

	element_set_mpz(element, msg_mpz);

	return msg_length;
}

string decode_element(element_t input, uint message_length) {
	mpz_t msg_mpz; mpz_init(msg_mpz);
	element_to_mpz(msg_mpz, input);

	// maximal output string size, in bits
	uint max_output_size = (mpz_sizeinbase(msg_mpz, 2) + 7) / 8;
	char* output = (char*) malloc(sizeof(char) * max_output_size);
	size_t* count = (size_t*) malloc(sizeof(size_t));
	mpz_export(output, count, 1, sizeof(char), 1, 0, msg_mpz);

	return string(output, message_length);
}

int main(int argc, char** argv) {
	uint seed = 1;
	uint rbits = 512;
	uint qbits = 200;
	string output_filename = generate_pairing_file(rbits, qbits, seed);

	pairing_t pairing;
	setup_pairing(pairing, output_filename);

	element_t a; element_init_G1(a, pairing);
	element_t b; element_init_G1(b, pairing);
	element_random(a);
	element_random(b);

	element_t alpha; element_init_Zr(alpha, pairing);
	element_t beta; element_init_Zr(beta, pairing);
	element_random(alpha);
	element_random(beta);

	element_t r1; element_init_GT(r1, pairing);
	element_t r2; element_init_GT(r2, pairing);

	// left term
	element_t tempZr; element_init_Zr(tempZr, pairing);
	element_mul(tempZr, alpha, beta);
	element_pairing(r1, a, b);
	element_pow_zn(r1, r1, tempZr);

	// right term
	element_t a_power; element_init_G1(a_power, pairing);
	element_t b_power; element_init_G1(b_power, pairing);
	element_pow_zn(a_power, a, alpha);
	element_pow_zn(b_power, b, beta);

	element_pairing(r2, a_power, b_power);

	element_printf("r1 = %B\n", r1);
	element_printf("r2 = %B\n", r2);
}
