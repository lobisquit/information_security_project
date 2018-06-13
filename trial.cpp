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

void generate_pairing_file(pairing_t pairing, uint rbits, uint qbits, uint seed) {
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

	// create conf file in buffer, suitable for PBC parameter specification
	std::stringstream conf_file;
	conf_file << "type a"           << "\n";
	conf_file << "q "      << q     << "\n";
	conf_file << "r "      << r     << "\n";
	conf_file << "h "      << h     << "\n";
	conf_file << "exp1 "   << exp1  << "\n";
	conf_file << "exp2 "   << exp2  << "\n";
	conf_file << "sign0 "  << sign0 << "\n";
	conf_file << "sign1 "  << sign1 << "\n";
	std::string pairing_setup = conf_file.str();

	pairing_init_set_buf(pairing,
						 pairing_setup.c_str(),
						 pairing_setup.length());
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

void sha256(element_t output, element_t* inputs, size_t inputs_size) {
	// setup output buffer, of length fixed by SHA256 output
	unsigned char output_buffer[SHA256_DIGEST_LENGTH];
	memset(output_buffer, '\0', SHA256_DIGEST_LENGTH);

	// compute size of buffer containing all inputs
	size_t total_length = 0;
	for (int i = 0; i < inputs_size; i++) {
		total_length += element_length_in_bytes(inputs[i]);
	}

	// collect all inputs in same buffer
	unsigned char input_buffer[total_length];
	size_t previous_ptr = 0;
	for (int i = 0; i < inputs_size; i++) {
		element_to_bytes(input_buffer + previous_ptr, inputs[i]);
		previous_ptr = element_length_in_bytes(inputs[i]);
	}

	// actually compute hash and save to output element
	sha256(output_buffer, input_buffer, total_length);
	element_from_hash(output, output_buffer, SHA256_DIGEST_LENGTH);
}

void sha256(element_t output, element_t input) {
	element_t inputs[] = {*input};
	sha256(output, inputs, 1);
}

void encode_string(element_t element, string message) {
	size_t rbits = mpz_sizeinbase(element->field->order, 2);
	size_t msg_length = message.length();

	// check string is not too long to encrypt, i.e. rbits chars
	if (msg_length * 8 > rbits) {
		stringstream ss;
		ss << "Message is too long to be transmitted: ";
		ss << msg_length * 8 << " bits";
		ss << " > rbits = " << rbits << " bits";
		throw invalid_argument(ss.str());
	}

	string padded_message = message + string(rbits/8 - msg_length, '*');
	const char* msg_c_str = padded_message.c_str();

	mpz_t msg_mpz; mpz_init(msg_mpz);
	mpz_import(msg_mpz, rbits/8, 1, sizeof(char), 0, 0, msg_c_str);

	element_set_mpz(element, msg_mpz);
}

void decode_element(string* str, element_t input) {
	mpz_t msg_mpz; mpz_init(msg_mpz);
	element_to_mpz(msg_mpz, input);

	// maximal output string size, in bytes
	uint max_output_size = (mpz_sizeinbase(msg_mpz, 2) + 7) / 8;
	char* output_buffer = (char*) malloc(sizeof(char) * max_output_size);

	size_t* count = (size_t*) malloc(sizeof(size_t));

	mpz_export(output_buffer, count, 1, sizeof(char), 1, 0, msg_mpz);
	uint rbits = mpz_sizeinbase(input->field->order, 2);
	*str = string(output_buffer, rbits/8);
}

inline std::string to_string(element_t e) {
	unsigned char data[element_length_in_bytes(e)];
	element_to_bytes(data, e);
	return std::string((char*) data);
}

inline int to_element(element_t e, std::string data) {
	unsigned char* raw_data = (unsigned char*) data.c_str();
    return element_from_bytes(e, raw_data);
}

int main(int argc, char** argv) {
	/* INIT (done by GW)
		Input:
			- random seed
		Output:
			- pairing
			- private key pub_keyGW ∈ Zr
			- public key pri_keyGW ∈ G1
			- id, pri_key for all veicoles
	*/

	// setup crypto pairing given generated specs
	uint seed = time(NULL);
	uint rbits = 512;
	uint qbits = 1024;

	pairing_t pairing;
	generate_pairing_file(pairing, rbits, qbits, seed);

	// setup G1 generator (every non-zero element
	// suits, since its order is prime)
	element_t g; element_init_G1(g, pairing);
	do { element_random(g); } while (element_is0(g));

	element_t pri_keyGW; element_init_Zr(pri_keyGW, pairing);
	element_random(pri_keyGW);

	element_t pub_keyGW; element_init_G1(pub_keyGW, pairing);
	// pub_key = g^{pri_key}
	element_pow_zn(pub_keyGW, g, pri_keyGW);

	//////////////////////////////////////////

	// do forall veicoles to manage
	// checking that they are all different
	element_t idA; element_init_G1(idA, pairing);
	element_t idB; element_init_G1(idB, pairing);
	element_random(idA);
	element_random(idB);

	element_t pri_keyA; element_init_G1(pri_keyA, pairing);
	element_t pri_keyB; element_init_G1(pri_keyB, pairing);
	// pri_key = id^{pri_keyGW}
	element_pow_zn(pri_keyA, idA, pri_keyGW);
	element_pow_zn(pri_keyB, idB, pri_keyGW);

	/* Network discovery phase (done by a veicole)
		Input:
			- real identity of veicole, id
			- Nonce n
		Output:
			- tid, temporary identity (for tx round)
			- pub_key, veicole temporary public key
	*/
	element_t nA; element_init_Zr(nA, pairing);
	element_t nB; element_init_Zr(nB, pairing);
	element_random(nA);
	element_random(nB);

	element_t tidA; element_init_G1(tidA, pairing); // <- INIT
	element_t tidB; element_init_G1(tidB, pairing);
	element_pow_zn(tidA, idA, nA); // <- INIT + refreshTID
	element_pow_zn(tidB, idB, nB);

	element_t pub_keyA; element_init_G1(pub_keyA, pairing);
	element_t pub_keyB; element_init_G1(pub_keyB, pairing);
	element_pow_zn(pub_keyA, g, nA);
	element_pow_zn(pub_keyB, g, nB);

	/* Data TX phase */

	/* Anony */

	// compute nonces
	element_t rA; element_init_Zr(rA, pairing);
	element_t rB; element_init_Zr(rB, pairing);
	element_random(rA);
	element_random(rB);

	element_t otiA; element_init_G1(otiA, pairing);
	element_t otiB; element_init_G1(otiB, pairing);
	element_pow_zn(otiA, tidA, rA);
	element_pow_zn(otiB, g, rB);

	element_t t; element_init_GT(t, pairing);
	element_pairing(t, tidB, pub_keyGW);
	element_pow_zn(t, t, rB);

	element_t tempZr; element_init_Zr(tempZr, pairing);
	sha256(tempZr, t);

	element_t paramsA; element_init_Zr(paramsA, pairing);
	element_t paramsB; element_init_Zr(paramsB, pairing);
	element_add(paramsA, rA, tempZr);
	element_add(paramsB, rB, tempZr);

	/* GenkA */
	element_t tempG1; element_init_G1(tempG1, pairing);
	element_pow_zn(tempG1, tidB, nA);

	element_t shared_key; element_init_GT(shared_key, pairing);
	element_pairing(shared_key, pri_keyA, tempG1);

	/* EncM */
	string message_str = "The quick brown fox jumps over the lazy dog";

	element_t message; element_init_Zr(message, pairing);
	encode_string(message, message_str);

	sha256(tempZr, shared_key);
	element_t cyphertext; element_init_Zr(cyphertext, pairing);
	element_add(cyphertext, message, tempZr);

	/* SignM */

	// sign both shared_key *and* message

	element_t sign; element_init_Zr(sign, pairing);
	element_t temp[2] = {*shared_key, *message};
	sha256(sign, temp, 2);

	/* B */

	/* Extr */
	element_t t_prime; element_init_GT(t_prime, pairing);
	element_pow_zn(tempG1, otiB, nB);
	element_pairing(t_prime, pri_keyB, tempG1);

	cout << "t: "
		 << ((element_cmp(t, t_prime) == 0) ? "ok" : "ERROR")
		 << "\n";

	uint t_length = element_length_in_bytes(t);
	unsigned char t_buffer[t_length];
	element_to_bytes(t_buffer, t);

	uint t_prime_length = element_length_in_bytes(t_prime);
	unsigned char t_prime_buffer[t_prime_length];
	element_to_bytes(t_prime_buffer, t_prime);

	element_t rA_prime; element_init_Zr(rA_prime, pairing);
	element_t rB_prime; element_init_Zr(rB_prime, pairing);

	sha256(tempZr, t_prime);

	// element_printf("h(t_prime) = %B\n", tempZr);

	element_sub(rA_prime, paramsA, tempZr);
	element_sub(rB_prime, paramsB, tempZr);

	cout << "rA: "
		 << ((element_cmp(rA, rA_prime) == 0) ? "ok" : "ERROR") << "\n"
		 << "rB: "
		 << ((element_cmp(rB, rB_prime) == 0) ? "ok" : "ERROR")
		 << "\n";

	element_pow_zn(tempG1, g, rB);
	cout << "otiB: "
		 << ((element_cmp(otiB, tempG1) == 0) ? "ok" : "ERROR")
		 << "\n";

	element_t tidA_prime; element_init_G1(tidA_prime, pairing);
	element_invert(tempZr, rA_prime);
	element_pow_zn(tidA_prime, otiA, tempZr);

	cout << "tidA: "
		 << ((element_cmp(tidA, tidA_prime) == 0) ? "ok" : "ERROR")
		 << "\n";

	/* GenkB */
	element_t shared_key_prime; element_init_GT(shared_key_prime, pairing);
	element_pow_zn(tempG1, tidA_prime, nB);
	element_pairing(shared_key_prime, tempG1, pri_keyB);

	sha256(tempZr, shared_key_prime);

	/* DecM */
	element_t message_prime; element_init_Zr(message_prime, pairing);
	element_sub(message_prime, cyphertext, tempZr);

	// cout << decode_element(message, message_str.length()) << "\n";
	std::string out;
	decode_element(&out, message);
	cout << out << "\n";
	decode_element(&out, message_prime);
	cout << out << "\n";

	cout << "message: "
		 << ((element_cmp(message, message_prime) == 0) ? "ok" : "ERROR")
		 << "\n";

	/* VerM */
	cout << "shared_key: "
		 << ((element_cmp(shared_key, shared_key_prime) == 0) ? "ok" : "ERROR")
		 << "\n";

	// unsigned char output_buffer[SHA256_DIGEST_LENGTH];
	element_t sign_prime; element_init_Zr(sign_prime, pairing);
	element_t temp_prime[2] = {*shared_key_prime, *message_prime};
	sha256(sign_prime, temp_prime, 2);

	cout << "sign: "
		 << ((element_cmp(sign, sign_prime) == 0) ? "ok" : "ERROR")
		 << "\n";
}
