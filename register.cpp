#include "variables.h"
#include "u2f_hid.h"
#include "utils.h"
#include <uECC.h>
#include <sha256.h>
#include "keys.h"

void handle_register()
{
	// validate that req_data_len == 64
	int req_data_len = (message[4] << 16) | (message[5] << 8) | message[6];
	if (req_data_len != 64)
	{
		data_len = 2;
		message[0] = (SW_WRONG_LENGTH >> 8) & 0xFF;
		message[1] = SW_WRONG_LENGTH & 0xFF;
		send_response();
		return;
	}

	// yubico's key wrapping algorithm
	// https://www.yubico.com/blog/yubicos-u2f-key-wrapping/

	// STEP 1: get the challenge parameter and application parameter from the message

	// STEP 2: generate a random nonce of 16 bytes

	// STEP 3: use the application param and random nonce and run them through hmac-sha256 using the master key
	// the output is the private key

	// STEP 4: compute the public key from the private key
	// initialize the public key as an array with length 65, and add the 0x04 byte at the beginning because uECC_compute_public_key doesn't

	// STEP 5: run the application param and the newly generated private key and run them through hmac-sha256 again, using the same master key
	// the result is the MAC used in the key handle

	// STEP 6: start building the response message
	// can initialize an `idx` to store our current index

	// A reserved byte [1 byte], which for legacy reasons has the value 0x05.

	// A user public key [65 bytes].

	// A key handle length byte [1 byte], which specifies the length of the key handle

	// A key handle, made up of the random nonce and the MAC

	// An attestation certificate

	// a signature [variable length, 71-73 bytes]. This is a ECDSA signature (on P-256) over the following byte string:

	// STEP 6.1: create a hash of the signature data
	// to generate a signature, we first hash it with sha256, then use the uECC_sign function

	// A byte reserved for future use [1 byte] with the value 0x00.

	// The application parameter [32 bytes] from the registration request message.

	// The challenge parameter [32 bytes] from the registration request message.

	// The above key handle, which is the nonce + MAC

	// The above user public key [65 bytes].

	// get the hash

	// STEP 6.2: sign the hash with the private key from the attestation certificate

	// STEP 6.3: put signature in correct format

	// STEP 7: set the message length, to be used in the send_response function

	// STEP 8: change the leds to blue and wait for user interaction

	// STEP 9: send the response
}