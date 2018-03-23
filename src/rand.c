#include<openssl/rand.h>

#include"private.h"

#include"errors/errors.h"

/**
 * Required entropy in bytes.
 */
#ifndef ENTROPY_NEEDED
#define ENTROPY_NEEDED 32
#endif

Error * e222crypto_rand_init( void ) {
	Error * e = NULL;
	int rc = RAND_load_file( "/dev/random", ENTROPY_NEEDED );
	if ( rc != ENTROPY_NEEDED ) {
		e = error_newc( "Insufficient entropy from /dev/random" );
		goto noent;
	}

	return NULL;

noent:
	return e;
}

void e222crypto_rand_fini( void ) {
}
