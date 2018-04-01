#include<openssl/rand.h>

#include"private.h"

#include"errors/errors.h"

/**
 * Required entropy in bytes.
 */
#ifndef ENTROPY_NEEDED
#define ENTROPY_NEEDED 32
#endif

Error * e222crypto_rand_init( const char * randpath ) {
	Error * e = NULL;
	if ( randpath == NULL ) {
		randpath = "/dev/random";
	}
	int rc = RAND_load_file( randpath, ENTROPY_NEEDED );
	if ( rc != ENTROPY_NEEDED ) {
		e = crypto_error( "Insufficient entropy from seed file" );
		goto noent;
	}

	return NULL;

noent:
	return e;
}

void e222crypto_rand_fini( void ) {
}
