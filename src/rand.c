#include<errors.h>
#include<limits.h>

#include<openssl/rand.h>

#include"private.h"

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

Error * e222crypto_rand( size_t n, void * buf ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( n > INT_MAX ) {
		e = error_newc( "Too many bytes requested" );
		goto badparm;
	}
	if ( ( buf == NULL ) && ( n > 0 ) ) {
		e = error_newc( "Null buffer pointer supplied" );
		goto badparm;
	}

	/* Make random bytes */
	int rc = RAND_bytes( buf, n );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to produce random bytes" );
	}

badparm:
	return e;
}
