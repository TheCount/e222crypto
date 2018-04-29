#include<errors.h>

#include<openssl/err.h>
#include<openssl/evp.h>

#include"private.h"

/**
 * Whether the library has been initialised before.
 */
static int initialised = 0;

Error * e222crypto_init( const char * randpath ) {
	Error * e = NULL;

	/* Sanity check */
	if ( initialised ) {
		e = error_newc( "Due to deficiencies in libcrypto, this libary can be initialised only once" );
		goto alreadyinit;
	}
	initialised = 1;

	/* Init */
	ERR_load_crypto_strings();
	e = e222crypto_threads_init();
	if ( e != NULL ) {
		goto nothreads;
	}
	e = e222crypto_rand_init( randpath );
	if ( e != NULL ) {
		goto norand;
	}
	e = e222crypto_curve_init();
	if ( e != NULL ) {
		goto nocurve;
	}

	return NULL;

	e222crypto_curve_fini();
nocurve:
	e222crypto_rand_fini();
norand:
nothreads:
	EVP_cleanup();
	ERR_free_strings();
	e222crypto_threads_fini();
alreadyinit:
	return e;
}

void e222crypto_fini( void ) {
	/* Sanity check */
	if ( !initialised ) {
		return;
	}

	/* Finalise */
	e222crypto_curve_fini();
	e222crypto_rand_fini();
	EVP_cleanup();
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();
	e222crypto_threads_fini();
}
