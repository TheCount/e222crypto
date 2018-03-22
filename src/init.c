#include<openssl/err.h>
#include<openssl/evp.h>

#include"private.h"

#include"errors/errors.h"

/**
 * Whether the library has been initialised before.
 */
static int initialised = 0;

Error * e222crypto_init( void ) {
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

	return NULL;

nothreads:
	EVP_cleanup();
	ERR_free_strings();
alreadyinit:
	return e;
}

void e222crypto_fini( void ) {
	/* Sanity check */
	if ( !initialised ) {
		return;
	}

	/* Finalise */
	EVP_cleanup();
	ERR_free_strings();
	e222crypto_threads_fini();
}
