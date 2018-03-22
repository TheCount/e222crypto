#include<openssl/err.h>
#include<openssl/evp.h>

#include"private.h"

#include"errors/errors.h"

Error * e222crypto_init( void ) {
	Error * e = NULL;
	ERR_load_crypto_strings();
	e = e222crypto_threads_init();
	if ( e != NULL ) {
		goto nothreads;
	}

	return NULL;

nothreads:
	EVP_cleanup();
	ERR_free_strings();
	return e;
}

void e222crypto_fini( void ) {
	EVP_cleanup();
	ERR_free_strings();
	e222crypto_threads_fini();
}
