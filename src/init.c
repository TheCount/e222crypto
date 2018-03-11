#include<openssl/err.h>
#include<openssl/evp.h>

#include"errors/errors.h"

Error * e222crypto_init( void ) {
	ERR_load_crypto_strings();

	return NULL;
}

void e222crypto_fini( void ) {
	EVP_cleanup();
	ERR_free_strings();
}
