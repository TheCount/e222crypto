#include<assert.h>

#include"e222crypto.h"

#include"errors/errors.h"

int main( void ) {
	Error * e = e222crypto_init();
	assert( e == NULL );

	e = e222crypto_privkey_generate( NULL );
	assert( e != NULL );
	error_del( e );
	E222CryptoPrivkey privkey;
	e = e222crypto_privkey_generate( &privkey );
	assert( e == NULL );
	e222crypto_privkey_del( privkey );

	e222crypto_fini();
}
