#include<assert.h>

#include"e222crypto.h"
#include"init.h"

#include"errors/errors.h"

int main( void ) {
	init();

	Error * e = e222crypto_privkey_generate( NULL );
	assert( e != NULL );
	error_del( e );
	E222CryptoPrivkey privkey;
	e = e222crypto_privkey_generate( &privkey );
	assert( e == NULL );
	e222crypto_privkey_del( privkey );

	fini();
}
