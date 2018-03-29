#include<assert.h>

#include"e222crypto.h"

#include"errors/errors.h"

int main( void ) {
	Error * e = e222crypto_init();
	assert( e == NULL );

	E222CryptoPrivkey privkey;
	e = e222crypto_privkey_generate( &privkey );
	assert( e == NULL );
	char buf[E222CRYPTO_PRIVSIZE];
	e = e222crypto_privkey_out( privkey, buf );
	assert( e == NULL );
	e222crypto_privkey_del( privkey );
	e = e222crypto_privkey_in( &privkey, buf );
	assert( e == NULL );
	e222crypto_privkey_del( privkey );

	e222crypto_fini();
}
