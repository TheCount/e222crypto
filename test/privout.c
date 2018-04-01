#include<assert.h>
#include<string.h>

#include"e222crypto.h"

#include"errors/errors.h"

int main( void ) {
	Error * e = e222crypto_init();
	assert( e == NULL );

	E222CryptoPrivkey privkey1;
	e = e222crypto_privkey_generate( &privkey1 );
	assert( e == NULL );
	char buf1[E222CRYPTO_PRIVSIZE];
	e = e222crypto_privkey_out( privkey1, buf1 );
	assert( e == NULL );
	E222CryptoPrivkey privkey2;
	e = e222crypto_privkey_in( &privkey2, buf1 );
	assert( e == NULL );
	char buf2[E222CRYPTO_PRIVSIZE];
	e = e222crypto_privkey_out( privkey2, buf2 );
	assert( e == NULL );
	int rc = memcmp( buf1, buf2, E222CRYPTO_PRIVSIZE );
	assert( rc == 0 );

	e222crypto_privkey_del( privkey1 );
	e222crypto_privkey_del( privkey2 );
	e222crypto_fini();
}
