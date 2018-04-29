#include<assert.h>
#include<errors.h>

#include"e222crypto.h"
#include"error.h"
#include"init.h"

int main( void ) {
	init();

	Error * e = e222crypto_privkey_generate( NULL );
	assert( e != NULL );
	error_del( e );
	E222CryptoPrivkey privkey;
	e = e222crypto_privkey_generate( &privkey );
	assert_error_null( e );
	e222crypto_privkey_del( privkey );

	fini();
}
