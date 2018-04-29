#include<assert.h>
#include<errors.h>

#include"e222crypto.h"
#include"error.h"
#include"init.h"

int main( void ) {
	init();

	E222CryptoPrivkey privkey;
	Error * e = e222crypto_privkey_generate( &privkey );
	assert_error_null( e );
	E222CryptoPubkey pubkey;
	e = e222crypto_privkey_getpubkey( privkey, &pubkey );
	assert_error_null( e );

	e222crypto_pubkey_del( pubkey );
	e222crypto_privkey_del( privkey );
	fini();
}
