#include<assert.h>

#include"e222crypto.h"

#include"errors/errors.h"

int main( void ) {
	Error * e = e222crypto_init();
	assert( e == NULL );

	E222CryptoPrivkey privkey;
	e = e222crypto_privkey_generate( &privkey );
	assert( e == NULL );
	E222CryptoPubkey pubkey;
	e = e222crypto_privkey_getpubkey( privkey, &pubkey );
	assert( e == NULL );

	e222crypto_pubkey_del( pubkey );
	e222crypto_privkey_del( privkey );
	e222crypto_fini();
}
