#include<assert.h>

#include"e222crypto.h"
#include"init.h"

#include"errors/errors.h"

int main( void ) {
	init();

	E222CryptoPrivkey privkey;
	Error * e = e222crypto_privkey_generate( &privkey );
	assert( e == NULL );
	E222CryptoPubkey pubkey;
	e = e222crypto_privkey_getpubkey( privkey, &pubkey );
	assert( e == NULL );

	e222crypto_pubkey_del( pubkey );
	e222crypto_privkey_del( privkey );
	fini();
}
