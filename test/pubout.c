#include<assert.h>
#include<string.h>

#include"e222crypto.h"
#include"error.h"
#include"init.h"

#include"errors/errors.h"

int main( void ) {
	init();

	E222CryptoPrivkey privkey;
	Error * e = e222crypto_privkey_generate( &privkey );
	assert_error_null( e );
	E222CryptoPubkey pubkey1;
	e = e222crypto_privkey_getpubkey( privkey, &pubkey1 );
	assert_error_null( e );
	char buf1[E222CRYPTO_PUBSIZE];
	e = e222crypto_pubkey_out( pubkey1, buf1 );
	assert_error_null( e );
	E222CryptoPubkey pubkey2;
	e = e222crypto_pubkey_in( &pubkey2, buf1 );
	assert_error_null( e );
	char buf2[E222CRYPTO_PUBSIZE];
	e = e222crypto_pubkey_out( pubkey2, buf2 );
	assert( e == 0 );
	int rc = memcmp( buf1, buf2, E222CRYPTO_PUBSIZE );
	assert( rc == 0 );

	e222crypto_pubkey_del( pubkey1 );
	e222crypto_pubkey_del( pubkey2 );
	e222crypto_privkey_del( privkey );
	fini();
}	
