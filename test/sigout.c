#include<assert.h>
#include<string.h>

#include"e222crypto.h"
#include"error.h"
#include"init.h"

#include"errors/errors.h"

int main( void ) {
	init();

	/* Create signature of a public key */
	E222CryptoPrivkey privkey;
	Error * e = e222crypto_privkey_generate( &privkey );
	assert( e == NULL );
	E222CryptoPubkey pubkey;
	e = e222crypto_privkey_getpubkey( privkey, &pubkey );
	assert( e == NULL );
	char keybuf[E222CRYPTO_PUBSIZE];
	e = e222crypto_pubkey_out( pubkey, keybuf );
	assert( e == NULL );
	char digest[E222CRYPTO_DGSTSIZE];
	e = e222crypto_digest( sizeof( keybuf ), keybuf, digest );
	assert( e == NULL );
	E222CryptoSig sig;
	e = e222crypto_sign( privkey, digest, &sig );
	assert( e == NULL );

	/* Test serialisation */
	char sigbuf1[E222CRYPTO_SIGSIZE];
	e = e222crypto_sig_out( sig, sigbuf1 );
	assert( e == NULL );
	E222CryptoSig sigtest;
	e = e222crypto_sig_in( &sigtest, sigbuf1 );
	assert( e == NULL );
	int result;
	e = e222crypto_verify( pubkey, digest, sigtest, &result );
	assert( e == NULL );
	assert( result == 1 );
	char sigbuf2[E222CRYPTO_SIGSIZE];
	e = e222crypto_sig_out( sigtest, sigbuf2 );
	assert( e == NULL );
	result = memcmp( sigbuf1, sigbuf2, E222CRYPTO_SIGSIZE );
	assert( result == 0 );

	/* Cleanup */
	e222crypto_privkey_del( privkey );
	e222crypto_pubkey_del( pubkey );
	e222crypto_sig_del( sig );
	e222crypto_sig_del( sigtest );
	fini();
}
