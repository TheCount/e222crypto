#include<assert.h>
#include<errors.h>
#include<stddef.h>

#include"e222crypto.h"
#include"error.h"
#include"init.h"

int main( void ) {
	init();

	/* Generate 2 keypairs */
	E222CryptoPrivkey privkey1, privkey2;
	E222CryptoPubkey pubkey1, pubkey2;
	Error * e = e222crypto_privkey_generate( &privkey1 );
	assert( e == NULL );
	e = e222crypto_privkey_generate( &privkey2 );
	assert( e == NULL );
	e = e222crypto_privkey_getpubkey( privkey1, &pubkey1 );
	assert( e == NULL );
	e = e222crypto_privkey_getpubkey( privkey2, &pubkey2 );
	assert( e == NULL );

	/* Hash public keys */
	char msg[2 * E222CRYPTO_PUBSIZE];
	char digest[E222CRYPTO_DGSTSIZE];
	e = e222crypto_pubkey_out( pubkey1, msg );
	assert( e == NULL );
	e = e222crypto_pubkey_out( pubkey2, msg + E222CRYPTO_PUBSIZE );
	assert( e == NULL );
	e = e222crypto_digest( sizeof( msg ), msg, digest );
	assert( e == NULL );

	/* Sign digest with both keys */
	E222CryptoSig sig1, sig2;
	e = e222crypto_sign( privkey1, digest, &sig1 );
	assert( e == NULL );
	e = e222crypto_sign( privkey2, digest, &sig2 );
	assert( e == NULL );

	/* Test signature verification */
	int result;
	e = e222crypto_verify( pubkey1, digest, sig1, &result );
	assert( e == NULL );
	assert( result == 1 );
	e = e222crypto_verify( pubkey1, digest, sig2, &result );
	assert( e == NULL );
	assert( result == 0 );
	e = e222crypto_verify( pubkey2, digest, sig1, &result );
	assert( e == NULL );
	assert( result == 0 );
	e = e222crypto_verify( pubkey2, digest, sig2, &result );
	assert( e == NULL );
	assert( result == 1 );

	/* Cleanup */
	e222crypto_privkey_del( privkey1 );
	e222crypto_privkey_del( privkey2 );
	e222crypto_pubkey_del( pubkey1 );
	e222crypto_pubkey_del( pubkey2 );
	e222crypto_sig_del( sig1 );
	e222crypto_sig_del( sig2 );
	fini();
}
