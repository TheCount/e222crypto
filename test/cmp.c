#include<assert.h>

#include"e222crypto.h"

#include"errors/errors.h"

static void test_privcmpfail( E222CryptoPrivkey privkey1, E222CryptoPrivkey privkey2, int * result ) {
	Error * e = e222crypto_privkey_cmp( privkey1, privkey2, result );
	assert( e != NULL );
	error_del( e );
}

static void test_pubcmpfail( E222CryptoPubkey pubkey1, E222CryptoPubkey pubkey2, int * result ) {
	Error * e = e222crypto_pubkey_cmp( pubkey1, pubkey2, result );
	assert( e != NULL );
	error_del( e );
}

int main( void ) {
	Error * e = e222crypto_init();
	assert( e == NULL );

	/* Generate keys */
	E222CryptoPrivkey privnull, privkey1, privkey2;
	E222CryptoPubkey pubnull, pubkey1, pubkey2;
	privnull.key = NULL;
	pubnull.key = NULL;
	e = e222crypto_privkey_generate( &privkey1 );
	assert( e == NULL );
	e = e222crypto_privkey_getpubkey( privkey1, &pubkey1 );
	assert( e == NULL );
	e = e222crypto_privkey_generate( &privkey2 );
	assert( e == NULL );
	e = e222crypto_privkey_getpubkey( privkey2, &pubkey2 );
	assert( e == NULL );
	int result;

	/* Test private key comparison */
	test_privcmpfail( privnull, privnull, NULL );
	test_privcmpfail( privnull, privnull, &result );
	test_privcmpfail( privnull, privkey2, NULL );
	test_privcmpfail( privnull, privkey2, &result );
	test_privcmpfail( privkey1, privnull, NULL );
	test_privcmpfail( privkey1, privnull, &result );
	test_privcmpfail( privkey1, privkey2, NULL );
	e = e222crypto_privkey_cmp( privkey1, privkey2, &result );
	assert( e == NULL );
	assert( result != 0 );
	e = e222crypto_privkey_cmp( privkey1, privkey1, &result );
	assert( e == NULL );
	assert( result == 0 );
	e222crypto_privkey_del( privkey2 );
	char privbuf[E222CRYPTO_PRIVSIZE];
	e = e222crypto_privkey_out( privkey1, privbuf );
	assert( e == NULL );
	e = e222crypto_privkey_in( &privkey2, privbuf );
	assert( e == NULL );
	e = e222crypto_privkey_cmp( privkey1, privkey2, &result );
	assert( e == NULL );
	assert( result == 0 );

	/* Test public key comparison */
	test_pubcmpfail( pubnull, pubnull, NULL );
	test_pubcmpfail( pubnull, pubnull, &result );
	test_pubcmpfail( pubnull, pubkey2, NULL );
	test_pubcmpfail( pubnull, pubkey2, &result );
	test_pubcmpfail( pubkey1, pubnull, NULL );
	test_pubcmpfail( pubkey1, pubnull, &result );
	test_pubcmpfail( pubkey1, pubkey2, NULL );
	e = e222crypto_pubkey_cmp( pubkey1, pubkey2, &result );
	assert( e == NULL );
	assert( result != 0 );
	e = e222crypto_pubkey_cmp( pubkey1, pubkey1, &result );
	assert( e == NULL );
	assert( result == 0 );
	e222crypto_pubkey_del( pubkey2 );
	char pubbuf[E222CRYPTO_PUBSIZE];
	e = e222crypto_pubkey_out( pubkey1, pubbuf );
	assert( e == NULL );
	e = e222crypto_pubkey_in( &pubkey2, pubbuf );
	assert( e == NULL );
	e = e222crypto_pubkey_cmp( pubkey1, pubkey2, &result );
	assert( e == NULL );
	assert( result == 0 );

	/* Cleanup */
	e222crypto_privkey_del( privkey1 );
	e222crypto_privkey_del( privkey2 );
	e222crypto_pubkey_del( pubkey1 );
	e222crypto_pubkey_del( pubkey2 );
	e222crypto_fini();
}
