#ifndef E222CRYPTO_H_
#define E222CRYPTO_H_

#include<openssl/ec.h>

#include"errors/errors.h"

/**
 * Private key.
 *
 * Fields are private to the implementation.
 */
typedef struct {
	EC_KEY * key;
} E222CryptoPrivkey;

/**
 * Initialises the E-222 crypto library.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_init( void );

/**
 * Uninitialises the E-222 crypto library.
 */
void e222crypto_fini( void );

/**
 * Generates a new private key.
 *
 * @param privkey Pointer to location to store generated key in.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_privkey_generate( E222CryptoPrivkey * privkey );

/**
 * Destroys a private key.
 *
 * @param privkey Private key to be destroyed.
 */
void e222crypto_privkey_del( E222CryptoPrivkey privkey );

#endif
