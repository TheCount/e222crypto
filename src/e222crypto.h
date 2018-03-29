#ifndef E222CRYPTO_H_
#define E222CRYPTO_H_

#include<openssl/ec.h>

#include"errors/errors.h"

/**
 * Size of serialised private key, in bytes.
 */
#define E222CRYPTO_PRIVSIZE 28

/**
 * Private key.
 *
 * Fields are private to the implementation.
 */
typedef struct {
	EC_KEY * key;
} E222CryptoPrivkey;

/**
 * Public key.
 *
 * Fields are private to the implementation.
 */
typedef struct {
	EC_KEY * key;
} E222CryptoPubkey;

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

/**
 * Serialises a private key.
 * The serialised key size is always #E222CRYPTO_PRIVSIZE bytes.
 *
 * @param privkey Private key to be serialised.
 * @param buf Pointer to buffer to serialise to.
 * 	Must be able to hold at least #E222CRYPTO_PRIVSIZE bytes.
 *
 * @return On success, a null pointer is returned.
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_privkey_out( E222CryptoPrivkey privkey, void * buf );

/**
 * Deserialises a private key.
 *
 * @param privkey Pointer to location to store deserialised key in.
 * @param buf Pointer to buffer to deserialise from.
 * 	Must point to the #E222CRYPTO_PRIVSIZE bytes of serialised key data.
 *
 * @return On success, a null pointer is returned.
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_privkey_in( E222CryptoPrivkey * privkey, const void * buf );

/**
 * Creates a public key from a private key.
 *
 * @param privkey Private key.
 * @param pubkey Pointer to location to store public key in.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_privkey_getpubkey( E222CryptoPrivkey privkey, E222CryptoPubkey * pubkey );

/**
 * Destroys a public key.
 *
 * @param pubkey Public key to be destroyed.
 */
void e222crypto_pubkey_del( E222CryptoPubkey pubkey );

#endif
