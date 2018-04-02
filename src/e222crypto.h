#ifndef E222CRYPTO_H_
#define E222CRYPTO_H_

#include<openssl/bn.h>
#include<openssl/ec.h>
#include<openssl/ecdsa.h>

#include"errors/errors.h"

/**
 * Size of serialised private key, in bytes.
 */
#define E222CRYPTO_PRIVSIZE 28

/**
 * Size of serialised public key, in bytes.
 */
#define E222CRYPTO_PUBSIZE 28

/**
 * Digest size in bytes.
 */
#define E222CRYPTO_DGSTSIZE 28

/**
 * Size of serialised signature, in bytes.
 */
#define E222CRYPTO_SIGSIZE 56

/**
 * Private key.
 *
 * Fields are private to the implementation.
 */
typedef struct {
	EC_KEY * key;
	BIGNUM * kinv;
	BIGNUM * rp;
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
 * Signature.
 *
 * Fields are private to the implementation.
 */
typedef struct {
	ECDSA_SIG * sig;
} E222CryptoSig;

/**
 * Initialises the E-222 crypto library.
 *
 * @param randpath Path to a file containing a random number generator seed,
 * 	or a null pointer. If the latter, a default random source will be used.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_init( const char * randpath );

/**
 * Uninitialises the E-222 crypto library.
 */
void e222crypto_fini( void );

/**
 * Uninitialises thread-specific data.
 * Should be called by each thread right before exiting.
 * Must be called before #e222crypto_fini().
 */
void e222crypto_thread_fini( void );

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
 * Compares two private keys.
 *
 * @param privkey1 First private key.
 * @param privkey2 Second private key.
 * @param result Pointer to location to store result.
 *
 * @return On success, a null pointer is returned.
 * 	A non-zero value is stored in @c *result if and only if
 * 	the two provided keys are different.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_privkey_cmp( E222CryptoPrivkey privkey1, E222CryptoPrivkey privkey2, int * result );

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

/**
 * Compares two public keys.
 *
 * @param pubkey1 First public key.
 * @param pubkey2 Second public key.
 * @param result Pointer to location to store result.
 *
 * @return On success, a null pointer is returned.
 * 	A non-zero value is stored in @c *result if and only if
 * 	the two provided keys are different.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_pubkey_cmp( E222CryptoPubkey pubkey1, E222CryptoPubkey pubkey2, int * result );

/**
 * Serialises a public key.
 * The serialised key size is always #E222CRYPTO_PUBSIZE bytes.
 *
 * @param pubkey Public key to be serialised.
 * @param buf Pointer to buffer to serialise to.
 * 	Must be able to hold at least #E222CRYPTO_PUBSIZE bytes.
 *
 * @return On success, a null pointer is returned.
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_pubkey_out( E222CryptoPubkey pubkey, void * buf );

/**
 * Deserialises a public key.
 *
 * @param pubkey Pointer to location to store deserialised key in.
 * @param buf Pointer to buffer to deserialise from.
 * 	Must point to the #E222CRYPTO_PUBSIZE bytes of serialised key data.
 *
 * @return On success, a null pointer is returned.
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_pubkey_in( E222CryptoPubkey * pubkey, const void * buf );

/**
 * Digests a message.
 *
 * @param msglen Message length in bytes.
 * @param msg Pointer to message.
 * @param dgst Pointer to location to store the #E222CRYPTO_DGSTSIZE bytes of digest.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_digest( size_t msglen, const void * msg, void * dgst );

/**
 * Signs a digest using a private key.
 *
 * @param privkey Private key used to sign.
 * @param digest Pointer to digest of #E222CRYPTO_DGSTSIZE bytes length.
 * @param sig Pointer to location where signature can be stored.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_sign( E222CryptoPrivkey privkey, const void * digest, E222CryptoSig * sig );

/**
 * Verifies a digest signature using a public key.
 *
 * @param pubkey Public key used to verify.
 * @param digest Pointer to digest of #E222CRYPTO_DGSTSIZE bytes length.
 * @param sig Signature to verify.
 * @param result Pointer to location where the result can be stored.
 *
 * @return If an error occurs during the verification process,
 * 	a pointer to an error is returned.\n
 * 	Otherwise, if the signature verification succeeds,
 * 	a null pointer is returned,
 * 	and a non-zero value is stored in @c *result.\n
 * 	Otherwise, a null pointer is returned,
 * 	and zero is stored in @c *result.
 */
Error * e222crypto_verify( E222CryptoPubkey pubkey, const void * digest, E222CryptoSig sig, int * result );

/**
 * Destroys a signature.
 *
 * @param sig Signature.
 */
void e222crypto_sig_del( E222CryptoSig sig );

/**
 * Serialises a signature.
 *
 * @param sig Signature.
 * @param buf Pointer to buffer to serialise signature into.
 * 	Must be able to hold at least #E222CRYPTO_SIGSIZE bytes.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_sig_out( E222CryptoSig sig, void * buf );

/**
 * Deserialises a signature.
 *
 * @param sig Pointer to location to store signature in.
 * @param buf Pointer to buffer to deserialise from.
 * 	Must point to #E222CRYPTO_SIGSIZE bytes of serialised signature data.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_sig_in( E222CryptoSig * sig, const void * buf );

#endif
