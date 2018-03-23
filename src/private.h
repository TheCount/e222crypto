#ifndef E222CRYPTO_PRIVATE_H_
#define E222CRYPTO_PRIVATE_H_

#include"errors/errors.h"

/**
 * Initialises thread support for libcrypto.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_threads_init( void );

/**
 * Uninitialises thread support for libcrypto.
 */
void e222crypto_threads_fini( void );

/**
 * Initialises random number generation support for libcrypto.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_rand_init( void );

/**
 * Uninitialises random number generation support for libcrypto.
 */
void e222crypto_rand_fini( void );

#endif
