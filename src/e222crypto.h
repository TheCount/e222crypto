#ifndef E222CRYPTO_H_
#define E222CRYPTO_H_

#include"errors/errors.h"

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

#endif
