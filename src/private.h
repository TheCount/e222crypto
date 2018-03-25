#ifndef E222CRYPTO_PRIVATE_H_
#define E222CRYPTO_PRIVATE_H_

#include<openssl/err.h>

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

/**
 * Initialises curve.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
Error * e222crypto_curve_init( void );

/**
 * Uninitialises curve.
 */
void e222crypto_curve_fini( void );

/**
 * Creates a libcyrpto error.
 *
 * @param msg String constant error message.
 *
 * @return A pointer to an error is returned.
 */
static inline Error * crypto_error( const char * msg ) {
	if ( msg == NULL ) {
		return error_newc( "Invalid crypto error message" );
	}
	Error * e = NULL;
	unsigned long errnum;
	while ( ( errnum = ERR_get_error() ) != 0 ) {
		if ( e == NULL ) {
			e = error_newf( "crypto: %s", ERR_error_string( errnum, NULL ) );
		} else {
			e = error_wrapf( e, "crypto: %s", ERR_error_string( errnum, NULL ) );
		}
	}
	if ( e == NULL ) {
		return error_newf( "No crypto error in queue: %s", msg );
	} else {
		return error_wrapc( e, msg );
	}
}

#endif
