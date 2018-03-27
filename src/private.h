#ifndef E222CRYPTO_PRIVATE_H_
#define E222CRYPTO_PRIVATE_H_

#include<openssl/err.h>

#include"errors/errors.h"

/**
 * @name Curve parameters
 *
 * @{
 */
#define CURVE_P "6739986666787659948666753771754907668409286105635143120275902562187"
#define CURVE_A "6037904722330612037347300253863771452949985469631482378579961985046"
#define CURVE_B "4345107145139729851165951216281809689009227269489322585521626174657"
/** @} */

/**
 * @name Generator parameters
 *
 * @{
 */
#define GEN_X "3931658888959468303388939700190362806572083561620500153494276564283"
#define GEN_Y "4026804752437888347627536236100168036813172966796522253886677796639"
#define ORDER "1684996666696914987166688442938726735569737456760058294185521417407"
/** @} */

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
