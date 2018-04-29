#ifndef E222CRYPTO_TEST_ERROR_H_
#define E222CRYPTO_TEST_ERROR_H_

#include<assert.h>
#include<errors.h>
#include<stddef.h>

static inline void assert_error_null( Error * e ) {
	if ( e == NULL ) {
		return;
	}
	error_frender( "Error: ", e, "\n", stderr );
	assert( "Error not null" == NULL );
}

#endif
