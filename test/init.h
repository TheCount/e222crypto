#ifndef E222CRYPTO_TEST_INIT_H_
#define E222CRYPTO_TEST_INIT_H_

#include<assert.h>
#include<stddef.h>

#include"e222crypto.h"

#include"errors/errors.h"

static inline void init( void ) {
#ifdef RANDOM_SOURCE
	Error * e = e222crypto_init( RANDOM_SOURCE );
#else
	Error * e = e222crypto_init( NULL );
#endif
	assert( e == NULL );
}

#endif
