#ifndef E222CRYPTO_TEST_INIT_H_
#define E222CRYPTO_TEST_INIT_H_

#include<assert.h>
#include<errors.h>
#include<stddef.h>

#include"e222crypto.h"

static inline void init( void ) {
#ifdef RANDOM_SOURCE
	Error * e = e222crypto_init( RANDOM_SOURCE );
#else
	Error * e = e222crypto_init( NULL );
#endif
	assert( e == NULL );
}

static inline void fini( void ) {
	e222crypto_thread_fini();
	e222crypto_fini();
}

#endif
