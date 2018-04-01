#include<assert.h>

#include"e222crypto.h"

#include"errors/errors.h"

int main( void ) {
	Error * e = e222crypto_init( NULL );
	assert( e == NULL );
	e222crypto_fini();
	e = e222crypto_init( NULL );
	assert( e != NULL );
	error_del( e );
}
