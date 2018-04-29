#include<assert.h>
#include<errors.h>

#include"e222crypto.h"
#include"error.h"

int main( void ) {
	Error * e = e222crypto_init( NULL );
	assert_error_null( e );
	e222crypto_thread_fini();
	e222crypto_fini();
	e = e222crypto_init( NULL );
	assert( e != NULL );
	error_del( e );
}
