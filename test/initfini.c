#include<assert.h>

#include"e222crypto.h"

#include"errors/errors.h"

int main( void ) {
	Error * e = e222crypto_init();
	assert( e == NULL );
	e222crypto_fini();
}
