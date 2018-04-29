#include<assert.h>
#include<errors.h>
#include<string.h>

#include"e222crypto.h"
#include"error.h"
#include"init.h"

int main( void ) {
	init();

	char buf1[256];
	char buf2[256];
	Error * e = e222crypto_rand( sizeof( buf1 ), buf1 );
	assert( e == NULL );
	e = e222crypto_rand( sizeof( buf2 ), buf2 );
	assert( e == NULL );
	int rc = memcmp( buf1, buf2, sizeof( buf1 ) );
	assert( rc != 0 );

	fini();
}
