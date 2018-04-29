#include<errors.h>
#include<stddef.h>

#include"KeccakCodePackage/Standalone/CompactFIPS202/C/Keccak-more-compact.c"

Error * e222crypto_digest( size_t msglen, const void * msg, void * dgst ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( ( msg == NULL ) && ( msglen != 0 ) ) {
		e = error_newc( "Null message supplied" );
		goto badparm;
	}
	if ( dgst == NULL ) {
		e = error_newc( "Null digest location supplied" );
		goto badparm;
	}

	/* Digest */
	FIPS202_SHA3_224( msg, msglen, dgst );

badparm:
	return e;
}
