#include<errors.h>
#include<limits.h>
#include<stdlib.h>

#include"KeccakHash.c"
#include"KeccakP-1600-reference.c"
#include"KeccakSpongeWidth1600.c"

#include"KeccakCodePackage/Standalone/CompactFIPS202/C/Keccak-more-compact.c"

/**
 * Digest state.
 */
struct E222CryptoDigestState {
	/**
	 * Keccak hash instance.
	 */
	Keccak_HashInstance keccak;
};

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

Error * e222crypto_digest_new( struct E222CryptoDigestState ** state ) {
	Error * e = NULL;

	/* Sanity check */
	if ( state == NULL ) {
		e = error_newc( "Null state location supplied" );
		goto badparm;
	}

	/* Allocate state */
	*state = malloc( sizeof( **state ) );
	if ( *state == NULL ) {
		e = error_newc( "Insufficient memory to allocate state" );
	}

badparm:
	return e;
}

void e222crypto_digest_del( struct E222CryptoDigestState * state ) {
	free( state );
}

Error * e222crypto_digest_init( struct E222CryptoDigestState * state ) {
	Error * e = NULL;

	/* Sanity check */
	if ( state == NULL ) {
		e = error_newc( "Null state supplied" );
		goto badparm;
	}

	/* Init state */
	HashReturn hrc = Keccak_HashInitialize_SHA3_224( &state->keccak );
	if ( hrc != SUCCESS ) {
		e = error_newc( "Unable to initialise Keccak state" );
	}

badparm:
	return e;
}

Error * e222crypto_digest_update( struct E222CryptoDigestState * state, size_t len, const void * data ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( state == NULL ) {
		e = error_newc( "Null state supplied" );
		goto badparm;
	}
	if ( len > SIZE_MAX / 8 ) {
		e = error_newf( "Piece size of %zu exceeds maximum piece size of %zu", len, SIZE_MAX / 8 );
		goto badparm;
	}
	if ( ( len > 0 ) && ( data == NULL ) ) {
		e = error_newc( "Null data supplied" );
		goto badparm;
	}

	/* Update state */
	HashReturn hrc = Keccak_HashUpdate( &state->keccak, data, len * 8 );
	if ( hrc != SUCCESS ) {
		e = error_newc( "Unable to update Keccak state" );
	}

badparm:
	return e;
}

Error * e222crypto_digest_fini( struct E222CryptoDigestState * state, void * dgst ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( state == NULL ) {
		e = error_newc( "Null state supplied" );
		goto badparm;
	}
	if ( dgst == NULL ) {
		e = error_newc( "Null digest location supplied" );
		goto badparm;
	}

	/* Finish digest */
	HashReturn hrc = Keccak_HashFinal( &state->keccak, dgst );
	if ( hrc != SUCCESS ) {
		e = error_newc( "Unable to finish Keccak digest" );
	}

badparm:
	return e;
}
