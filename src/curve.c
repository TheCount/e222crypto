#include<openssl/bn.h>
#include<openssl/ec.h>

#include"private.h"

#include"errors/errors.h"

/**
 * Big number context.
 */
static BN_CTX * bnctx;

/**
 * E-222 curve group.
 */
static EC_GROUP * e222group;

/**
 * Creates a new E-222 group.
 *
 * @param group Pointer to location to store group pointer in.
 * @param bnctx Pointer to big number context.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
static Error * group_new( EC_GROUP ** group, BN_CTX * bnctx ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( group == NULL ) {
		e = error_newc( "Supplied group storage pointer is null" );
		goto badparm;
	}
	if ( *group != NULL ) {
		e = error_newc( "Supplied group pointer already initialised" );
		goto badparm;
	}
	if ( bnctx == NULL ) {
		e = error_newc( "Supplied big number context is null" );
		goto badparm;
	}

	/* Create group parameters */
	BIGNUM * p = NULL;
	BIGNUM * a = NULL;
	BIGNUM * b = NULL;
	int rc = BN_dec2bn( &p, CURVE_P );
	if ( rc <= 0 ) {
		e = crypto_error( "Unable to create curve parameter p" );
		goto nop;
	}
	rc = BN_dec2bn( &a, CURVE_A );
	if ( rc <= 0 ) {
		e = crypto_error( "Unable to create curve parameter a" );
		goto noa;
	}
	rc = BN_dec2bn( &b, CURVE_B );
	if ( rc <= 0 ) {
		e = crypto_error( "Unable to create curve parameter b" );
		goto nob;
	}

	/* Create group */
	*group = EC_GROUP_new_curve_GFp( p, a, b, bnctx );
	if ( *group == NULL ) {
		e = crypto_error( "Unable to create E-222 curve" );
	}

	/* Cleanup */
	BN_clear_free( b );
nob:
	BN_clear_free( a );
noa:
	BN_clear_free( p );
nop:
badparm:
	return e;
}

/**
 * Destroys an E-222 group.
 *
 * @param group Pointer to group, or a null pointer.
 * 	If @c group is a null pointer, no operation is performed.
 */
static void group_del( EC_GROUP * group ) {
	if ( group != NULL ) {
		EC_GROUP_clear_free( group );
	}
}

/**
 * Creates a new generator for an E-222 group curve.
 *
 * @param gen Pointer to location to store generation pointer in.
 * @param order Pointer to location to store order pointer in.
 * @param cofactor Pointer to location to store cofactor pointer in.
 * @param group Pointer to E-222 group.
 * @param bnctx Pointer to big number context.
 *
 * @return On success, a null pointer is returned.\n
 * 	On error, a pointer to an error is returned.
 */
static Error * generator_new( EC_POINT ** gen, BIGNUM ** order, BIGNUM ** cofactor, const EC_GROUP * group, BN_CTX * bnctx ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( gen == NULL ) {
		e = error_newc( "Supplied generator storage pointer is null" );
		goto badparm;
	}
	if ( *gen != NULL ) {
		e = error_newc( "Supplied generator pointer already initialised" );
		goto badparm;
	}
	if ( order == NULL ) {
		e = error_newc( "Supplied order storage pointer is null" );
		goto badparm;
	}
	if ( *order != NULL ) {
		e = error_newc( "Supplied order pointer already initialised" );
		goto badparm;
	}
	if ( cofactor == NULL ) {
		e = error_newc( "Supplied cofactor storage pointer is null" );
		goto badparm;
	}
	if ( *cofactor != NULL ) {
		e = error_newc( "Supplied cofactor pointer already initialised" );
		goto badparm;
	}
	if ( group == NULL ) {
		e = error_newc( "Supplied group pointer is null" );
		goto badparm;
	}
	if ( bnctx == NULL ) {
		e = error_newc( "Supplied big number context is null" );
		goto badparm;
	}

	/* Create generator parameters */
	BIGNUM * x = NULL;
	BIGNUM * y = NULL;
	int rc = BN_dec2bn( &x, GEN_X );
	if ( rc <= 0 ) {
		e = crypto_error( "Unable to create generator coordinate x" );
		goto nox;
	}
	rc = BN_dec2bn( &y, GEN_Y );
	if ( rc <= 0 ) {
		e = crypto_error( "Unable to create generator coordinate y" );
		goto noy;
	}

	/* Create generator */
	EC_POINT * point = EC_POINT_new( group );
	if ( point == NULL ) {
		e = crypto_error( "Unable to create curve point" );
		goto nopoint;
	}
	rc = EC_POINT_set_affine_coordinates_GFp( group, point, x, y, bnctx );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set affine coordinates of generator" );
		goto nocoord;
	}

	/* Create order and cofactor */
	rc = BN_dec2bn( order, ORDER );
	if ( rc <= 0 ) {
		e = crypto_error( "Unable to create generator order" );
		goto noorder;
	}
	*cofactor = BN_new();
	if ( *cofactor == NULL ) {
		e = crypto_error( "Unable to allocate cofactor" );
		goto nocfalloc;
	}
	rc = BN_set_word( *cofactor, COFACTOR );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set cofactor" );
		goto nocofactor;
	}

	/* Cleanup */
	*gen = point;
	goto success;

nocofactor:
	*cofactor = NULL;
nocfalloc:
	BN_clear_free( *order );
noorder:
	*order = NULL;
nocoord:
	EC_POINT_clear_free( point );
nopoint:
success:
	BN_clear_free( y );
noy:
	BN_clear_free( x );
nox:
badparm:
	return e;
}

/**
 * Destroys the generator of an E-222 group curve.
 *
 * @param gen Pointer to generator, or a null pointer.
 * @param order Pointer to order, or a null pointer.
 * @param cofactor Pointer to cofactor, or a null pointer.
 */
static void generator_del( EC_POINT * gen, BIGNUM * order, BIGNUM * cofactor ) {
	if ( gen != NULL ) {
		EC_POINT_clear_free( gen );
	}
	if ( order != NULL ) {
		BN_clear_free( order );
	}
	if ( cofactor != NULL ) {
		BN_clear_free( cofactor );
	}
}

Error * e222crypto_curve_init( void ) {
	Error * e = NULL;

	/* Big number context */
	bnctx = BN_CTX_new();
	if ( bnctx == NULL ) {
		e = crypto_error( "Unable to allocate big number context" );
		goto nobnctx;
	}

	/* Group */
	EC_GROUP * group = NULL;
	e = group_new( &group, bnctx );
	if ( e != NULL ) {
		goto nogroup;
	}

	/* Generator */
	EC_POINT * gen = NULL;
	BIGNUM * order = NULL;
	BIGNUM * cofactor = NULL;
	e = generator_new( &gen, &order, &cofactor, group, bnctx );
	if ( e != NULL ) {
		goto nogen;
	}
	int rc = EC_GROUP_set_generator( group, gen, order, cofactor );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set group generator" );
		goto nogenset;
	}

	/* Cleanup */
	e222group = group;
	group = NULL;
nogenset:
	generator_del( gen, order, cofactor );
nogen:
	group_del( group );
nogroup:
	if ( e != NULL ) {
		BN_CTX_free( bnctx );
	}
nobnctx:
	return e;
}

void e222crypto_curve_fini( void ) {
	group_del( e222group );
	e222group = NULL;
	BN_CTX_free( bnctx );
}

Error * e222crypto_privkey_generate( E222CryptoPrivkey * privkey ) {
	Error * e = NULL;

	/* Sanity check */
	if ( privkey == NULL ) {
		e = error_newc( "Private key location pointer is null" );
		goto badparm;
	}

	/* Generate key */
	EC_KEY * key = EC_KEY_new();
	if ( key == NULL ) {
		e = crypto_error( "Unable to create key" );
		goto nokey;
	}
	int rc = EC_KEY_set_group( key, e222group );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set key group" );
		goto nogroup;
	}
	rc = EC_KEY_generate_key( key );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to generate key" );
		goto nogen;
	}

	privkey->key = key;
	return NULL;

nogen:
nogroup:
	EC_KEY_free( key );
nokey:
badparm:
	return e;
}

void e222crypto_privkey_del( E222CryptoPrivkey privkey ) {
	if ( privkey.key != NULL ) {
		EC_KEY_free( privkey.key );
	}
}
