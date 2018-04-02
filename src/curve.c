#include<string.h>

#include<openssl/bn.h>
#include<openssl/ec.h>
#include<openssl/ecdsa.h>

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

	/* Precompute signature parts */
	privkey->kinv = NULL;
	privkey->rp = NULL;
	rc = ECDSA_sign_setup( key, bnctx, &privkey->kinv, &privkey->rp );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to setup signature parts" );
		goto nosig;
	}

	privkey->key = key;
	return NULL;

nosig:
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
	if ( privkey.kinv != NULL ) {
		BN_clear_free( privkey.kinv );
	}
	if ( privkey.rp != NULL ) {
		BN_clear_free( privkey.rp );
	}
}

Error * e222crypto_privkey_cmp( E222CryptoPrivkey privkey1, E222CryptoPrivkey privkey2, int * result ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( ( privkey1.key == NULL ) || ( privkey2.key == NULL ) ) {
		e = error_newc( "Uninitialised private key supplied" );
		goto badparm;
	}
	if ( result == NULL ) {
		e = error_newc( "Result storage location is null" );
		goto badparm;
	}

	/* Set result */
	*result = BN_cmp( EC_KEY_get0_private_key( privkey1.key ), EC_KEY_get0_private_key( privkey2.key ) );

badparm:
	return e;
}

Error * e222crypto_privkey_out( E222CryptoPrivkey privkey, void * buf ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( privkey.key == NULL ) {
		e = error_newc( "Uninitialised private key supplied" );
		goto error;
	}
	if ( buf == NULL ) {
		e = error_newc( "Null buffer supplied" );
		goto error;
	}

	/* Serialise */
	e = bn_out( EC_KEY_get0_private_key( privkey.key ), E222CRYPTO_PRIVSIZE, buf );

error:
	return e;
}

Error * e222crypto_privkey_in( E222CryptoPrivkey * privkey, const void * buf ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( privkey == NULL ) {
		e = error_newc( "Private key location pointer is null" );
		goto badparm;
	}
	if ( buf == NULL ) {
		e = error_newc( "Private key data buffer is null" );
		goto badparm;
	}

	/* Get key as bignum and calculate public key */
	BIGNUM * priv = BN_bin2bn( buf, E222CRYPTO_PRIVSIZE, NULL );
	if ( priv == NULL ) {
		e = crypto_error( "Unable to deserialise key data" );
		goto nopriv;
	}
	EC_POINT * pub = EC_POINT_new( e222group );
	if ( pub == NULL ) {
		e = crypto_error( "Unable to create public key" );
		goto nopub;
	}
	int rc = EC_POINTs_mul( e222group, pub, priv, 0, NULL, NULL, bnctx );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to calculate public key" );
		goto nopubmul;
	}

	/* Build key */
	EC_KEY * key = EC_KEY_new();
	if ( key == NULL ) {
		e = crypto_error( "Unable to create key" );
		goto nokey;
	}
	rc = EC_KEY_set_group( key, e222group );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set key group" );
		goto keyerr;
	}
	rc = EC_KEY_set_private_key( key, priv );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set private key" );
		goto keyerr;
	}
	rc = EC_KEY_set_public_key( key, pub );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set public key" );
		goto keyerr;
	}
	rc = EC_KEY_check_key( key );
	if ( rc != 1 ) {
		e = crypto_error( "Key check failed" );
		goto keyerr;
	}

	/* Precompute signature parts */
	privkey->kinv = NULL;
	privkey->rp = NULL;
	rc = ECDSA_sign_setup( key, bnctx, &privkey->kinv, &privkey->rp );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to setup signature parts" );
		goto nosig;
	}

	privkey->key = key;
	goto success;

nosig:
keyerr:
	EC_KEY_free( key );
nokey:
nopubmul:
success:
	EC_POINT_clear_free( pub );
nopub:
	BN_clear_free( priv );
nopriv:
badparm:
	return e;
}

Error * e222crypto_privkey_getpubkey( E222CryptoPrivkey privkey, E222CryptoPubkey * pubkey ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( privkey.key == NULL ) {
		e = error_newc( "Uninitialised private key supplied" );
		goto badparm;
	}
	if ( pubkey == NULL ) {
		e = error_newc( "Supplied public key storage location is null" );
		goto badparm;
	}

	/* Duplicate key */
	int rc = EC_KEY_up_ref( privkey.key );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to duplicate key" );
		goto nodup;
	}

	pubkey->key = privkey.key;

nodup:
badparm:
	return e;
}

void e222crypto_pubkey_del( E222CryptoPubkey pubkey ) {
	if ( pubkey.key != NULL ) {
		EC_KEY_free( pubkey.key );
	}
}

Error * e222crypto_pubkey_cmp( E222CryptoPubkey pubkey1, E222CryptoPubkey pubkey2, int * result ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( ( pubkey1.key == NULL ) || ( pubkey2.key == NULL ) ) {
		e = error_newc( "Uninitialised public key supplied" );
		goto badparm;
	}
	if ( result == NULL ) {
		e = error_newc( "Result storage location is null" );
		goto badparm;
	}

	/* Set result */
	*result = EC_POINT_cmp( e222group, EC_KEY_get0_public_key( pubkey1.key ), EC_KEY_get0_public_key( pubkey2.key ), bnctx );
	if ( *result == -1 ) {
		e = crypto_error( "Point comparison failed" );
	}

badparm:
	return e;
}

Error * e222crypto_pubkey_out( E222CryptoPubkey pubkey, void * buf ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( pubkey.key == NULL ) {
		e = error_newc( "Uninitialised public key supplied" );
		goto error;
	}
	if ( buf == NULL ) {
		e = error_newc( "Null buffer supplied" );
		goto error;
	}

	/* Serialise */
	const EC_POINT * pub = EC_KEY_get0_public_key( pubkey.key );
	unsigned char tmp[E222CRYPTO_PUBSIZE + 1];
	size_t numconv = EC_POINT_point2oct( e222group, pub, POINT_CONVERSION_COMPRESSED, tmp, sizeof( tmp ), bnctx );
	if ( numconv != E222CRYPTO_PUBSIZE + 1 ) {
		e = crypto_error( "Unable to convert public key" );
		goto error;
	}
	if ( tmp[1] & 0x80u ) {
		e = error_newc( "Pubkey MSB set" );
		goto error;
	}
	if ( tmp[0] == POINT_CONVERSION_COMPRESSED + 1 ) {
		tmp[1] |= 0x80;
	}
	memcpy( buf, tmp + 1, E222CRYPTO_PUBSIZE );

error:
	return e;
}

Error * e222crypto_pubkey_in( E222CryptoPubkey * pubkey, const void * buf ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( pubkey == NULL ) {
		e = error_newc( "Public key location pointer is null" );
		goto badparm;
	}
	if ( buf == NULL ) {
		e = error_newc( "Public key data buffer is null" );
		goto badparm;
	}

	/* Convert key to oct format */
	unsigned char tmp[E222CRYPTO_PUBSIZE + 1];
	memcpy( tmp + 1, buf, E222CRYPTO_PUBSIZE );
	if ( tmp[1] & 0x80 ) {
		tmp[0] = POINT_CONVERSION_COMPRESSED + 1;
		tmp[1] &= 0x7F;
	} else {
		tmp[0] = POINT_CONVERSION_COMPRESSED;
	}

	/* Create public key */
	EC_POINT * pub = EC_POINT_new( e222group );
	if ( pub == NULL ) {
		e = crypto_error( "Unable to create public key" );
		goto nopub;
	}
	int rc = EC_POINT_oct2point( e222group, pub, tmp, sizeof( tmp ), bnctx );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to load public key" );
		goto nopubload;
	}
	EC_KEY * key = EC_KEY_new();
	if ( key == NULL ) {
		e = crypto_error( "Unable to create key" );
		goto nokey;
	}
	rc = EC_KEY_set_group( key, e222group );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set group for key" );
		goto nogroup;
	}
	rc = EC_KEY_set_public_key( key, pub );
	if ( rc != 1 ) {
		e = crypto_error( "Unable to set public key" );
		goto nokeyset;
	}

	pubkey->key = key;
	goto success;

nokeyset:
nogroup:
	EC_KEY_free( key );
nokey:
nopubload:
success:
	EC_POINT_clear_free( pub );
nopub:
badparm:
	return e;
}

Error * e222crypto_sign( E222CryptoPrivkey privkey, const void * digest, E222CryptoSig * sig ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( ( privkey.key == NULL ) || ( privkey.kinv == NULL ) || ( privkey.rp == NULL ) ) {
		e = error_newc( "Uninitialised private key supplied" );
		goto badparm;
	}
	if ( digest == NULL ) {
		e = error_newc( "Null digest supplied" );
		goto badparm;
	}
	if ( sig == NULL ) {
		e = error_newc( "Null signature location pointer supplied" );
		goto badparm;
	}

	/* Sign */
	sig->sig = ECDSA_do_sign_ex( digest, E222CRYPTO_DGSTSIZE, privkey.kinv, privkey.rp, privkey.key );
	if ( sig->sig == NULL ) {
		e = crypto_error( "Unable to sign digest" );
	}

badparm:
	return e;
}

Error * e222crypto_verify( E222CryptoPubkey pubkey, const void * digest, E222CryptoSig sig, int * result ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( pubkey.key == NULL ) {
		e = error_newc( "Uninitialised public key supplied" );
		goto badparm;
	}
	if ( digest == NULL ) {
		e = error_newc( "Null digest supplied" );
		goto badparm;
	}
	if ( sig.sig == NULL ) {
		e = error_newc( "Uninitialised signature supplied" );
		goto badparm;
	}
	if ( result == NULL ) {
		e = error_newc( "Null result location pointer supplied" );
		goto badparm;
	}

	/* Verify */
	int rc = ECDSA_do_verify( digest, E222CRYPTO_DGSTSIZE, sig.sig, pubkey.key );
	if ( rc == -1 ) {
		e = crypto_error( "Signature verification error" );
	} else {
		*result = rc;
	}

badparm:
	return e;
}

void e222crypto_sig_del( E222CryptoSig sig ) {
	if ( sig.sig != NULL ) {
		ECDSA_SIG_free( sig.sig );
	}
}

Error * e222crypto_sig_out( E222CryptoSig sig, void * buf ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( sig.sig == NULL ) {
		e = error_newc( "Uninitialised signature supplied" );
		goto badparm;
	}
	if ( buf == NULL ) {
		e = error_newc( "Null signature serialisation buffer supplied" );
		goto badparm;
	}

	/* Serialise */
	e = bn_out( sig.sig->r, E222CRYPTO_SIGSIZE / 2, buf );
	if ( e == NULL ) {
		e = bn_out( sig.sig->s, E222CRYPTO_SIGSIZE / 2, buf + E222CRYPTO_SIGSIZE / 2 );
	}

badparm:
	return e;
}

Error * e222crypto_sig_in( E222CryptoSig * sig, const void * buf ) {
	Error * e = NULL;

	/* Sanity checks */
	if ( sig == NULL ) {
		e = error_newc( "Null signature location pointer supplied" );
		goto badparm;
	}
	if ( buf == NULL ) {
		e = error_newc( "Null deserialisation buffer pointer supplied" );
		goto badparm;
	}

	/* Create signature and deserialise */
	sig->sig = ECDSA_SIG_new();
	if ( sig->sig == NULL ) {
		e = crypto_error( "Unable to create signature" );
		goto nosig;
	}
	sig->sig->r = BN_bin2bn( buf, E222CRYPTO_SIGSIZE / 2, sig->sig->r );
	if ( sig->sig->r == NULL ) {
		e = crypto_error( "Unable to deserialise signature r" );
		goto nosigr;
	}
	sig->sig->s = BN_bin2bn( buf + E222CRYPTO_SIGSIZE / 2, E222CRYPTO_SIGSIZE / 2, sig->sig->s );
	if ( sig->sig->s == NULL ) {
		e = crypto_error( "Unable to deserialise signature s" );
		goto nosigs;
	}

	return NULL;

nosigs:
nosigr:
	ECDSA_SIG_free( sig->sig );
nosig:
badparm:
	return e;
}
