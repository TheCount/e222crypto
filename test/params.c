#include<assert.h>

#include<openssl/bn.h>
#include<openssl/ec.h>

#include"private.h"

int main( void ) {
	/* big number context */
	BN_CTX * bnctx = BN_CTX_new();
	assert( bnctx != NULL );

	/* Make sure p is a prime */
	BIGNUM * p = NULL;
	int rc = BN_dec2bn( &p, CURVE_P );
	assert( rc > 0 );
	rc = BN_is_prime_ex( p, 100, bnctx, NULL );
	assert( rc == 1 );

	/* Make sure a and b are smaller than p */
	BIGNUM * a = NULL;
	rc = BN_dec2bn( &a, CURVE_A );
	assert( rc > 0 );
	BIGNUM * b = NULL;
	rc = BN_dec2bn( &b, CURVE_B );
	assert( rc > 0 );
	rc = BN_cmp( p, a );
	assert( rc == 1 );
	rc = BN_cmp( p, b );
	assert( rc == 1 );

	/* Make sure 4a³+27b² != 0 (mod p) */
	BIGNUM * n4 = BN_new();
	assert( n4 != NULL );
	rc = BN_set_word( n4, 4 );
	assert( rc == 1 );
	BIGNUM * n27 = BN_new();
	assert( n27 != NULL );
	rc = BN_set_word( n27, 27 );
	assert( rc == 1 );
	BIGNUM * tmp = BN_new();
	assert( tmp != NULL );
	rc = BN_mul( tmp, n4, a, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp, tmp, a, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp, tmp, a, bnctx );
	assert( rc == 1 );
	BIGNUM * tmp2 = BN_new();
	assert( tmp2 != NULL );
	rc = BN_mul( tmp2, n27, b, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp2, tmp2, b, bnctx );
	assert( rc == 1 );
	rc = BN_add( tmp, tmp, tmp2 );
	assert( rc == 1 );
	rc = BN_mod( tmp2, tmp, p, bnctx );
	assert( rc == 1 );
	rc = BN_is_zero( tmp2 );
	assert( rc == 0 );

	/* Generate and check Edwards parameter */
	BIGNUM * d = BN_new();
	assert( d != NULL );
	rc = BN_set_word( d, 160102 );
	assert( rc == 1 );
	const BIGNUM * n1 = BN_value_one();
	rc = BN_sub( tmp, n1, d );
	assert( rc == 1 );
	rc = BN_mod_mul( tmp2, tmp, d, p, bnctx );
	assert( rc == 1 );
	rc = BN_is_zero( tmp2 );
	assert( rc == 0 );

	/* Generate and check Montgomery parameters */
	BIGNUM * n2 = BN_new();
	assert( n2 != NULL );
	rc = BN_set_word( n2, 2 );
	assert( rc == 1 );
	BIGNUM * invexp = BN_new();
	assert( invexp != NULL );
	rc = BN_sub( invexp, p, n2 );
	assert( rc == 1 );
	rc = BN_sub( tmp, n1, d );
	assert( rc == 1 );
	rc = BN_mod_exp( tmp2, tmp, invexp, p, bnctx );
	assert( rc == 1 );
	BIGNUM * A = BN_new();
	assert( A != NULL );
	rc = BN_add( A, n1, d );
	assert( rc == 1 );
	rc = BN_mul( A, A, n2, bnctx );
	assert( rc == 1 );
	rc = BN_mod_mul( A, A, tmp2, p, bnctx );
	assert( rc == 1 );
	BIGNUM * B = BN_new();
	assert( B != NULL );
	rc = BN_mod_mul( B, n4, tmp2, p, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp, A, A, bnctx );
	assert( rc == 1 );
	rc = BN_sub( tmp, tmp, n4 );
	assert( rc == 1 );
	rc = BN_mod_mul( tmp, tmp, B, p, bnctx );
	assert( rc == 1 );
	rc = BN_is_zero( tmp );
	assert( rc == 0 );

	/* Generate Weierstrass parameters and compare with a and b */
	BIGNUM * n3 = BN_new();
	assert( n3 != NULL );
	rc = BN_set_word( n3, 3 );
	assert( rc == 1 );
	BIGNUM * Wa = BN_new();
	assert( Wa != NULL );
	rc = BN_mul( Wa, A, A, bnctx );
	assert( rc == 1 );
	rc = BN_sub( Wa, n3, Wa );
	assert( rc == 1 );
	rc = BN_mul( tmp, n3, B, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp, tmp, B, bnctx );
	assert( rc == 1 );
	rc = BN_mod_exp( tmp2, tmp, invexp, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_mul( Wa, Wa, tmp2, p, bnctx );
	assert( rc == 1 );
	rc = BN_cmp( Wa, a );
	assert( rc == 0 );
	BIGNUM * n9 = BN_new();
	assert( n9 != NULL );
	rc = BN_set_word( n9, 9 );
	assert( rc == 1 );
	rc = BN_exp( tmp, A, n3, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp, tmp, n2, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp2, n9, A, bnctx );
	assert( rc == 1 );
	BIGNUM * Wb = BN_new();
	assert( Wb != NULL );
	rc = BN_sub( Wb, tmp, tmp2 );
	assert( rc == 1 );
	rc = BN_exp( tmp, B, n3, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp, n27, tmp, bnctx );
	assert( rc == 1 );
	rc = BN_mod_exp( tmp2, tmp, invexp, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_mul( Wb, Wb, tmp2, p, bnctx );
	assert( rc == 1 );
	rc = BN_cmp( Wb, b );
	assert( rc == 0 );

	/* Check that generator order is prime */
	BIGNUM * order = NULL;
	rc = BN_dec2bn( &order, ORDER );
	assert( rc > 0 );
	rc = BN_is_prime_ex( order, 100, bnctx, NULL );
	assert( rc == 1 );

	/* Check that order and cofactor match p */
	BIGNUM * cofactor = BN_new();
	assert( cofactor != NULL );
	rc = BN_set_word( cofactor, COFACTOR );
	assert( rc == 1 );
	rc = BN_mul( tmp, order, cofactor, bnctx );
	assert( rc == 1 );
	rc = BN_sub( tmp, tmp, p );
	assert( rc == 1 );
	rc = BN_sub( tmp, tmp, n1 );
	assert( rc == 1 );
	rc = BN_sqr( tmp, tmp, bnctx );
	assert( rc == 1 );
	rc = BN_mul( tmp2, n2, p, bnctx );
	assert( rc == 1 );
	rc = BN_cmp( tmp, tmp2 );
	assert( rc == -1 );

	/* Cook up generator point */
	BIGNUM * Ex = NULL;
	rc = BN_dec2bn( &Ex, "2705691079882681090389589001251962954446177367541711474502428610129" );
	assert( rc > 0 );
	BIGNUM * Ey = BN_new();
	assert( Ey != NULL );
	rc = BN_set_word( Ey, 28 );
	assert( rc == 1 );
	BIGNUM * Mx = BN_new();
	assert( Mx != NULL );
	BIGNUM * My = BN_new();
	assert( My != NULL );
	rc = BN_sub( tmp, n1, Ey );
	assert( rc == 1 );
	rc = BN_mod_exp( tmp2, tmp, invexp, p, bnctx );
	assert( rc == 1 );
	rc = BN_add( tmp, n1, Ey );
	assert( rc == 1 );
	rc = BN_mod_mul( Mx, tmp, tmp2, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_exp( tmp, Ex, invexp, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_mul( My, Mx, tmp, p, bnctx );
	assert( rc == 1 );
	BIGNUM * Wx = BN_new();
	assert( Wx != NULL );
	BIGNUM * Wy = BN_new();
	assert( Wy != NULL );
	rc = BN_mod_exp( tmp, n3, invexp, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_mul( tmp2, tmp, A, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_add( tmp, tmp2, Mx, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_exp( tmp2, B, invexp, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_mul( Wx, tmp, tmp2, p, bnctx );
	assert( rc == 1 );
	rc = BN_mod_mul( Wy, My, tmp2, p, bnctx );
	assert( rc == 1 );
	BIGNUM * x = NULL;
	BIGNUM * y = NULL;
	rc = BN_dec2bn( &x, GEN_X );
	assert( rc > 0 );
	rc = BN_dec2bn( &y, GEN_Y );
	assert( rc > 0 );
	rc = BN_cmp( x, Wx );
	assert( rc == 0 );
	rc = BN_cmp( y, Wy );
	assert( rc == 0 );

	/* Check that generator point lies on curve */
	rc = BN_sqr( tmp, y, bnctx );
	assert( rc == 1 );
	rc = BN_mod_exp( tmp2, x, n3, p, bnctx );
	assert( rc == 1 );
	rc = BN_sub( tmp, tmp, tmp2 );
	assert( rc == 1 );
	rc = BN_mul( tmp2, a, x, bnctx );
	assert( rc == 1 );
	rc = BN_sub( tmp, tmp, tmp2 );
	assert( rc == 1 );
	rc = BN_mod_sub( tmp2, tmp, b, p, bnctx );
	assert( rc == 1 );
	rc = BN_is_zero( tmp2 );
	assert( rc == 1 );

	/* Check that generator point has correct order */
	EC_GROUP * curve = EC_GROUP_new_curve_GFp( p, a, b, bnctx );
	assert( curve != NULL );
	EC_POINT * generator = EC_POINT_new( curve );
	assert( generator != NULL );
	rc = EC_POINT_set_affine_coordinates_GFp( curve, generator, x, y, bnctx );
	assert( rc == 1 );
	rc = EC_GROUP_set_generator( curve, generator, order, cofactor );
	assert( rc == 1 );
	EC_POINT * target = EC_POINT_new( curve );
	assert( target != NULL );
	rc = EC_POINT_mul( curve, target, NULL, generator, order, bnctx );
	assert( rc == 1 );
	rc = EC_POINT_is_at_infinity( curve, target );
	assert( rc == 1 );

	/* Cleanup */
	EC_GROUP_clear_free( curve );
	EC_POINT_clear_free( generator );
	EC_POINT_clear_free( target );
	BN_clear_free( tmp );
	BN_clear_free( tmp2 );
	BN_clear_free( invexp );
	BN_clear_free( n2 );
	BN_clear_free( n3 );
	BN_clear_free( n4 );
	BN_clear_free( n9 );
	BN_clear_free( n27 );
	BN_clear_free( Ex );
	BN_clear_free( Ey );
	BN_clear_free( Mx );
	BN_clear_free( My );
	BN_clear_free( Wx );
	BN_clear_free( Wy );
	BN_clear_free( x );
	BN_clear_free( y );
	BN_clear_free( order );
	BN_clear_free( cofactor );
	BN_clear_free( d );
	BN_clear_free( B );
	BN_clear_free( A );
	BN_clear_free( Wa );
	BN_clear_free( Wb );
	BN_clear_free( b );
	BN_clear_free( a );
	BN_clear_free( p );
	BN_CTX_free( bnctx );
}
