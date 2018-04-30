#include<assert.h>
#include<errno.h>
#include<errors.h>
#include<stdlib.h>
#include<string.h>

#include"e222crypto.h"
#include"error.h"
#include"init.h"

/**
 * Test message type.
 */
struct TestMessage {
	const char * const in;
	const char out[2 * E222CRYPTO_DGSTSIZE];
};

/**
 * FIPS202 test messages (selection).
 */
static const struct TestMessage TEST_MSGS[] = {
	{
		"",
		"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
	}, {
		"01",
		"488286d9d32716e5881ea1ee51f36d3660d70f0db03b3f612ce9eda4",
	}, {
		"69cb",
		"94bd25c4cf6ca889126df37ddd9c36e6a9b28a4fe15cc3da6debcdd7",
	}, {
		"3b9ab76a23ae56340b5f4b80e1f3",
		"c0903be96f38051cfc2a5ad256aa0b8332217f450eab904ee84b6541",
	}, {
		"eb9e1143782a0f9fa815261c2adc2758fb1d88ffe40a0ae144189a48",
		"9d70d22520094a113297a192ead33e316924fdc7a2a9f8ea7098b84b",
	}, {
		"e65de91fdcb7606f14dbcfc94c9c94a57240a6b2c31ed410346c4dc011526559e44296fc988cc589de2dc713d0e82492d4991bd8c4c5e6c74c753fc09345225e1db8d565f0ce26f5f5d9f404a28cf00bd655a5fe04edb682942d675b86235f235965ad422ba5081a21865b8209ae81763e1c4c0cccbccdaad539cf773413a50f5ff1267b9238f5602adc06764f775d3c",
		"26ec9df54d9afe11710772bfbeccc83d9d0439d3530777c81b8ae6a3",
	}, {
		"31c82d71785b7ca6b651cb6c8c9ad5e2aceb0b0633c088d33aa247ada7a594ff4936c023251319820a9b19fc6c48de8a6f7ada214176ccdaadaeef51ed43714ac0c8269bbd497e46e78bb5e58196494b2471b1680e2d4c6dbd249831bd83a4d3be06c8a2e903933974aa05ee748bfe6ef359f7a143edf0d4918da916bd6f15e26a790cff514b40a5da7f72e1ed2fe63a05b8149587bea05653718cc8980eadbfeca85b7c9c286dd040936585938be7f98219700c83a9443c2856a80ff46852b26d1b1edf72a30203cf6c44a10fa6eaf1920173cedfb5c4cf3ac665b37a86ed02155bbbf17dc2e786af9478fe0889d86c5bfa85a242eb0854b1482b7bd16f67f80bef9c7a628f05a107936a64273a97b0088b0e515451f916b5656230a12ba6dc78",
		"aab23c9e7fb9d7dacefdfd0b1ae85ab1374abff7c4e3f7556ecae412",
	}, {
		"b7b8ac96733943c648cf833e75ca4dee7bb6cce48130fbbff6f96867784937fbf566690b10745f08c68f99f85117c46e4c4bf4ba191a2e5d803529c098695525eb2c1dddd57669bb2dd268ca27b48c3b790dd6a1bd1d53611788e76317ad490ee1334f748be46cc9c6bf771ac148ad3b4a23fa0237e174b2041a28babdbc1aa01ea28738fa696d19d97f4e51e57c305807b6e8434d0f983a8f12772c523fd0c1eca24e91e9ab7693ae3975d85cf81c79f7ed29cec84fc8e0ff9959219ddd745b915b2ae721528e1f8c167515ee63798663f144096f480b8c9ed65801673f0d5556f4a6a26b07bea5bd3ed4726266506693e9c15e0ca36926b2f2fb35780ca3978396472a8d720d0d87d81d5682a8a803cffe29346507ea978414ca2398ed3f09606897e74f3a833f330cd52914d289445f5802f2441d97c55c654e348f8ae79335931d427b07282408048652e18bfb118a1ed7026f8d7799820d0ed0248aa61d493e61a1d78305a250e5b73bb17c07529a792dcbaefe92fb3d3393602196818fe592ec6d2d5421a251daf14b4c4cb4efd5908eb5cb19f1d4d6ff634a4c5582d151b7450f4322840d5508bbea79a40bd1848c81288c859b0a959a08f86d70b0cbd5d4f4ede19637c9a29a9d80022c12deee948f8cbbea9887c22c0ad04e8e1366b9118271d15741c080b61f75ad8bd3ff5dd13e491ef2f131a5dcef3cb658b48844977602da0eaad83985ca32436a561d176a19c77e43adf286d341a36c759a1abf8e5807c3637bfb142e251d8b70a11e6588a56fa285d4b1ac39876d398ecd05721eb1ea55fdbb1058d9b99f4f46beec8f536ca754616f5660354a01e54b562fa56d0712588572ff4eb00c215593b56dddf2f5d85a7e85c8eaef11c938533c82a0a6e5e794a2a8b03ed8a80966008c8b978ec86b7d861ef19290642cfa4f87e5aaefd0d1d0fd660a6f7c15c04a354d2c044e6ec6851e42b8a040cb92f2e6403f0d705238d63eb3f72bc2d9afc9d9003a6d5b6e533af0fa055b26cf63e9c16e7a0f53f2846c0c985fb8d27e3dab94ab9c1adc507964a44dc00c6bf708a788197df9bd391d5b0f1c285fd58cd1b710583a53fa9d9fcae244d2fb36cce7f4e2493013d8ad6c6af0473b68f389d5b6f20efc60dddc2f3551e62170b0d5699877077ba4ccd8d7635721801b53ffb071e5d6ca88ac95906d993b96b3019af65af05a46f6c142c70cebb3dfc01e75caad8fb78c1590502a3a634b190b50a3f703f54b794fde71a52f5504419e7b748b3598b92a4db0966564571f93c2c579d25b2de1fcf84befd7923d1c8cfe93835bd0a9e48c7935eea9b21cbeea1e8aa3f12a4124b7393144c7fe4904aa288e2aa2456a419be046e15eed5b300868c4a9ba38d81c9359b8f6db3a24c3816493f1c85d82d73dcc0cf6ecddbb",
		"e93d038156082ba508def0a26ea9172930f546dbec5b5652928a28c7",
	}, {
		"d18793d705f8597b71ec1aa00854935f8dbdaf4861d3f9059a2456395427f4ae4c7d7eb0ab7692b41fd7743e30db0401d277ed4736e22093e65581851110dfff239d2a869958e0eb142fc92aaca7e492861fa126a95950440d36da84f5c1afe37f6fff217aa62d67777b812d23c01d5bd43e32ae613f735e3750cafea9444aa3887c6648f46660717144040f3e2f95a4e25b08a7079c702a8b29babad5a19a87654bc5c5afa261512a11b998a4fb36b5d8fe8bd942792ff0324b108120de86d63f65855e5461184fc96a0a8ffd2ce6d5dfb0230cbbdd98f8543e361b3205f5da3d500fdc8bac6db377d75ebef3cb8f4d1ff738071ad0938917889250b41dd1d98896ca06fb8a48c45be11eeb2cde1866bf5e3293065a08eca6b38ee84e2f011c47be1da64d0391cb9e0fb0df50706965e76a79782784df6a274790aaa7426deba3517282291f301067ea7d6208866a95c1a5757e26550049c3ca025f685efd8ec4d6306435e70ddbdff9ed3cfc2a033d72968e6cabd653d1a1c64bcf388b994cd1d5be121c6210742dc46934d3631ca425c52d0c5d0dc14ceac2d3c2c0d2296ef3d78654849822227bd35713353a9d1300bbb824e5043000c5470200a83a953c5163eff41692292feeaf20a1ccb56ed22bff997deac389365bdc405097ccc5fe140161b879570ee1b0df2da63ddf7729cf1936df1550b536d309f57c358fa1fc6339446a55efba81e9ebe5ea33bda1601492f9120eb59b485656894a2b8b127e679401d054631456c05caf345459d2be21f149dd7cfa22b40c4c648321c8fecb4799feb31cba03aa5eb8f54e48baf38c1fbe8d09082534c11c72eeefbe4f4f2c2cd1a4da55fc71c3eb8a1efeb8e8ed1335822f5e5940b8b9af509055ab27ebe93ec25b0fa83245ea8e57920d4ceca6988cc396a4185295e2ec6fb07e9058bc4aa4f68c18bc6367676fa9b843abcd08664b0c2aa3ec64b585fc56b83313eba89687f59dbe3b97be82b707fa677e93fac49be253237e7dffe9068d0e3adfe799170e45f8c9cad634838efabf436c4663f9a4cf79eb75a55b58339d1c5b9a547613627003011329b0b11b09709d1eef2d4e8d5a04c47ae4b118ab0d4860ed3a27d3aafe282ebe971b5687bc733e3b963f0b7f0c5c763543e9729565fc0f7fa2939f0f75ce1773295bb8f99b31ee6c418178a16be9c94dc9ecae192e9f32f993a4bfb95f5c85d9e6591f9a2f127459fadbdc1c0114856b7fa01461ef998f0216417acf433c4098d6fdd592ff7f9aa9c8358117564371366beeec923051ef433252197aaad510590130210893de2605b477adbbf0df565797be7dd77a311963efc0e4e11b8fbdc470d84a247498e114c489a9305951fc750bf9105653a0d70b5571232d1ed20e802ade99102916937f0253bd9d19002b39ce85ed374606efe36d4e1e853b06cc36372b56f13abf04ed76be302ab653ab4ae74c5ca3d8cc2a923e3f1d12fb93bf8da0a6c9f230fafb0727b04c01bab443526135a5c2935850c1d02d67fbe5e2af2e6c363938923142751d125747ad8abdf641270fbbfe1329172cfe4569825964c0a3c5f0eee8cb9fde60cd9a27153cdfe0910ce3b7a1657c3d599cff845861a5ec4e3a343abb30dbeaf9c75dc77c3472b859cb6add05b713da5feddd73f1633c5a737c4e4491c7be42efeae84f69d93d259f4ce956b16fb49747db265fd5c5efb11d758635f5fa0f8e4a1d82e865930ad06d77ab492df7281c184d246f8af18799510c23356c309875124774baf7ca9f61ca34f7df02b53710da2a1dcc9a4dccbc19296f6b80d21fa0505207eca7e6c57fbf6b143fb713a81c965c5a9d8d4385bf7cb4b000b8466db70c2580a6fd4f44d252044b93d47745e753ca230be9397c4d83962f1c9cf54a614ca82a12826ee4038de7e400e24bd41a195cc03e3899770c34b534e5b5477d461ac34c55bda96dba78fc27b068f61e5cf0fa785d01ca3fa499fa06868aa5d00f7d5e2d9a3669a69e1a2c5bcbeee0eb56e18c9491cd349cbeba4def25a47509647e611607761758587b5dca78fc7103aff3fa5c01233f55029d9735eb8920f1ec23b44fc404194b90a378bae01b112d102f2c18d68b5334174cbe21ffc30f5050764020fa68d947ed9b66742bd22833219b0b10378dd8ffa6cfacfb89daa9ee387febd1d12bbd14176a0d4080aa1edb89427d8c4db2367f562c470bb35455924a459ea970d42f79b7185765072a5beef1296bd33f81d57cd06d7998a3bb7d0631d042f100eb964075ae2b2deada4733005abe2e36831ebebb9a29ec819688109328bdf2a8f95a2ff83370de4e424b745fdc5ce55a3e770cc0b93f4d766ede791956f9f19185e20fe9af10c15debcd77b5b72f40d23c492f87d4a204aacae7086a61dc39e21798a7ef2af21e3f5c3705abf31e86c705fdf0b7f23c5944320a872f515011c437e3c1b3adfe3d1c1defe6e9991001601ff915f81cf4936c2eb2bc0f2e3cc05f6e2b23dc3f1c651bb75fe216b1eff7c614a766f459b2fc4c474471b301878fda43d99613e934e064b1edc1da41a2b1206c6ead50b15eda0904296cc2d21bc65e3f53e200b22ef42093034adf53117797adb5b0b72ce176ceeec976e5a7dfad12e802cf4aa2f2ea77e60846caee24915361e638cfd32118c18b8c56c48abb8b1fc94e259ac1690a9030647e461bc3467b0f680d40ad07080a66dbd6068297aaac67a0ab9718799b94fc7eb7f9e1d6df3840a3f7b3c27b8dd2041cbc53975b50e24c5e2aeaae0be7aacfc0bc8b4845a4b17bffbed01b66f041efb9d155d2f0c6e9fff26b3a8b0834fb339154a558f8dd0f48e4293ebfae7a7eae18ddb13a3c54e808c23330b856cbafaf5946ef1ad7d2792fba02a6b63d70b2c9a3a812d8284107f0384d743cdff4edcc815b1095cbcb18b9e90faf09f91d04c8c0f91eb29cd7703dba80ad1f89f6dd106f5bb1d1ba0f136dd91902bfccc89d34d9997dd3815c487ab293836a3e1ba8058c0e79d78ee793d4f2e746e09db8a4955551d840bd19ba2c874fa024e5a97633403b11ae",
		"a88eb8ce917b17c34800b6bcfe9683deb431e128256f4edc7c084add",
	}, {
		NULL,
		"",
	}
};

static size_t to_bin( const struct TestMessage * testmsg, char ** msg, char * outexpect ) {
	assert( testmsg != NULL );
	assert( testmsg->in != NULL );
	assert( msg != NULL );
	assert( outexpect != NULL );

	size_t hexlen = strlen( testmsg->in );
	assert( hexlen % 2 == 0 );
	size_t binlen = hexlen / 2;
	*msg = malloc( binlen );
	assert( ( *msg != NULL ) || ( binlen == 0 ) );
	for ( size_t i = 0; i != binlen; ++i ) {
		char byte[3] = { testmsg->in[2 * i], testmsg->in[2 * i + 1], 0 };
		errno = 0;
		( *msg )[i] = strtol( byte, NULL, 16 );
		assert( errno == 0 );
	}
	for ( size_t i = 0; i != E222CRYPTO_DGSTSIZE; ++i ) {
		char byte[3] = { testmsg->out[2 * i], testmsg->out[2 * i + 1], 0 };
		errno = 0;
		outexpect[i] = strtol( byte, NULL, 16 );
		assert( errno == 0 );
	}

	return binlen;
}

static void assert_digest_state( void ) {
	/* new */
	E222CryptoDigestState * state;
	Error * e = e222crypto_digest_new( NULL );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_new( &state );
	assert( e == NULL );

	/* init */
	e = e222crypto_digest_init( NULL );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_init( state );
	assert( e == NULL );

	/* Update */
	e = e222crypto_digest_update( NULL, 0, NULL );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_update( state, 0, NULL );
	assert( e == NULL );
	e = e222crypto_digest_update( NULL, 1, NULL );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_update( state, 1, NULL );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_update( NULL, 0, &state );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_update( state, 0, &state );
	assert( e == NULL );
	e = e222crypto_digest_update( NULL, 1, &state );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_update( state, 1, &state );
	assert( e == NULL );
	e = e222crypto_digest_update( state, SIZE_MAX / 7, &state );
	assert( e != NULL );
	error_del( e );

	/* fini */
	char out[E222CRYPTO_DGSTSIZE];
	e = e222crypto_digest_fini( NULL, NULL );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_fini( state, NULL );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_fini( NULL, out );
	assert( e != NULL );
	error_del( e );
	e = e222crypto_digest_fini( state, out );
	assert( e == NULL );

	/* del */
	e222crypto_digest_del( state );
}

static void assert_digest_simple( const struct TestMessage * testmsg ) {
	size_t msglen;
	char * msg;
	char outexpect[E222CRYPTO_DGSTSIZE];
	char out[E222CRYPTO_DGSTSIZE];
	msglen = to_bin( testmsg, &msg, outexpect );
	Error * e = e222crypto_digest( msglen, msg, out );
	assert( e == NULL );
	int rc = memcmp( outexpect, out, E222CRYPTO_DGSTSIZE );
	assert( rc == 0 );
	free( msg );
}

static void assert_digest_complex( const struct TestMessage * testmsg ) {
	char out[E222CRYPTO_DGSTSIZE];
	int rc;

	/* Obtain digest state, message, and expected digest */
	char * msg;
	char outexpect[E222CRYPTO_DGSTSIZE];
	size_t msglen = to_bin( testmsg, &msg, outexpect );
	E222CryptoDigestState * state;
	Error * e = e222crypto_digest_new( &state );
	assert( e == NULL );

	/* Digest in one piece */
	e = e222crypto_digest_init( state );
	assert( e == NULL );
	e = e222crypto_digest_update( state, msglen, msg );
	assert( e == NULL );
	e = e222crypto_digest_fini( state, out );
	assert( e == NULL );
	rc = memcmp( out, outexpect, E222CRYPTO_DGSTSIZE );
	assert( rc == 0 );

	/* Digest with null updates */
	e = e222crypto_digest_init( state );
	assert( e == NULL );
	e = e222crypto_digest_update( state, 0, NULL );
	assert( e == NULL );
	e = e222crypto_digest_update( state, msglen, msg );
	assert( e == NULL );
	e = e222crypto_digest_update( state, 0, NULL );
	assert( e == NULL );
	e = e222crypto_digest_fini( state, out );
	assert( e == NULL );
	rc = memcmp( out, outexpect, E222CRYPTO_DGSTSIZE );
	assert( rc == 0 );

	/* Digest in two pieces */
	e = e222crypto_digest_init( state );
	assert( e == NULL );
	e = e222crypto_digest_update( state, msglen / 2, msg );
	assert( e == NULL );
	e = e222crypto_digest_update( state, msglen - msglen / 2, msg + msglen / 2 );
	assert( e == NULL );
	e = e222crypto_digest_fini( state, out );
	assert( e == NULL );
	rc = memcmp( out, outexpect, E222CRYPTO_DGSTSIZE );
	assert( rc == 0 );

	/* Cleanup */
	e222crypto_digest_del( state );
	free( msg );
}

static void assert_digest( const struct TestMessage * testmsg ) {
	assert_digest_simple( testmsg );
	assert_digest_complex( testmsg );
}

int main( void ) {
	init();

	/* Some generic digest state tests */
	assert_digest_state();

	/* Run some actual digests */
	for ( const struct TestMessage * testmsg = TEST_MSGS; testmsg->in != NULL; ++testmsg ) {
		assert_digest( testmsg );
	}

	fini();
}
