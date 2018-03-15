#include<stdatomic.h>
#include<thread.h>

/**
 * Provides a dynamic lock type
 * for libcrypto's dynlock.
 */
struct CRYPTO_dynlock_value {
	/**
	 * Entry lock, ensures the order of threads entering the
	 * critical section protected by this lock is detrmined
	 * by the operating system.
	 */
	mtx_t entryLock;

	/**
	 * Lock acquired by writers and the first reader.
	 */
	mtx_t writerLock;

	/**
	 * Current number of readers.
	 */
	atomic_uint numReaders;
};

#include<openssl/crypto.h>

#include"errors/errors.h"

/**
 * Dummy variable whose address serves as thread identifier.
 * We use this rather than the return value of thrd_current()
 * because libcrypto requires us to know whether the thread identifier
 * is a pointer or an an integer. Unfortunarely, the C11 standard does not say
 * anything about thrd_t other than that it is a complete type.
 */
static _Thread_local unsigned char threadLocalDummy = 0;

/**
 * Stores the ID of the current thread in the specified destination.
 *
 * @param dest Pointer to destination.
 */
static void threadid_func( CRYPTO_THREADID * dest ) {
	CRYPTO_THREADID_set_pointer( dest, &threadLocalDummy );
}

Error * e222crypto_threads_init( void ) {
	Error * e = NULL;

	/* Set thread id callback */
	int rc = CRYPTO_THREADID_set_callback( threadid_func );
	if ( rc != 1 ) {
		e = error_newc( "Thread-ID callback already set" );
		goto nothreadid;
	}

	return NULL;

nothreadid:
	return e;
}

void e222crypto_threads_fini( void ) {
}
