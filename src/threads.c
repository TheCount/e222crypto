#include<stdatomic.h>
#include<stdlib.h>
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

static struct CRYPTO_dynlock_value * dynlock_create( char * file, int line ) {
	struct CRYPTO_dynlock_value * result = malloc( sizeof( *result ) );
	if ( result == NULL ) {
		goto nodynlock;
	}
	int rc = mtx_init( &result->entryLock, mtx_plain );
	if ( rc != thrd_success ) {
		goto noelock;
	}
	rc = mtx_init( &result->writerLock, mtx_plain );
	if ( rc != thrd_success ) {
		goto nowlock;
	}
	result->numReaders = ATOMIC_VAR_INIT( 0 );

	return result;

	mtx_destroy( &result->writerLock );
nowlock:
	mtx_destroy( &result->entryLock );
noelock:
	free( result );
nodynlock:
	return NULL;
}

static void dynlock_destroy( struct CRYPTO_dynlock_value * lock, char * file, int line ) {
	mtx_destroy( &lock->writerLock );
	mtx_destroy( &lock->entryLock );
	free( lock );
}

static void dynlock_lock( int mode, struct CRYPTO_dynlock_value * lock, char * file, int line ) {
	if ( mode & CRYPTO_LOCK ) {
		mtx_lock( &lock->entryLock );
		if ( mode & CRYPTO_READ ) {
			unsigned int old = atomic_fetch_add_explicit( &lock->numReaders, 1, memory_order_relaxed );
			if ( old == 0 ) {
				mtx_lock( &lock->writerLock );
			}
		} else {
			mtx_lock( &lock->writerLock );
		}
		mtx_unlock( &lock->entryLock );
	} else {
		if ( mode & CRYPTO_READ ) {
			unsigned int old = atomic_fetch_sub_explicit( &lock->numReaders, 1, memory_order_relaxed );
			if ( old == 1 ) {
				mtx_unlock( &lock->writerLock );
			}
		} else {
			mtx_unlock( &lock->writerLock );
		}
	}
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
