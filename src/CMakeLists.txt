set( E222CRYPTO_LIB ${PROJECT_NAME} )
if( UNIX )
	set( E222CRYPTO_LIB_STATIC ${E222CRYPTO_LIB} )
else()
	set( E222CRYPTO_LIB_STATIC "${E222CRYPTO_LIB}_static" )
endif()

set( E222CRYPTO_LIB_SOURCES
	curve.c
	init.c
	rand.c
	threads.c
)
set( E222CRYPTO_LIB_LINK
	${CRYPTO_LIBRARIES}
	tinycthread
)
include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
)
link_directories(
	${CRYPTO_LIBRARY_DIRS}
)

add_library( e222crypto SHARED ${E222CRYPTO_LIB_SOURCES} )
target_link_libraries( e222crypto ${E222CRYPTO_LIB_LINK} )
set_target_properties( e222crypto PROPERTIES VERSION ${LIBE222CRYPTO_VERSION} SOVERSION ${LIBE222CRYPTO_SOVERSION} OUTPUT_NAME ${E222CRYPTO_LIB} )
add_library( e222crypto_static STATIC ${E222CRYPTO_LIB_SOURCES} )
target_link_libraries( e222crypto_static ${E222CRYPTO_LIB_LINK} )
set_target_properties( e222crypto_static PROPERTIES OUTPUT_NAME ${E222CRYPTO_LIB_STATIC} )

add_subdirectory( tinycthread )
