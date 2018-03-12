cmake_minimum_required( VERSION 3.0 )
project( e222crypto )
enable_testing()

# Version
set( E222CRYPTO_VERSION_MAJOR 0 ) # increases with incompatible API changes
set( E222CRYPTO_VERSION_MINOR 0 ) # increases with backwards compatible API changes
set( E222CRYPTO_VERSION_PATCH 0 ) # increases with each non-API-changing release
set( E222CRYPTO_VERSION "${E222CRYPTO_VERSION_MAJOR}.${E222CRYPTO_VERSION_MINOR}.${E222CRYPTO_VERSION_PATCH}" )
set( LIBE222CRYPTO_SOVERSION 0 ) # increases with incompatible ABI changes
set( LIBE222CRYPTO_MINOR 0 ) # increases with backwards compatible ABI changes
set( LIBE222CRYPTO_RELEASE 0 ) # increases with code changes that do not affect the ABI
set( LIBE222CRYPTO_VERSION "${LIBE222CRYPTO_SOVERSION}.${LIBE222CRYPTO_MINOR}.${LIBE222CRYPTO_RELEASE}" )

# Dependencies
find_package( PkgConfig REQUIRED )
pkg_search_module( CRYPTO REQUIRED libcrypto )

# Build subdirs
add_subdirectory( src )
add_subdirectory( test )
