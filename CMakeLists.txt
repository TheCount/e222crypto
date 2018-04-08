cmake_minimum_required( VERSION 3.1 )
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

# pkg-config
include( GNUInstallDirs )
set( PKGCONFIG_PREFIX "${CMAKE_INSTALL_PREFIX}" )
set( PKGCONFIG_EXEC_PREFIX "${CMAKE_INSTALL_BINDIR}" )
set( PKGCONFIG_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}" )
set( PKGCONFIG_LIBDIR "${CMAKE_INSTALL_LIBDIR}" )
set( PKGCONFIG_NAME "${PROJECT_NAME}" )
set( PKGCONFIG_DESC "E-222" )
set( PKGCONFIG_VERSION "${E222CRYPTO_VERSION}" )
set( PKGCONFIG_REQUIRES_PRIVATE "libcrypto" )
configure_file( "${CMAKE_CURRENT_SOURCE_DIR}/${PKGCONFIG_NAME}.pc.in" "${CMAKE_CURRENT_BINARY_DIR}/${PKGCONFIG_NAME}.pc" @ONLY )

# Compiler settings
set( CMAKE_C_STANDARD 11 )

# Build subdirs
add_subdirectory( src )
add_subdirectory( test )
