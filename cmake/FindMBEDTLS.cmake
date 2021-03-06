find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h HINTS "${THIRDPARTY_INCLUDE_DIR}" NO_DEFAULT_PATH)

find_library(MBEDTLS_LIBRARY mbedtls HINTS "${THIRDPARTY_LIB_DIR}" NO_DEFAULT_PATH)
find_library(MBEDX509_LIBRARY mbedx509 HINTS "${THIRDPARTY_LIB_DIR}" NO_DEFAULT_PATH)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto HINTS "${THIRDPARTY_LIB_DIR}" NO_DEFAULT_PATH)

set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MBEDTLS DEFAULT_MSG
    MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
