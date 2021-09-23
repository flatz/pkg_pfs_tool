find_path(UTHASH_INCLUDE_DIR NAMES uthash.h HINTS "${THIRDPARTY_INCLUDE_DIR}/uthash" NO_DEFAULT_PATH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(UTHASH DEFAULT_MSG UTHASH_INCLUDE_DIR)
mark_as_advanced(UTHASH_INCLUDE_DIR)
