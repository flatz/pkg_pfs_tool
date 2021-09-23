cmake_minimum_required(VERSION 3.12)
project(pkg_pfs_tool)

#
# Compiler settings.
#

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-masm=intel -march=native)
add_compile_options(-Wall -Wextra -Werror-implicit-function-declaration -Wno-unused-function -Wno-unused-label)

# just install libasan6 (or w/e) then flip this ON
set(ENABLE_ASAN OFF)
if(ENABLE_ASAN)
	add_compile_options(-ggdb -O0)
	set(ASAN_FLAGS -fsanitize=address)
	add_compile_options(${ASAN_FLAGS})
	add_link_options(${ASAN_FLAGS})
endif()

if(WIN32)
	add_compile_definitions(WIN32 _WIN32)
	add_compile_definitions(WIN32_LEAN_AND_MEAN)
	add_compile_definitions(NOMINMAX)
endif()

if(UNIX OR MSYS)
	add_compile_definitions(_GNU_SOURCE)
endif()

add_compile_definitions(
	$<$<CONFIG:DEBUG>:_DEBUG>
	$<$<CONFIG:RELEASE>:NDEBUG>
)

#
# Third-party dependendices.
#

string(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(THIRDPARTY_ROOT_DIR "${CMAKE_SOURCE_DIR}/thirdparty")
set(THIRDPARTY_INCLUDE_DIR "${THIRDPARTY_ROOT_DIR}/include")
if(MINGW)
	if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
		set(THIRDPARTY_LIB_DIR "${THIRDPARTY_ROOT_DIR}/lib/win64")
	else()
		set(THIRDPARTY_LIB_DIR "${THIRDPARTY_ROOT_DIR}/lib/win32")
	endif()
elseif(UNIX)
	if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
		set(THIRDPARTY_LIB_DIR "${THIRDPARTY_ROOT_DIR}/lib/linux64")
	else()
		set(THIRDPARTY_LIB_DIR "${THIRDPARTY_ROOT_DIR}/lib/linux32")
	endif()
endif()

if(MINGW)
	# hack to force static zlib (but it doesn't mess anything else up...)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	list(APPEND LIBS ucrt)
endif()

find_package(ZLIB REQUIRED)
include_directories(${ZLIB_INCLUDE_DIRS})
list(APPEND LIBS ${ZLIB_LIBRARIES})

find_package(MBEDTLS 2.24.0 REQUIRED)
include_directories(${MBEDTLS_INCLUDE_DIRS})
list(APPEND LIBS ${MBEDTLS_LIBRARIES})

find_package(UTHASH REQUIRED)
include_directories(${UTHASH_INCLUDE_DIRS})

#
# Project settings.
#

file(GLOB SRCS "src/*.c")
if(MINGW)
	file(GLOB MINGW_SRCS "src/mingw/*.c")
	list(APPEND SRCS ${MINGW_SRCS})
endif()
include_directories(src)

add_executable(pkg_pfs_tool ${SRCS})
target_link_libraries(pkg_pfs_tool ${LIBS})
