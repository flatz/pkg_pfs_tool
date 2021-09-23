#pragma once

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#	ifndef O_LARGEFILE
#		define O_LARGEFILE 0
#	endif

	typedef off64_t fileoff_t;
#else
#	ifndef O_BINARY
#		define O_BINARY 0
#	endif

	typedef off_t fileoff_t;
#endif

#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)

#define JOIN_HELPER(a, b) a##b
#define JOIN(a, b) JOIN_HELPER(a, b)

#define COUNT_OF(x) (sizeof(x) / sizeof(x[0]))

#define UNUSED(x) (void)(x)

#define CT_SIZE_ASSERT(name, size) \
	_Static_assert(sizeof(name) == (size), "Size of " #name " != " #size)

#define CT_FIELD_OFFSET_ASSERT(name, member, offset) \
	_Static_assert(offsetof(name, member) == (offset), "Offset of " #name "." #member " != " #offset)

#define PACKED __attribute__ ((packed))

#if defined(__GNUC__) || defined(__clang__)
#	define ALIGNED(x) __attribute__ ((aligned(x)))
#else
#	error Unsupported compiler.
#endif

#define DECLARE_ALIGNED_TYPE(type, x) typedef type ALIGNED(x)

#define U16C(x) (uint16_t)(JOIN(x,   U))
#define U32C(x) (uint32_t)(JOIN(x,   U))
#define U64C(x) (uint64_t)(JOIN(x, ULL))

#define SWAP16(x) \
	((uint16_t)( \
		(((uint16_t)(x) & U16C(0x00FF)) << 8) | \
		(((uint16_t)(x) & U16C(0xFF00)) >> 8) \
	))

#define SWAP32(x) \
	((uint32_t)( \
		(((uint32_t)(x) & U32C(0x000000FF)) << 24) | \
		(((uint32_t)(x) & U32C(0x0000FF00)) <<  8) | \
		(((uint32_t)(x) & U32C(0x00FF0000)) >>  8) | \
		(((uint32_t)(x) & U32C(0xFF000000)) >> 24) \
	))

#define SWAP64(x) \
	((uint64_t)( \
		(uint64_t)(((uint64_t)(x) & U64C(0x00000000000000FF)) << 56) | \
		(uint64_t)(((uint64_t)(x) & U64C(0x000000000000FF00)) << 40) | \
		(uint64_t)(((uint64_t)(x) & U64C(0x0000000000FF0000)) << 24) | \
		(uint64_t)(((uint64_t)(x) & U64C(0x00000000FF000000)) <<  8) | \
		(uint64_t)(((uint64_t)(x) & U64C(0x000000FF00000000)) >>  8) | \
		(uint64_t)(((uint64_t)(x) & U64C(0x0000FF0000000000)) >> 24) | \
		(uint64_t)(((uint64_t)(x) & U64C(0x00FF000000000000)) >> 40) | \
		(uint64_t)(((uint64_t)(x) & U64C(0xFF00000000000000)) >> 56) \
	))

#define LE16(x) (x)
#define LE32(x) (x)
#define LE64(x) (x)

#define BE16(x) SWAP16(x)
#define BE32(x) SWAP32(x)
#define BE64(x) SWAP64(x)

#ifndef MIN
#	define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#	define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define MAGIC4_BE(c0, c1, c2, c3) ( \
		(uint32_t)(uint8_t)(c0) | ((uint32_t)(uint8_t)(c1) << 8) | \
		((uint32_t)(uint8_t)(c2) << 16) | ((uint32_t)(uint8_t)(c3) << 24) \
	)
#define MAGIC4_LE(c0, c1, c2, c3) MAGIC4_BE(c3, c2, c1, c0)

#define MAGIC8_BE(c0, c1, c2, c3, c4, c5, c6, c7) ( \
		(uint64_t)(uint8_t)(c0) | ((uint64_t)(uint8_t)(c1) << 8) | \
		((uint64_t)(uint8_t)(c2) << 16) | ((uint64_t)(uint8_t)(c3) << 24) | \
		((uint64_t)(uint8_t)(c4) << 32) | ((uint64_t)(uint8_t)(c5) << 40) | \
		((uint64_t)(uint8_t)(c6) << 48) | ((uint64_t)(uint8_t)(c7) << 56) \
	)
#define MAGIC8_LE(c0, c1, c2, c3, c4, c5, c6, c7) MAGIC8_BE(c7, c6, c5, c4, c3, c2, c1, c0)

#define TYPE_PAD(size) char JOIN(_pad_, __COUNTER__)[size]
#define TYPE_BEGIN(name, size) name { union { TYPE_PAD(size)
#define TYPE_END() }; }
#define TYPE_FIELD(field, offset) struct { TYPE_PAD(offset); field; }

enum cb_result {
	CB_RESULT_STOP,
	CB_RESULT_CONTINUE,
};

#define PKG_PFS_TOOL_VERSION "1.8.2"

#define CONFIG_FILE "config.ini"

//#define ENABLE_REPACK_SUPPORT
#define ENABLE_EKC_KEYGEN
#define ENABLE_SD_KEYGEN
