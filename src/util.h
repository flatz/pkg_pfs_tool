#pragma once

#include "common.h"

void info(const char* fmt, ...);
void warning(const char* fmt, ...);
void error(const char* fmt, ...);

int is_exists(const char* path);
int is_file(const char* path);
int is_directory(const char* path);
int is_drive_letter(const char* path);
int is_readable(const char* path);
int is_writeable(const char* path);

int has_magic(void* source, size_t source_size, const void* magic, size_t magic_size);
int file_has_magic(const char* path, const void* magic, size_t magic_size);

uint64_t get_file_size(const char* path);

int make_directory(const char* path, int mode);
int make_directories(const char* path, int mode);

typedef int (*list_directory_cb)(void* arg, const char* parent_name, const char* child_name, unsigned int mode);
int list_directory_r(const char* directory, list_directory_cb cb, void* cb_arg);

int write_to_file(const char* path, const void* data, size_t size, ssize_t* nwritten, int mode);

unsigned int ctz_32(uint32_t n);
unsigned int ctz_64(uint64_t n);

unsigned int popcnt_32(uint32_t n);
unsigned int popcnt_64(uint64_t n);

unsigned int ilog2_32(uint32_t n);
unsigned int ilog2_64(uint64_t n);

ptrdiff_t str_index(const char* s, char ch);

void strip_trailing_newline(char* s);

char* ltrim_ex(char* s, int (* check)(int ch));
char* ltrim(char* s);
char* rtrim_ex(char* s, int (* check)(int ch));
char* rtrim(char* s);
char* rtrim_slashes(char* s);

static inline char* trim_ex(char* s, int (* check)(int ch)) {
	rtrim_ex(s, check);
	ltrim_ex(s, check);
	return s;
}

static inline char* trim(char* s) {
	rtrim(s);
	ltrim(s);
	return s;
}

int starts_with(const char* haystack, const char* needle);
int starts_with_nocase(const char* haystack, const char* needle);

int ends_with(const char* haystack, const char* needle);
int ends_with_nocase(const char* haystack, const char* needle);

int wildcard_match(const char* data, const char* mask);
int wildcard_match_nocase(const char* data, const char* mask);

const char* path_get_separator(const char* path);
const char* path_skip_separator(const char* path);
const char* path_get_file_name(char* file_name, size_t max_size, const char* path);
const char* path_get_directory(char* directory, size_t max_size, const char* path);
const char* path_slashes_to_backslashes(char* path);
const char* path_backslashes_to_slashes(char* path);

uint64_t x_to_u64(const char* hex);
uint8_t* x_to_u8_buffer(const char* hex, size_t* size);

int generate_crypto_random(uint8_t* data, size_t data_size);

int bin_to_readable(char* out_data, size_t max_out_size, const uint8_t* in_data, size_t in_size);

int hex_print_internal(const void* data, size_t data_size, size_t indent, void (*cb)(void* arg, const char* s), void* arg);
void snprintf_hex(char* s, size_t max_size, const void* data, size_t data_size);
void fprintf_hex(FILE* fp, const void* data, size_t data_size, size_t indent);

#if defined(_WIN32)
ssize_t getline(char** linep, size_t* n, FILE* stream);
#endif

static inline size_t align_up(size_t size, size_t alignment) {
	return ((size - 1) & ~(alignment - 1)) + alignment;
}

static inline uint32_t align_up_32(uint32_t size, uint32_t alignment) {
	return ((size - 1) & ~(alignment - 1)) + alignment;
}

static inline uint64_t align_up_64(uint64_t size, uint64_t alignment) {
	return ((size - 1) & ~(alignment - 1)) + alignment;
}

static inline uint8_t* wbe32(uint8_t* p, uint32_t v) {
	*p++ = (uint8_t)(v >> 24);
	*p++ = (uint8_t)(v >> 16);
	*p++ = (uint8_t)(v >> 8);
	*p++ = (uint8_t)(v);

	return p;
}

static inline uint8_t* wle32(uint8_t* p, uint32_t v) {
	*p++ = (uint8_t)(v);
	*p++ = (uint8_t)(v >> 8);
	*p++ = (uint8_t)(v >> 16);
	*p++ = (uint8_t)(v >> 24);

	return p;
}
