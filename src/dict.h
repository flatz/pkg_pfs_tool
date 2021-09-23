#pragma once

#include "common.h"

#include <uthash.h>

struct string_dict_entry {
	char* key;
	char* value;
	UT_hash_handle hh;
};

enum {
	STRING_DICT_FLAG_TRIM_KEY = (1 << 0),
	STRING_DICT_FLAG_TRIM_VALUE = (1 << 1),
	STRING_DICT_FLAG_TRIM_ALL = (STRING_DICT_FLAG_TRIM_KEY | STRING_DICT_FLAG_TRIM_VALUE),
};

struct string_dict_entry* string_dict_load_from_filep(FILE* fp, char sep, unsigned int flags);
struct string_dict_entry* string_dict_load_from_file(const char* file_path, char sep, unsigned int flags);

void string_dict_free(struct string_dict_entry* dict);

const char* string_dict_find(struct string_dict_entry* dict, const char* key);

void string_dict_dump(struct string_dict_entry* dict);
