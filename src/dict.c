#include "dict.h"
#include "util.h"

struct string_dict_entry* string_dict_load_from_filep(FILE* fp, char sep, unsigned int flags) {
	struct string_dict_entry* dict = NULL;
	struct string_dict_entry* entry;
	char* buf = NULL;
	size_t buf_size = 0;
	ssize_t nread;
	size_t line_no = 1;
	size_t key_len, value_len;
	char* key = NULL;
	char* value = NULL;
	char* p;

	assert(fp != NULL);

	for (;;) {
		nread = getline(&buf, &buf_size, fp);
		if (nread == -1)
			break;
		++line_no;
		p = strchr(buf, '\n');
		if (p)
			*p = '\0';
		if (*buf == '\0' || *buf == '#')
			continue;
		p = strchr(buf, sep);
		if (!p) {
bad_line:
			warning("Bad line in dictionary at line %" PRIuMAX ": %s", (uintmax_t)(line_no - 1), buf);
			continue;
		}

		key_len = p - buf;
		key = malloc(key_len + 1);
		if (!key) {
			warning("Unable to allocate memory for key of size %" PRIuMAX " bytes.", (uintmax_t)(key_len + 1));
			goto error;
		}
		strncpy(key, buf, key_len);
		key[key_len] = '\0';

		if (flags & STRING_DICT_FLAG_TRIM_KEY) {
			trim(key);
			key_len = strlen(key);
		}

		if (key_len == 0)
			goto bad_line;

		value_len = strlen(++p);
		value = malloc(value_len + 1);
		if (!value) {
			warning("Unable to allocate memory for value of size %" PRIuMAX " bytes.", (uintmax_t)(value_len + 1));
			goto error;
		}
		strncpy(value, p, value_len);
		value[value_len] = '\0';

		if (flags & STRING_DICT_FLAG_TRIM_VALUE) {
			trim(value);
			value_len = strlen(value);
		}

		HASH_FIND_STR(dict, key, entry);
		if (entry == NULL) {
			entry = (struct string_dict_entry*)malloc(sizeof(*entry));
			if (!entry) {
				warning("Unable to allocate memory for entry.");
				goto error;
			}
			memset(entry, 0, sizeof(*entry));
			HASH_ADD_KEYPTR(hh, dict, key, key_len, entry);
		} else {
			free(entry->key);
			free(entry->value);
		}

		entry->key = key;
		key = NULL;

		entry->value = value;
		value = NULL;
	}

	if (buf)
		free(buf);

	return dict;

error:
	if (key)
		free(key);
	if (value)
		free(value);

	if (buf)
		free(buf);

	if (dict)
		string_dict_free(dict);

	return NULL;
}

struct string_dict_entry* string_dict_load_from_file(const char* file_path, char sep, unsigned int flags) {
	struct string_dict_entry* dict = NULL;
	FILE* fp = NULL;

	fp = fopen(file_path, "r");
	if (!fp) {
		warning("Unable to open file: %s", file_path);
		goto error;
	}

	dict = string_dict_load_from_filep(fp, sep, flags);
	if (!dict)
		goto error;

error:
	if (fp)
		fclose(fp);

	return dict;
}

void string_dict_free(struct string_dict_entry* dict) {
	struct string_dict_entry* entry;
	struct string_dict_entry* tmp;

	if (!dict)
		return;

	HASH_ITER(hh, dict, entry, tmp) {
		HASH_DEL(dict, entry);

		free(entry->key);
		free(entry->value);

		free(entry);
	}
}

const char* string_dict_find(struct string_dict_entry* dict, const char* key) {
	struct string_dict_entry* entry;

	assert(dict != NULL);

	HASH_FIND_STR(dict, key, entry);
	if (!entry)
		return NULL;

	return entry->value;
}

void string_dict_dump(struct string_dict_entry* dict) {
	struct string_dict_entry* entry;
	struct string_dict_entry* tmp;

	assert(dict != NULL);

	HASH_ITER(hh, dict, entry, tmp) {
		info("%s = %s", entry->key, entry->value);
	}
}