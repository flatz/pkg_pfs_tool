#include "util.h"

#if defined(_WIN32)
#	include <windows.h>
#	include <wincrypt.h>
#endif

#include <dirent.h>

void info(const char* fmt, ...) {
	char buffer[1024];
	va_list args;

	assert(fmt != NULL);

	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	fprintf(stdout, "%s\n", buffer);
}

void warning(const char* fmt, ...) {
	char buffer[1024];
	va_list args;

	assert(fmt != NULL);

	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	fprintf(stderr, "WARNING: %s\n", buffer);
}

void error(const char* fmt, ...) {
	char buffer[1024];
	va_list args;

	assert(fmt != NULL);

	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	fprintf(stderr, "ERROR: %s\n", buffer);
	exit(1);
}

int is_exists(const char* path) {
	struct stat64 info;
	assert(path != NULL);
	return stat64(path, &info) == 0;
}

int is_file(const char* path) {
	struct stat64 info;
	assert(path != NULL);
	if (stat64(path, &info) < 0)
		return 0;
	return S_ISREG(info.st_mode);
}

int is_directory(const char* path) {
	struct stat64 info;
	assert(path != NULL);
	if (stat64(path, &info) < 0)
		return 0;
	return S_ISDIR(info.st_mode);
}

int is_drive_letter(const char* path) {
	assert(path != NULL);
	if (toupper(path[0]) >= 'A' && toupper(path[0]) <= 'Z' && path[1] == ':' && path[2] == '\0')
		return 1;
	return 0;
}

int is_readable(const char* path) {
	assert(path != NULL);
	return access(path, R_OK) == 0;
}

int is_writeable(const char* path) {
	assert(path != NULL);
	return access(path, W_OK) == 0;
}

int has_magic(void* source, size_t source_size, const void* magic, size_t magic_size) {
	assert(source != NULL);
	assert(magic != NULL);

	if (source_size < magic_size)
		return 0;

	return memcmp(source, magic, magic_size) == 0;
}

int file_has_magic(const char* path, const void* magic, size_t magic_size) {
	FILE* fp = NULL;
	void* tmp = NULL;
	int status = 0;

	assert(path != NULL);
	assert(magic != NULL);

	fp = fopen(path, "rb");
	if (!fp)
		goto error;

	tmp = malloc(magic_size);
	if (!tmp)
		goto error;
	memset(tmp, 0, magic_size);

	if (fread(tmp, 1, magic_size, fp) != magic_size)
		goto error;

	status = has_magic(tmp, magic_size, magic, magic_size);

error:
	if (tmp)
		free(tmp);
	if (fp)
		fclose(fp);

	return status;
}

uint64_t get_file_size(const char* path) {
	struct stat64 info;
	assert(path != NULL);
	if (stat64(path, &info) < 0)
		return (uint64_t)-1;
	return (uint64_t)info.st_size;
}

int make_directory(const char* path, int mode) {
	assert(path != NULL);

#ifdef __linux__
	return mkdir(path, mode) == 0;
#else
	UNUSED(mode);

	return mkdir(path) == 0;
#endif
}

int make_directories(const char* path, int mode) {
	char directory[PATH_MAX];
	const char* part;
	const char* separator;
	size_t part_length;

	assert(path != NULL);

	part = path;
	while (*part != '\0') {
		separator = path_get_separator(part);
		if (*separator != '\0')
			part_length = separator - path;
		else
			part_length = strlen(path);
		if (part_length > sizeof(directory) - 1)
			return 0;
		if (part_length != 0) {
			memset(directory, 0, sizeof(directory));
			strncpy(directory, path, part_length);

			if (part == path && is_drive_letter(directory)) {
				goto next;
			} else if (!is_directory(directory)) {
				if (!is_exists(directory)) {
					if (!make_directory(directory, mode)) {
						warning("Unable to create directory: %s", directory);
						return 0;
					}
				} else {
					warning("Unable to create directory because path already exists: %s", directory);
					return 0;
				}
			}
		}
next:
		part = path_skip_separator(separator);
	}

	return 1;
}

static char* join_path(const char* parent, const char* child) {
	char* buf = NULL;
	char* p;
	size_t parent_len, child_len, len;

	parent_len = (parent && *parent != '\0') ? strlen(parent) : 0;
	child_len = (child && *child != '\0') ? strlen(child) : 0;

	len = parent_len;
	if (parent_len > 0 && child_len > 0)
		len += 1;
	len += child_len;

	p = buf = (char*)malloc(len + 1);
	if (!p)
		goto error;

	if (parent_len > 0) {
		strncpy(p, parent, parent_len);
		p += parent_len;

		if (child_len > 0)
			*p++ = '/';
	}

	if (child_len > 0) {
		strncpy(p, child, child_len);
		p += child_len;
	}

	*p = '\0';

	return buf;

error:
	if (buf)
		free(buf);

	return NULL;
}

int list_directory_r_internal(const char* parent_name, const char* name, list_directory_cb cb, void* cb_arg) {
	char* full_name = NULL;
	char* tmp_name = NULL;
	DIR* dp = NULL;
	struct dirent* entry;
	struct stat64 stat_buf;
	int status = 0;

	full_name = join_path(parent_name, name);
	if (!full_name)
		goto error;

	dp = opendir(full_name);
	if (!dp)
		goto error;

	while ((entry = readdir(dp)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		tmp_name = join_path(full_name, entry->d_name);
		if (!tmp_name)
			goto error;
		if (stat64(tmp_name, &stat_buf) < 0)
			goto error;
		free(tmp_name);
		tmp_name = NULL;

		if (cb && (*cb)(cb_arg, full_name, entry->d_name, stat_buf.st_mode) == CB_RESULT_STOP)
			goto done;

		if (S_ISDIR(stat_buf.st_mode))
			list_directory_r_internal(full_name, entry->d_name, cb, cb_arg);
	}

done:
	status = 1;

error:
	if (tmp_name)
		free(tmp_name);

	if (dp)
		closedir(dp);

	if (full_name)
		free(full_name);

	return status;
}

int list_directory_r(const char* directory, list_directory_cb cb, void* cb_arg) {
	return list_directory_r_internal(NULL, directory, cb, cb_arg);
}

int write_to_file(const char* path, const void* data, size_t size, ssize_t* nwritten, int mode) {
	int fd = -1;
	int status = 0;
	ssize_t n;

	assert(path != NULL);
	assert(data != NULL);

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, mode);
	if (fd < 0)
		goto error;

	n = write(fd, data, size);
	if (n < 0)
		goto error;
	if (nwritten)
		*nwritten = n;

	status = 1;

error:
	if (fd > 0)
		close(fd);

	return status;
}

unsigned int ctz_32(uint32_t n) {
#if defined(__GNUC__) || defined(__clang__)
	return n ? (unsigned int)__builtin_ctz(n) : (unsigned int)-1;
#else
#	error Unsupported compiler.
#endif
}

unsigned int ctz_64(uint64_t n) {
#if defined(__GNUC__) || defined(__clang__)
	return n ? (unsigned long long)__builtin_ctzll(n) : (unsigned int)-1;
#else
#	error Unsupported compiler.
#endif
}

unsigned int popcnt_32(uint32_t n) {
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_popcount(n);
#else
#	error Unsupported compiler.
#endif
}

unsigned int popcnt_64(uint64_t n) {
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_popcountll(n);
#else
#	error Unsupported compiler.
#endif
}

unsigned int ilog2_32(uint32_t n) {
#if defined(__GNUC__) || defined(__clang__)
	return ((unsigned int)(sizeof(n) * CHAR_BIT) - (unsigned int)__builtin_clzl((n << 1) - 1) - 1);
#else
#	error Unsupported compiler.
#endif
}

unsigned int ilog2_64(uint64_t n) {
#if defined(__GNUC__) || defined(__clang__)
	return ((unsigned int)(sizeof(n) * CHAR_BIT) - (unsigned int)__builtin_clzll((n << 1) - 1) - 1);
#else
#	error Unsupported compiler.
#endif
}

ptrdiff_t str_index(const char* s, char ch) {
	char* p;
	assert(s != NULL);
	p = strchr(s, ch);
	return (p != NULL ? (ptrdiff_t)(p - s) : -1);
}

void strip_trailing_newline(char* s) {
	size_t len;
	assert(s != NULL);
	len = strlen(s);
	if (len != 0 && s[len - 1] == '\n')
		s[len - 1] = '\0';
}

char* ltrim_ex(char* s, int (* check)(int ch)) {
	size_t start, end;
	assert(s != NULL);
	assert(check != NULL);
	if (*s == '\0')
		return s;
	for (start = 0; s[start] != '\0' && check(s[start]); ++start);
	for (end = start + 1; s[end] != '\0'; ++end);
	memmove(s, s + start, end - start + 1);
	return s;
}

char* rtrim_ex(char* s, int (* check)(int ch)) {
	char* end;
	size_t len;
	assert(s != NULL);
	assert(check != NULL);
	if (*s == '\0')
		return s;
	len = strlen(s);
	for (end = &s[len - 1]; end >= s && check(*end); --end);
	end[1] = '\0';
	return end >= s ? end : NULL;
}

static int check_space(int ch) {
	return isspace(ch);
}

static int check_slashes(int ch) {
	return (ch == '/') || (ch == '\\');
}

char* ltrim(char* s) {
	return ltrim_ex(s, &check_space);
}

char* rtrim(char* s) {
	return rtrim_ex(s, &check_space);
}

char* rtrim_slashes(char* s) {
	return rtrim_ex(s, &check_slashes);
}

int starts_with(const char* haystack, const char* needle) {
	int i;

	assert(haystack != NULL);
	assert(needle != NULL);

	for (i = 0; haystack[i] != '\0'; ++i) {
		if (haystack[i] != needle[i])
			break;
	}

	return needle[i] == '\0';
}

int starts_with_nocase(const char* haystack, const char* needle) {
	int i;

	assert(haystack != NULL);
	assert(needle != NULL);

	for (i = 0; haystack[i] != '\0'; ++i) {
		if (tolower(haystack[i]) != tolower(needle[i]))
			break;
	}

	return needle[i] == '\0';
}

int ends_with(const char* haystack, const char* needle) {
	ptrdiff_t diff;
	int i;

	assert(haystack != NULL);
	assert(needle != NULL);

	diff = strlen(haystack) - strlen(needle);
	if (diff < 0)
		return 0;

	for (i = 0; needle[i] != '\0'; ++i) {
		if (needle[i] != haystack[i + diff])
			return 0;
	}

	return 1;
}

int ends_with_nocase(const char* haystack, const char* needle) {
	ptrdiff_t diff;
	int i;

	assert(haystack != NULL);
	assert(needle != NULL);

	diff = strlen(haystack) - strlen(needle);
	if (diff < 0)
		return 0;

	for (i = 0; needle[i] != '\0'; ++i) {
		if (tolower(needle[i]) != tolower(haystack[i + diff]))
			return 0;
	}

	return 1;
}

const char* path_get_separator(const char* path) {
	const char* p;

	assert(path != NULL);

	if (*path == '\0' || *path == '/' || *path == '\\')
		return path;

	p = path;
	do {
		p++;
	} while (*p != '\0' && *p != '/' && *p != '\\');

	return p;
}

const char* path_skip_separator(const char* path) {
	const char* p;

	assert(path != NULL);

	if (*path != '/' && *path != '\\')
		return path;

	p = path;
	do {
		p++;
	} while (*p == '/' || *p == '\\');

	return p;
}

const char* path_get_file_name(char* file_name, size_t max_size, const char* path) {
	const char* p;

	assert(file_name != NULL);
	assert(path != NULL);

	p = strrchr(path, '/');
	if (!p)
		p = strrchr(path, '\\');
	if (!p)
		strncpy(file_name, path, max_size);
	else
		strncpy(file_name, p + 1, max_size);

	return file_name;
}

const char* path_get_directory(char* directory, size_t max_size, const char* path) {
	const char* p;
	size_t len;

	assert(directory != NULL);
	assert(path != NULL);

	p = strrchr(path, '/');
	if (!p)
		p = strrchr(path, '\\');
	if (!p) {
		directory[0] = '\0';
	} else {
		len = p - path;
		strncpy(directory, path, MIN(len, max_size));
		directory[len] = '\0';
	}

	return directory;
}

const char* path_slashes_to_backslashes(char* path) {
	size_t len, i;

	assert(path != NULL);

	for (len = strlen(path), i = 0; i < len; ++i) {
		if (path[i] != '/')
			continue;
		path[i] = '\\';
	}

	return path;
}

const char* path_backslashes_to_slashes(char* path) {
	size_t len, i;

	assert(path != NULL);

	for (len = strlen(path), i = 0; i < len; ++i) {
		if (path[i] != '\\')
			continue;
		path[i] = '/';
	}

	return path;
}

uint64_t x_to_u64(const char* hex) {
	uint64_t result;
	size_t len;
	int c, t;

	assert(hex != NULL);

	result = 0;
	len = strlen(hex);

	while (len--) {
		c = *hex++;
		if (c >= '0' && c <= '9')
			t = c - '0';
		else if (c >= 'a' && c <= 'f')
			t = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			t = c - 'A' + 10;
		else
			t = 0;
		result |= (uint64_t)t << (len * 4);
	}

	return result;
}

uint8_t* x_to_u8_buffer(const char* hex, size_t* size) {
	char tmp[3] = { '\0' };
	uint8_t* result = NULL;
	uint8_t* ptr;
	size_t len = 0;

	assert(hex != NULL);

	len = strlen(hex);
	if (len % 2 != 0)
		goto error;

	result = (uint8_t*)malloc(len);
	if (!result)
		goto error;
	memset(result, 0, len);

	if (size)
		*size = len / 2;

	ptr = result;
	while (len--) {
		tmp[0] = *hex++;
		tmp[1] = *hex++;
		*ptr++ = (uint8_t)x_to_u64(tmp);
	}

error:
	if (!result) {
		if (size)
			*size = 0;
	}

	return result;
}

int generate_crypto_random(uint8_t* data, size_t data_size) {
#if defined(__linux__)
	int fd = -1;
	size_t offset;
	ssize_t ret;
	int status = 0;

	assert(data != NULL);

	fd = open("/dev/random", O_RDONLY | O_BINARY);
	if (fd < 0) {
		warning("Unable to open random device.");
		goto error;
	}

	for (offset = 0; offset < data_size; ) {
		ret = read(fd, data + offset, data_size - offset);
		if (ret < 0) {
			warning("Unable to read from random device.");
			goto error;
		}

		offset += ret;
	}

	status = 1;

error:
	if (fd > 0)
		close(fd);

	return status;
#elif defined(_WIN32)
	HCRYPTPROV prov = (HCRYPTPROV)0;
	int status = 0;

	assert(data != NULL);

	if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		warning("Unable to acquire crypto provider context.");
		goto error;
	}

	if (!CryptGenRandom(prov, data_size, data)) {
		warning("Unable to generate random data.");
		goto error;
	}

	status = 1;

error:
	if (prov)
		CryptReleaseContext(prov, 0);

	return status;
#endif
}

int bin_to_readable(char* out_data, size_t max_out_size, const uint8_t* in_data, size_t in_size) {
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	static const size_t alphabet_len = sizeof(alphabet) - 1;
	size_t index;
	size_t i;
	int status = 0;

	assert(out_data != NULL);
	assert(in_data != NULL);

	if (max_out_size < in_size)
		goto error;

	for (i = 0; i < in_size; ++i) {
		index = (size_t)in_data[i] % alphabet_len;
		out_data[i] = alphabet[index];
	}

	status = 1;

error:
	return status;
}

static inline void hex_print_indent(size_t indent, void (*cb)(void* arg, const char* s), void* arg) {
	size_t i;
	for (i = 0; i < indent; ++i)
		(*cb)(arg, " ");
}

int hex_print_internal(const void* data, size_t data_size, size_t indent, void (*cb)(void* arg, const char* s), void* arg) {
	static const char* digits = "0123456789ABCDEF";
	const uint8_t* p = (const uint8_t*)data;
	char tmp[4] = { 0 };
	uint8_t c;
	size_t i;
	int status = 0;

	if (!data)
		goto error;
	if (!cb)
		goto error;

	if (data_size == 0)
		goto done;

	hex_print_indent(indent, cb, arg);

	for (i = 0; i < data_size; ++i) {
		if (i > 0 && (i & 0xF) == 0) {
			(*cb)(arg, "\n");
			hex_print_indent(indent, cb, arg);
		}

		c = p[i];
		tmp[0] = digits[c >> 4];
		tmp[1] = digits[c & 0xF];
		(*cb)(arg, tmp);

		if (i + 1 < data_size)
			(*cb)(arg, " ");
	}
	(*cb)(arg, "\n");

done:
	status = 1;

error:
	return status;
}

static void fprintf_hex_cb(void* arg, const char* s) {
	FILE* fp = (FILE*)arg;
	fputs(s, fp);
}

void fprintf_hex(FILE* fp, const void* data, size_t data_size, size_t indent) {
	hex_print_internal(data, data_size, indent, &fprintf_hex_cb, fp);
}

struct snprintf_hex_args {
	char* buf;
	size_t max_size;
	size_t offset;
};

static void snprintf_hex_cb(void* arg, const char* s) {
	struct snprintf_hex_args* args = (struct snprintf_hex_args*)arg;
	size_t len = strlen(s);
	if (isspace(*s))
		return;
	if (args->offset + len + 1 > args->max_size)
		return;
	strcpy(args->buf + args->offset, s);
	args->offset += len;
	args->buf[args->offset] = '\0';
}

void snprintf_hex(char* s, size_t max_size, const void* data, size_t data_size) {
	struct snprintf_hex_args args = { s, max_size, 0 };
	memset(s, 0, max_size);
	hex_print_internal(data, data_size, 0, &snprintf_hex_cb, &args);
}

#if defined(_WIN32)
ssize_t getline(char** linep, size_t* n, FILE* stream) {
	size_t pos;
	int c;

	if (linep == NULL || stream == NULL || n == NULL) {
		errno = EINVAL;
		return -1;
	}

	c = fgetc(stream);
	if (c == EOF) {
		return -1;
	}

	if (*linep == NULL) {
		*linep = malloc(128);
		if (*linep == NULL) {
			return -1;
		}
		*n = 128;
	}

	pos = 0;
	while (c != EOF) {
		if (pos + 1 >= *n) {
			size_t new_size = *n + (*n >> 2);
			if (new_size < 128) {
				new_size = 128;
			}
			char* new_ptr = realloc(*linep, new_size);
			if (new_ptr == NULL) {
				return -1;
			}
			*n = new_size;
			*linep = new_ptr;
		}

		(*linep)[pos++] = c;
		if (c == '\n') {
			break;
		}
		c = fgetc(stream);
	}

	(*linep)[pos] = '\0';

	return pos - 1;
}
#endif
