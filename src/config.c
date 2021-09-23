#include "config.h"

#define MAX_LINE_SIZE 1024
#define MAX_SECTION_SIZE 128
#define MAX_NAME_SIZE 128

static char* safe_strncpy(char* dst, const char* src, size_t size) {
	assert(dst != NULL);
	assert(src != NULL);
	assert(size != 0);

	strncpy(dst, src, size);
	dst[size - 1] = '\0';

	return dst;
}

static char* rstrip(char* s) {
	char* p;

	assert(s != NULL);

	p = s + strlen(s);
	while (p > s && isspace(*--p))
		*p = '\0';

	return s;
}

static char* lskip(const char* s) {
	while (*s != '\0' && isspace(*s))
		++s;
	return (char*)s;
}

static char* find_char_or_comment(const char* s, int c) {
	int is_white = 0;
	while (*s != '\0' && *s != c && !(is_white && *s == ';')) {
		is_white = isspace(*s);
		++s;
	}
	return (char*)s;
}

int parse_config_file(const char* path, parse_config_cb_t cb, void* arg) {
	char line_buf[MAX_LINE_SIZE];
	char section[MAX_SECTION_SIZE];
	char prev_name[MAX_NAME_SIZE];
	char* name;
	char* value;
	char* start;
	char* end;
	FILE *fp;
	int line;
	int error_line;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	memset(line_buf, 0, sizeof(line_buf));
	memset(section, 0, sizeof(section));
	memset(prev_name, 0, sizeof(prev_name));

	line = 0;
	error_line = 0;

	while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
		++line;

		start = line_buf;
		start = lskip(rstrip(start));

		if (*start == ';') {
			/* skip comment */
		} else if (*start == '[') { /* a "[section]" line */
			end = find_char_or_comment(start + 1, ']');
			if (*end == ']') {
				*end = '\0';
				safe_strncpy(section, start + 1, sizeof(section));
				*prev_name = '\0';
			} else if (!error_line) {
				error_line = line; /* no ']' found on section line */
			}
		} else if (*start != '\0' && *start != ';') { /* not a comment, must be a name[=:]value pair */
			end = find_char_or_comment(start, '=');
			if (*end != '=') {
				end = find_char_or_comment(start, ':');
			}
			if (*end == '=' || *end == ':') {
				*end = '\0';
				name = rstrip(start);
				value = lskip(end + 1);
				end = find_char_or_comment(value, '\0');
				if (*end == ';')
					*end = '\0';
				rstrip(value);

				/* valid name[=:]value pair found, call handler */
				safe_strncpy(prev_name, name, sizeof(prev_name));
				if (cb && (*cb)(arg, section, name, value) != 0 && !error_line)
					error_line = line;
			} else if (!error_line) {
				/* no '=' or ':' found on name[=:]value line */
				error_line = line;
			}
		}
	}

	fclose(fp);

	return error_line;
}
