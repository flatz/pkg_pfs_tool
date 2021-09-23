#include "pfs.h"
#include "util.h"

struct pfs_check_entry_cb_args {
	char name[PFS_DIR_ENTRY_NAME_MAX_SIZE];
	pfs_ino* ino;
	int found;
	int case_sensitive;
};

static int pfs_sort_dir_entries_cb(const void* a, const void* b) {
	const struct pfs_dir_entry* entry1 = (const struct pfs_dir_entry*)a;
	const struct pfs_dir_entry* entry2 = (const struct pfs_dir_entry*)b;

	size_t entry_name_len1 = LE32(entry1->name_size);
	size_t entry_name_len2 = LE32(entry2->name_size);

	if (!strncmp(entry1->name, ".", entry_name_len1))
		return -1;
	else if (!strncmp(entry2->name, ".", entry_name_len2))
		return 1;
	else if (!strncmp(entry1->name, "..", entry_name_len1))
		return -1;
	else if (!strncmp(entry2->name, "..", entry_name_len2))
		return 1;

	return strncmp(entry1->name, entry2->name, MAX(entry_name_len1, entry_name_len2));
}

static int pfs_sort_dir_entries_nocase_cb(const void* a, const void* b) {
	const struct pfs_dir_entry* entry1 = (const struct pfs_dir_entry*)a;
	const struct pfs_dir_entry* entry2 = (const struct pfs_dir_entry*)b;

	size_t entry_name_len1 = LE32(entry1->name_size);
	size_t entry_name_len2 = LE32(entry2->name_size);

	if (!strncmp(entry1->name, ".", entry_name_len1))
		return -1;
	else if (!strncmp(entry2->name, ".", entry_name_len2))
		return 1;
	else if (!strncmp(entry1->name, "..", entry_name_len1))
		return -1;
	else if (!strncmp(entry2->name, "..", entry_name_len2))
		return 1;

	return strncasecmp(entry1->name, entry2->name, MAX(entry_name_len1, entry_name_len2));
}

static enum cb_result pfs_check_entry_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* name) {
	struct pfs_check_entry_cb_args* args = (struct pfs_check_entry_cb_args*)arg;
	int match;
	enum cb_result result = CB_RESULT_CONTINUE;

	assert(args != NULL);
	assert(args->ino != NULL);

	assert(pfs != NULL);

	UNUSED(pfs);
	UNUSED(type);

	if (args->case_sensitive)
		match = strcmp(name, args->name) == 0;
	else
		match = strcasecmp(name, args->name) == 0;

	if (match) {
		*args->ino = ino;
		args->found = 1;
		result = CB_RESULT_STOP;
	}

	return result;
}

size_t pfs_parse_dir_entries(struct pfs* pfs, const void* data, uint64_t data_size, pfs_parse_dir_entries_cb cb, void* arg) {
	union {
		const uint8_t* buf_ptr;
		const struct pfs_dir_entry* ptr;
	} dir_entry;
	const uint8_t* dir_entry_buf_end_ptr;
	char name[PFS_DIR_ENTRY_NAME_MAX_SIZE];
	enum cb_result cb_result;
	size_t count;

	assert(pfs != NULL);
	assert(data != NULL);

	UNUSED(pfs);

	if (data_size <= PFS_MIN_DIR_ENTRY_SIZE)
		return 0;

	dir_entry.buf_ptr = (const uint8_t*)data;
	dir_entry_buf_end_ptr = dir_entry.buf_ptr + data_size;

	count = 0;
	while (LE32(dir_entry.ptr->ino) != 0 && LE32(dir_entry.ptr->entry_size) != 0) {
		++count;

		if (cb) {
			assert(dir_entry.ptr->name_size < sizeof(name));
			strncpy(name, dir_entry.ptr->name, MIN(sizeof(name), dir_entry.ptr->name_size));
			name[dir_entry.ptr->name_size] = '\0';
			cb_result = (*cb)(arg, pfs, dir_entry.ptr->ino, (enum pfs_entry_type)dir_entry.ptr->type, name);
			if (cb_result == CB_RESULT_STOP)
				break;
		}

		dir_entry.buf_ptr += LE32(dir_entry.ptr->entry_size);
		if (dir_entry.buf_ptr + PFS_MIN_DIR_ENTRY_SIZE >= dir_entry_buf_end_ptr)
			break;
	}

	return count;
}

size_t pfs_count_dir_entries(struct pfs* pfs, const void* data, uint64_t data_size) {
	return pfs_parse_dir_entries(pfs, data, data_size, NULL, NULL);
}

int pfs_lookup_path(struct pfs* pfs, const char* path, pfs_ino root_ino, pfs_ino* ino) {
	struct pfs_check_entry_cb_args check_entry_args;
	struct pfs_file_context* file = NULL;
	void* data = NULL;
	const char* separator;
	const char* part;
	size_t part_length;
	pfs_ino cur_ino;
	int status = 0;

	assert(pfs != NULL);
	assert(path != NULL);
	assert(ino != NULL);

	part = path;
	while (*part == '/')
		++part;

	if (*part == '\0') {
		*ino = root_ino;
		goto success;
	}

	memset(&check_entry_args, 0, sizeof(check_entry_args));

	check_entry_args.case_sensitive = (pfs->flags & PFS_FLAGS_CASE_SENSITIVE) != 0;

	cur_ino = root_ino;
	while (*part != '\0') {
		separator = path_get_separator(part);
		if (*separator != '\0')
			part_length = separator - part;
		else
			part_length = strlen(part);

		if (part_length > sizeof(check_entry_args.name) - 1)
			goto error;

		check_entry_args.ino = &cur_ino;
		strncpy(check_entry_args.name, part, part_length);
		check_entry_args.name[part_length] = '\0';

		file = pfs_get_file(pfs, cur_ino);
		if (!file)
			goto error;

		data = (uint8_t*)malloc(file->file_size);
		if (!data)
			goto error;
		memset(data, 0, file->file_size);

		if (!pfs_file_read(file, 0, data, file->file_size))
			goto error;

		check_entry_args.found = 0;
		if (!pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_check_entry_cb, &check_entry_args) || !check_entry_args.found)
			goto error;

		free(data);
		data = NULL;

		pfs_free_file(file);
		file = NULL;

		part = path_skip_separator(separator);
	}

	*ino = cur_ino;

success:
	status = 1;

error:
	if (data)
		free(data);

	if (file)
		pfs_free_file(file);

	return status;
}

int pfs_lookup_path_super(struct pfs* pfs, const char* path, pfs_ino* ino) {
	return pfs_lookup_path(pfs, path, pfs->super_root_dir_ino, ino);
}

int pfs_lookup_path_user(struct pfs* pfs, const char* path, pfs_ino* ino) {
	return pfs_lookup_path(pfs, path, pfs->user_root_dir_ino, ino);
}
