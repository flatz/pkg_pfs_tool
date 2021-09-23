#include "pfs.h"
#include "util.h"

struct pfs_parse_directory_cb_args {
	char parent_directory[PATH_MAX];
	pfs_enum_user_root_directory_cb cb;
	void* arg;
};

static enum cb_result pfs_parse_super_root_dir_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* name) {
	assert(pfs != NULL);

	UNUSED(arg);
	UNUSED(type);

	if (strcmp(name, "blk_bitmap") == 0) {
		pfs->block_bitmap_ino = ino;
	} else if (strcmp(name, "ino_bitmap") == 0) {
		pfs->ino_bitmap_ino = ino;
	} else if (strcmp(name, "uroot") == 0) {
		pfs->user_root_dir_ino = ino;
	} else if (strcmp(name, "block_addr_table") == 0) {
		pfs->block_addr_table_ino = ino;
	} else if (strcmp(name, "flat_path_table") == 0) {
		pfs->flat_path_table_ino = ino;
	} else if (strcmp(name, "collision_resolver") == 0) {
		pfs->collision_resolver_ino = ino;
	} else if (strcmp(name, "badblk_bitmap") == 0) {
		// skip
	} else if (strcmp(name, "lost+found") == 0) {
		// skip
	}

	return CB_RESULT_CONTINUE;
}

static enum cb_result pfs_enum_directory_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* name) {
	struct pfs_parse_directory_cb_args* args = (struct pfs_parse_directory_cb_args*)arg;
	struct pfs_parse_directory_cb_args new_args;
	struct pfs_file_context* file = NULL;
	uint8_t* data = NULL;
	char file_path[PATH_MAX];
	enum cb_result cb_result = CB_RESULT_CONTINUE;

	assert(args != NULL);
	assert(pfs != NULL);

	file = pfs_get_file(pfs, ino);
	if (!file)
		goto error;

	snprintf(file_path, sizeof(file_path), "%s/%s", args->parent_directory, name);

	if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
		if (args->cb) {
			cb_result = (*args->cb)(args->arg, pfs, ino, type, file_path, file->file_size, file->flags);
			if (cb_result == CB_RESULT_STOP)
				goto done;
		}

		if (type == PFS_ENTRY_DIRECTORY) {
			data = (uint8_t*)malloc(file->file_size);
			if (!data)
				goto error;
			memset(data, 0, file->file_size);

			if (!pfs_file_read(file, 0, data, file->file_size))
				goto error;

			memset(&new_args, 0, sizeof(new_args));
			{
				strncpy(new_args.parent_directory, file_path, sizeof(new_args.parent_directory));
				new_args.cb = args->cb;
				new_args.arg = args->arg;
			}

			pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_enum_directory_cb, &new_args);
		}
	}

done:
	if (data)
		free(data);
	pfs_free_file(file);

	return cb_result;

error:
	warning("Unable to get file: %s", name);
	goto done;
}

int pfs_parse_super_root_directory(struct pfs* pfs) {
	struct pfs_file_context* file = NULL;
	uint8_t* data = NULL;
	int status = 0;

	assert(pfs != NULL);

	file = pfs_get_file(pfs, pfs->super_root_dir_ino);
	if (!file)
		goto error;

	data = (uint8_t*)malloc(file->file_size);
	if (!data)
		goto error;
	memset(data, 0, file->file_size);

	if (!pfs_file_read(file, 0, data, file->file_size))
		goto error;

	pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_parse_super_root_dir_cb, pfs);

	status = 1;

error:
	if (data)
		free(data);

	if (file)
		pfs_free_file(file);

	return status;
}

int pfs_enum_user_root_directory(struct pfs* pfs, pfs_enum_user_root_directory_cb cb, void* arg) {
	struct pfs_parse_directory_cb_args args;
	struct pfs_file_context* file = NULL;
	uint8_t* data = NULL;
	int status = 0;

	assert(pfs != NULL);

	file = pfs_get_file(pfs, pfs->user_root_dir_ino);
	if (!file)
		goto error;

	data = (uint8_t*)malloc(file->file_size);
	if (!data)
		goto error;
	memset(data, 0, file->file_size);

	if (!pfs_file_read(file, 0, data, file->file_size))
		goto error;

	memset(&args, 0, sizeof(args));
	{
		args.parent_directory[0] = '\0';
		args.cb = cb;
		args.arg = arg;
	}

	pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_enum_directory_cb, &args);

	status = 1;

error:
	if (data)
		free(data);

	if (file)
		pfs_free_file(file);

	return status;
}

static enum cb_result pfs_list_user_root_directory_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* path, uint64_t size, uint32_t flags) {
	const char* tmp_path = path;

	assert(pfs != NULL);
	assert(path != NULL);

	UNUSED(arg);
	UNUSED(pfs);
	UNUSED(ino);
	UNUSED(type);
	UNUSED(size);
	UNUSED(flags);

	while (*tmp_path == '/')
		++tmp_path;
	if (*tmp_path == '\0')
		tmp_path = path;

	if (type == PFS_ENTRY_FILE)
		info("%s (size: 0x%" PRIX64 ")", tmp_path, size);
	else if (type == PFS_ENTRY_DIRECTORY)
		info("%s/", tmp_path);
	else
		info("%s", tmp_path);

	return CB_RESULT_CONTINUE;
}

int pfs_list_user_root_directory(struct pfs* pfs) {
	assert(pfs != NULL);

	return pfs_enum_user_root_directory(pfs, &pfs_list_user_root_directory_cb, NULL);
}

