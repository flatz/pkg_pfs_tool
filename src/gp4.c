#include "gp4.h"
#include "pkg.h"
#include "sfo.h"
#include "playgo.h"
#include "dict.h"
#include "util.h"

#include <utstring.h>
#include <time.h>

#define META_DATA_FILE_VERSION_MAJOR 1
#define META_DATA_FILE_VERSION_MINOR 0
#define META_DATA_FILE_VERSION_FORMAT "# PKG/PFS META DATA %d.%02d"
#define META_DATA_FORMAT_WO_PATH "0x%" PRIX64 ":0x%" PRIX64 ":0x%" PRIX32
#define META_DATA_FORMAT "%s:" META_DATA_FORMAT_WO_PATH

enum {
	META_DATA_FLAG_COMPRESSED = (1 << 0),
};

/* TODO: implement Master Data ID (mdid) */

struct dir_tree_entry {
	char* name;
	struct dir_tree_entry* children;
	UT_hash_handle hh;
};

struct enum_entries_for_gp4_cb_args {
	struct playgo* plgo;
	UT_string* files_xml;
	const char* output_directory;
	struct string_dict_entry* meta_data_dict;
	FILE* out_meta_data_fp;
	int is_sc_entry;
	int has_playgo_manifest;
	int all_compressed;
};

struct build_dir_tree_from_entries_cb_args {
	struct dir_tree_entry* root_dir_entry;
};

static int is_skipped_sc_entry(struct pkg_entry_desc* desc) {
	static enum pkg_entry_id skipped_entry_ids[] = {
		PKG_ENTRY_ID__LICENSE_DAT,
		PKG_ENTRY_ID__LICENSE_INFO,

		PKG_ENTRY_ID__SELFINFO_DAT,
		PKG_ENTRY_ID__IMAGEINFO_DAT,

		PKG_ENTRY_ID__TARGET_DELTAINFO_DAT,
		PKG_ENTRY_ID__ORIGIN_DELTAINFO_DAT,

		PKG_ENTRY_ID__PSRESERVED_DAT,

		PKG_ENTRY_ID__PLAYGO_CHUNK_DAT,
		PKG_ENTRY_ID__PLAYGO_CHUNK_SHA,
		PKG_ENTRY_ID__PLAYGO_MANIFEST_XML,

		PKG_ENTRY_ID__PUBTOOLINFO_DAT,

		PKG_ENTRY_ID__APP__PLAYGO_CHUNK_DAT,
		PKG_ENTRY_ID__APP__PLAYGO_CHUNK_SHA,
		PKG_ENTRY_ID__APP__PLAYGO_MANIFEST_XML,
	};
	static const char* skipped_entry_names[] = { "" };
	size_t i;

	assert(desc != NULL);

	if (desc->id < PKG_SC_ENTRY_ID_START)
		return 1;

	if (desc->id >= PKG_ENTRY_ID__ICON0_DDS && desc->id <= PKG_ENTRY_ID__ICON0_30_DDS)
		return 1;
	if (desc->id == PKG_ENTRY_ID__PIC0_DDS || (desc->id >= PKG_ENTRY_ID__PIC1_DDS && desc->id <= PKG_ENTRY_ID__PIC1_30_DDS))
		return 1;

	for (i = 0; i < COUNT_OF(skipped_entry_ids); ++i) {
		if (desc->id == skipped_entry_ids[i])
			return 1;
	}

	for (i = 0; i < COUNT_OF(skipped_entry_names); ++i) {
		if (strcmp(desc->name, skipped_entry_names[i]) == 0)
			return 1;
	}

	return 0;
}

static int is_skipped_pfs_entry(const char* path) {
	static const char* skipped_paths[] = {
		"sce_sys/about",
		"sce_sys/about/right.sprx",
		"sce_sys/keystone",

		"sce_discmap.plt",
		"sce_discmap_patch.plt",
	};
	size_t i;

	assert(path != NULL);

	for (i = 0; i < COUNT_OF(skipped_paths); ++i) {
		if (strcmp(path, skipped_paths[i]) == 0)
			return 1;
	}

	return 0;
}

static enum cb_result enum_sc_entries_for_gp4_cb(void* arg, struct pkg* pkg, struct pkg_entry_desc* desc) {
	struct enum_entries_for_gp4_cb_args* args = (struct enum_entries_for_gp4_cb_args*)arg;
	char target_path[PATH_MAX], orig_path[PATH_MAX];
	struct pkg_table_entry* sc_entry;

	assert(args != NULL);
	assert(args->files_xml != NULL);
	assert(args->output_directory != NULL);

	assert(pkg != NULL);
	assert(desc != NULL);

	UNUSED(pkg);

	if (is_skipped_sc_entry(desc))
		goto done;

	snprintf(target_path, sizeof(target_path), "sce_sys/%s", desc->name);

	snprintf(orig_path, sizeof(orig_path), "%s/Sc0/%s", args->output_directory, desc->name);
	path_slashes_to_backslashes(orig_path);

	utstring_printf(args->files_xml,
		"      <file targ_path=\"%s\" orig_path=\"%s\"/>\n",
		target_path, orig_path
	);

	if (strcmp(desc->name, PKG_ENTRY_NAME__PARAM_SFO) == 0) {
		sc_entry = pkg_find_entry(pkg, PKG_ENTRY_ID__SHAREPARAM_JSON);
		if (!sc_entry && BE32(pkg->hdr->content_type) == CONTENT_TYPE_GD && !pkg_is_patch(pkg)) {
			warning("Share parameters file is not found, adding it anyway...");

			snprintf(target_path, sizeof(target_path), "sce_sys/%s", PKG_ENTRY_NAME__SHAREPARAM_JSON);

			snprintf(orig_path, sizeof(orig_path), "%s/Sc0/%s", args->output_directory, PKG_ENTRY_NAME__SHAREPARAM_JSON);
			path_slashes_to_backslashes(orig_path);

			utstring_printf(args->files_xml,
				"      <file targ_path=\"%s\" orig_path=\"%s\"/>\n",
				target_path, orig_path
			);
		}
	}

done:
	return CB_RESULT_CONTINUE;
}

static int chunk_index_cmp(const void* a, const void* b) {
	uint16_t idx1 = *(const uint16_t*)a;
	uint16_t idx2 = *(const uint16_t*)b;

	if (idx1 > idx2)
		return 1;
	else if (idx1 < idx2)
		return -1;
	else
		return 0;
}

static enum cb_result enum_pfs_entries_for_gp4_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* path, uint64_t size, uint32_t flags) {
	struct enum_entries_for_gp4_cb_args* args = (struct enum_entries_for_gp4_cb_args*)arg;
	struct pfs_file_context* file = NULL;
	char target_path[PATH_MAX], orig_path[PATH_MAX];
	const char* meta_data;
	unsigned int meta_flags;
	UT_string* params_xml = NULL;
	uint64_t outer_offset, size_to_read;
	uint16_t* chunks = NULL;
	uint16_t cur_chunk, start_chunk = (uint16_t)-1, prev_chunk = (uint16_t)-1;
	struct playgo_chunk_attr_desc* chunk_attr;
	unsigned int disc_no, layer_no;
	size_t chunk_count;
	size_t i;
	int compressed;

	assert(args != NULL);
	assert(args->files_xml != NULL);
	assert(args->output_directory != NULL);

	assert(pfs != NULL);
	assert(path != NULL);

	UNUSED(ino);
	UNUSED(size);
	UNUSED(flags);

	if (type != PFS_ENTRY_FILE)
		goto done;

	if (starts_with(path, "/"))
		++path;

	if (is_skipped_pfs_entry(path))
		goto done;

	file = pfs_get_file(pfs, ino);
	if (!file) {
		warning("Unable to get context for file '%s'.", path);
		goto done;
	}

	strncpy(target_path, path, sizeof(target_path));

	snprintf(orig_path, sizeof(orig_path), "%s/Image0/%s", args->output_directory, path);
	path_slashes_to_backslashes(orig_path);

	meta_flags = 0;

	if (args->meta_data_dict) {
		meta_data = string_dict_find(args->meta_data_dict, target_path);
		if (!meta_data) {
			warning("Unable to find meta data for for file '%s'.", target_path);
			goto done;
		}
		if (sscanf(meta_data, META_DATA_FORMAT_WO_PATH, &outer_offset, &size_to_read, &meta_flags) != 3) {
			warning("Invalid meta data format for file '%s'.", target_path);
			goto done;
		}

		compressed = (meta_flags & META_DATA_FLAG_COMPRESSED) ? 1 : 0;
	} else {
		if (!pfs_file_get_offset_size(file, 0, size, NULL, &size_to_read, &compressed)) {
			warning("Unable to get read size for file '%s'.", path);
			goto done;
		}

		if (!pfs_file_get_outer_location(file, 0, &outer_offset)) {
			warning("Unable to get location for file '%s'.", path);
			goto done;
		}

		if (compressed)
			meta_flags |= META_DATA_FLAG_COMPRESSED;
	}

	if (args->out_meta_data_fp)
		fprintf(args->out_meta_data_fp, META_DATA_FORMAT "\n", target_path, outer_offset, size_to_read, meta_flags);

	utstring_new(params_xml);
	if ((compressed && size > size_to_read) || args->all_compressed)
		utstring_printf(params_xml, " pfs_compression=\"enable\"");

	if (args->plgo) {
		if (!playgo_get_chunks(args->plgo, outer_offset, size_to_read, &chunks, &chunk_count)) {
			warning("Unable to get chunks information for file '%s'.", path);
			goto done;
		}
		if (chunk_count > 0 && !(chunk_count == 1 && chunks[0] == 0)) {
			qsort(chunks, chunk_count, sizeof(*chunks), &chunk_index_cmp);

			for (i = 0, disc_no = layer_no = UINT_MAX; i < chunk_count; ++i) {
				chunk_attr = args->plgo->chunk_attrs + chunks[i];

				disc_no = MIN(disc_no, chunk_attr->disc_no);
				layer_no = MIN(layer_no, chunk_attr->layer_no);
			}
			if (disc_no == UINT_MAX)
				disc_no = 0;
			if (layer_no == UINT_MAX)
				layer_no = 0;

			if (disc_no > 0)
				utstring_printf(params_xml, " disc_no=\"%u\"", disc_no);
			if (layer_no > 0)
				utstring_printf(params_xml, " layer_no=\"%u\"", layer_no);

			utstring_printf(params_xml, " chunks=\"");
			for (i = 0; i < chunk_count; ++i) {
				cur_chunk = chunks[i];
				if (i == 0) {
					start_chunk = cur_chunk;
					utstring_printf(params_xml, "%u", cur_chunk);
				} else {
					if (cur_chunk == prev_chunk || cur_chunk == (prev_chunk + 1)) { /* consecutive? */
						if ((i + 1) == chunk_count) { /* last one? */
							if (cur_chunk != prev_chunk)
								utstring_printf(params_xml, "-%u", cur_chunk);
						}
					} else {
						if ((prev_chunk - start_chunk) >= 1) { /* gap found? */
							utstring_printf(params_xml, "-%u", prev_chunk);
						}
						utstring_printf(params_xml, " %u", cur_chunk);
						start_chunk = cur_chunk;
					}
				}
				prev_chunk = cur_chunk;
			}
			utstring_printf(params_xml, "\"");
		}
	}

	utstring_printf(args->files_xml,
		"      <file targ_path=\"%s\" orig_path=\"%s\"%s/>\n",
		target_path, orig_path, utstring_body(params_xml)
	);

	/* TODO: add image_no support */
	/* TODO: need proper file ordering (based on chunk order?) */

	if (params_xml)
		utstring_free(params_xml);

done:
	if (chunks)
		free(chunks);

	if (file)
		pfs_free_file(file);

	return CB_RESULT_CONTINUE;
}

static struct dir_tree_entry* get_dir_tree_entry(struct dir_tree_entry* parent, const char* name) {
	struct dir_tree_entry* entry = NULL;

	assert(parent != NULL);
	assert(name != NULL);

	HASH_FIND_STR(parent->children, name, entry);

	if (!entry) {
		entry = (struct dir_tree_entry*)malloc(sizeof(*entry));
		if (!entry)
			error("Unable to allocate memory for directory tree entry.");
		memset(entry, 0, sizeof(*entry));
		{
			entry->name = strdup(name);
		}
		HASH_ADD_STR(parent->children, name, entry);
	}

	return entry;
}

static void build_dir_tree(struct dir_tree_entry* root_dir_entry, const char* path) {
	struct dir_tree_entry* entry;
	char* orig_path;
	char* part;
	char* sep, old;
	size_t len;

	assert(root_dir_entry != NULL);
	assert(path != NULL);

	orig_path = strdup(path);

	for (entry = root_dir_entry, part = orig_path; *part != '\0'; ) {
		sep = (char*)path_get_separator(part);
		if (*sep != '\0')
			len = sep - part;
		else
			len = strlen(part);

		old = part[len], part[len] = '\0';
		entry = get_dir_tree_entry(entry, part);
		part[len] = old;

		part = (char*)path_skip_separator(sep);
	}

	free(orig_path);
}

static void cleanup_dir_tree(struct dir_tree_entry* root_dir_entry) {
	struct dir_tree_entry* entry;
	struct dir_tree_entry* tmp;

	assert(root_dir_entry != NULL);

	if (root_dir_entry->children) {
		HASH_ITER(hh, root_dir_entry->children, entry, tmp) {
			HASH_DEL(root_dir_entry->children, entry);
			cleanup_dir_tree(entry);
		}
	}

	if (root_dir_entry->name)
		free(root_dir_entry->name);

	free(root_dir_entry);
}

static enum cb_result build_dir_tree_from_sc_entries_cb(void* arg, struct pkg* pkg, struct pkg_entry_desc* desc) {
	struct build_dir_tree_from_entries_cb_args* args = (struct build_dir_tree_from_entries_cb_args*)arg;
	enum cb_result cb_result = CB_RESULT_CONTINUE;

	assert(args != NULL);
	assert(pkg != NULL);
	assert(desc != NULL);

	UNUSED(pkg);

	if (desc->id < PKG_SC_ENTRY_ID_START)
		goto done;

	build_dir_tree(args->root_dir_entry, "sce_sys");

	cb_result = CB_RESULT_STOP; /* no need to add sce_sys again */

done:
	return cb_result;
}

static enum cb_result build_dir_tree_from_pfs_entries_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* path, uint64_t size, uint32_t flags) {
	struct build_dir_tree_from_entries_cb_args* args = (struct build_dir_tree_from_entries_cb_args*)arg;

	assert(args != NULL);

	assert(pfs != NULL);
	assert(path != NULL);

	UNUSED(pfs);
	UNUSED(ino);
	UNUSED(size);
	UNUSED(flags);

	if (type != PFS_ENTRY_DIRECTORY)
		goto done;

	if (starts_with(path, "/"))
		++path;

	if (is_skipped_pfs_entry(path))
		goto done;

	build_dir_tree(args->root_dir_entry, path);

done:
	return CB_RESULT_CONTINUE;
}

static inline void print_dir_tree_indent(UT_string* dirs_xml, size_t depth) {
	static const char* indent = "  ";
	size_t i;

	assert(dirs_xml != NULL);

	for (i = 0; i < depth; ++i)
		utstring_printf(dirs_xml, "%s", indent);
}

static void print_dir_tree(UT_string* dirs_xml, struct dir_tree_entry* root_dir_entry, size_t depth, const char* start_indent) {
	struct dir_tree_entry* entry;
	struct dir_tree_entry* tmp;

	assert(dirs_xml != NULL);
	assert(root_dir_entry != NULL);

	if (root_dir_entry->children) {
		print_dir_tree_indent(dirs_xml, depth);
		if (depth > 0)
			utstring_printf(dirs_xml, "%s<dir targ_name=\"%s\">\n", start_indent, root_dir_entry->name);
		else
			utstring_printf(dirs_xml, "%s<rootdir>\n", start_indent);
		{
			HASH_ITER(hh, root_dir_entry->children, entry, tmp) {
				HASH_DEL(root_dir_entry->children, entry);
				print_dir_tree(dirs_xml, entry, depth + 1, start_indent);
			}
		}
		print_dir_tree_indent(dirs_xml, depth);
		if (depth > 0)
			utstring_printf(dirs_xml, "%s</dir>\n", start_indent);
		else
			utstring_printf(dirs_xml, "%s</rootdir>\n", start_indent);
	} else {
		print_dir_tree_indent(dirs_xml, depth);
		if (depth > 0)
			utstring_printf(dirs_xml, "%s<dir targ_name=\"%s\"/>\n", start_indent, root_dir_entry->name);
		else
			utstring_printf(dirs_xml, "%s<rootdir>\n", start_indent);
	}
}

static inline int find_xml_tag(const char* data, const char* tag_start, const char* tag_end, size_t* offset, size_t* size) {
	const char* p1;
	const char* p2;
	int status = 0;

	assert(data != NULL);
	assert(tag_start != NULL);
	assert(tag_end != NULL);

	p1 = strstr(data, tag_start);
	if (!p1)
		goto error;
	p2 = strstr(p1 + strlen(tag_start), tag_end);
	if (!p2)
		goto error;

	if (offset)
		*offset = p1 - data;
	if (size)
		*size = p2 + strlen(tag_end) - p1;

	status = 1;

error:
	return status;
}

#if 0
// XXX: actually it's used to get date of Publshing tools, but we want package's creation date instead.
static void pkg_timestamp_to_string(char* str, size_t max_size, unsigned int version_date) {
	unsigned y_l, y_h, y, m, d;

	assert(str != NULL);

	y_h = (version_date >> 24) & 0xFF;
	y_l = (version_date >> 16) & 0xFF;
	m = (version_date >> 8) & 0xFF;
	d = (version_date & 0xFF);

	y = (y_h >> 4) * 1000 + (y_h & 0xF) * 100 + (y_l >> 4) * 10 + (y_l & 0xF);
	m = (m >> 4) * 10 + (m & 0xF);
	d = (d >> 4) * 10 + (d & 0xF);

	snprintf(str, max_size, "%04u-%02u-%02u 00:00:00", y, m, d);
}
#endif

int pkg_generate_gp4_project(struct pkg* pkg, struct pfs* pfs, const char* in_meta_data_file_path, const char* gp4_file_path, const char* output_directory, const char* out_meta_data_file_path, int use_random_passcode, int all_compressed) {
	static const char* storage_types[] = { "bd25", "bd50", "bd50_50", "bd50_25", "digital50", "digital25" };
	static const char* app_categories[] = { "gx", "gxe", "gxc", "gxe+", "gxk" };
	struct sfo* sfo = NULL;
	struct sfo_entry* sfo_entry;
	struct playgo* plgo = NULL;
	struct string_dict_entry* meta_data_dict = NULL;
	FILE* in_meta_data_fp = NULL;
	FILE* out_meta_data_fp = NULL;
	int meta_data_version_major, meta_data_version_minor;
	UT_string* package_params_xml = NULL;
	UT_string* psproject_xml = NULL;
	UT_string* chunks_xml = NULL;
	UT_string* chunks_params_xml = NULL;
	UT_string* files_xml = NULL;
	UT_string* dirs_xml = NULL;
	const char* volume_id = "PS4VOLUME";
	const char* volume_type = NULL;
	char volume_timestamp[32];
	const char* app_type;
	uint8_t passcode_bin[KEYMGR_PASSCODE_SIZE];
	char passcode[KEYMGR_PASSCODE_SIZE + 1];
	char buf[1024];
	uint8_t* sfo_data;
	uint32_t sfo_data_size;
	uint8_t* playgo_data;
	uint32_t playgo_data_size;
	uint32_t sfo_uint_value;
	char* sfo_str_value = NULL;
	char* param_key_value;
	char* param_key;
	char* param_value;
	const char* playgo_manifest_xml_data;
	uint32_t playgo_manifest_xml_data_size;
	int has_playgo_manifest = 0;
	size_t chunk_info_xml_offset, chunk_info_xml_size;
	size_t scenarios_xml_offset, scenarios_xml_size;
	struct playgo_chunk_attr_desc* chunk_attr;
	UT_string* supported_languages = NULL;
	UT_string* default_language = NULL;
	int use_all_langs = 1;
	struct enum_entries_for_gp4_cb_args enum_entries_args;
	struct build_dir_tree_from_entries_cb_args build_dir_tree_from_entries_args;
	struct dir_tree_entry* root_dir_entry = NULL;
	unsigned int attr = 0, iro_tag = 0;
	int has_iro_tag = 0;
	int has_playgo = 0;
	int is_remaster = 0;
	struct tm* tm;
	time_t now;
	size_t i;
	int status = 0;

	assert(pkg != NULL);
	assert(pfs != NULL);
	assert(gp4_file_path != NULL);

	UNUSED(storage_types);
	UNUSED(app_categories);

	if (out_meta_data_file_path) {
		out_meta_data_fp = fopen(out_meta_data_file_path, "w");
		if (!out_meta_data_fp) {
			warning("Unable to open meta data file for writing: %s", out_meta_data_file_path);
			goto error;
		}

		fprintf(out_meta_data_fp, META_DATA_FILE_VERSION_FORMAT "\n\n", META_DATA_FILE_VERSION_MAJOR, META_DATA_FILE_VERSION_MINOR);
	}

	if (in_meta_data_file_path) {
		in_meta_data_fp = fopen(in_meta_data_file_path, "r");
		if (!in_meta_data_fp) {
			warning("Unable to open meta data file for reading: %s", in_meta_data_file_path);
			goto error;
		}

		if (!fgets(buf, sizeof(buf), in_meta_data_fp) || feof(in_meta_data_fp)) {
invalid_meta_data:
			warning("Invalid meta data file format: %s", in_meta_data_file_path);
			goto error;
		}
		if (sscanf(buf, META_DATA_FILE_VERSION_FORMAT, &meta_data_version_major, &meta_data_version_minor) != 2)
			goto invalid_meta_data;
		if (meta_data_version_major > META_DATA_FILE_VERSION_MAJOR || meta_data_version_minor > META_DATA_FILE_VERSION_MINOR) {
			warning("Unsupported meta data file format: %s", in_meta_data_file_path);
			goto error;
		}

		meta_data_dict = string_dict_load_from_filep(in_meta_data_fp, ':', STRING_DICT_FLAG_TRIM_ALL);
		if (!meta_data_dict) {
			warning("Unable to load meta data from file: %s", in_meta_data_file_path);
			goto error;
		}

		fclose(in_meta_data_fp);
		in_meta_data_fp = NULL;
	}

	sfo_data = pkg_locate_entry_data(pkg, PKG_ENTRY_ID__PARAM_SFO, NULL, &sfo_data_size);
	if (!sfo_data) {
		warning("System file object data is not found.");
		goto error;
	}

	sfo = sfo_alloc();
	if (!sfo) {
		warning("Unable to allocate memory for system file object.");
		goto error;
	}
	if (!sfo_load_from_memory(sfo, sfo_data, sfo_data_size)) {
		warning("Unable to load system file object.");
		goto error;
	}

	playgo_data = pkg_locate_entry_data(pkg, PKG_ENTRY_ID__PLAYGO_CHUNK_DAT, NULL, &playgo_data_size);
	if (!playgo_data) {
		if (BE32(pkg->hdr->content_type) == CONTENT_TYPE_GD) {
			warning("Playgo data is not found.");
			goto error;
		}
	} else {
		plgo = playgo_alloc();
		if (!plgo) {
			warning("Unable to allocate memory for playgo object.");
			goto error;
		}
		if (!playgo_load_from_memory(plgo, playgo_data, playgo_data_size)) {
			warning("Unable to load playgo file object.");
			goto error;
		}
		has_playgo = 1;
	}

	if (use_random_passcode) {
		if (!generate_crypto_random(passcode_bin, sizeof(passcode_bin))) {
			warning("Unable to generate passcode.");
			goto error;
		}
		bin_to_readable(passcode, sizeof(passcode) - 1, passcode_bin, sizeof(passcode_bin));
	} else {
		memset(passcode, '0', sizeof(passcode) - 1);
	}
	passcode[sizeof(passcode) - 1] = '\0';

	utstring_new(package_params_xml);
	utstring_printf(package_params_xml, " content_id=\"%36s\"", pkg->hdr->content_id);
	utstring_printf(package_params_xml, " passcode=\"%s\"", passcode);

	now = time(NULL);
	tm = localtime(&now);

	strftime(volume_timestamp, sizeof(volume_timestamp), "%Y-%m-%d %H:%M:%S", tm);

	sfo_entry = sfo_find_entry(sfo, "PUBTOOLINFO");
	if (sfo_entry) {
		if (sfo_entry->format != SFO_FORMAT_STRING || sfo_entry->size < 1) {
			warning("Invalid format of PUBTOOLINFO entry in system file object.");
			goto error;
		}
		if (strlen((const char*)sfo_entry->value) > 0) {
			sfo_str_value = strdup((const char*)sfo_entry->value);
			if (!sfo_str_value) {
				warning("Unable to allocate memory for SFO entry value.");
				goto error;
			}
			param_key_value = strtok(sfo_str_value, "=,");
			while (param_key_value) {
				param_key = param_key_value;
				param_key_value = strtok(NULL, "=,");
				param_value = param_key_value;
				param_key_value = strtok(NULL, "=,");

				if (strcmp(param_key, "c_date") == 0 && strlen(param_value) == strlen("YYYYMMDD")) {
					snprintf(volume_timestamp, sizeof(volume_timestamp), "%.4s-%.2s-%.2s 00:00:00", param_value, param_value + 4, param_value + 4 + 2);
#ifdef WRITE_CREATION_DATE
					utstring_printf(package_params_xml, " c_date=\"%.4s-%.2s-%.2s\"", param_value, param_value + 4, param_value + 4 + 2);
#endif
				} else if (strcmp(param_key, "st_type") == 0) {
					utstring_printf(package_params_xml, " storage_type=\"%s\"", param_value);
				}
			}
			free(sfo_str_value);
			sfo_str_value = NULL;
		}
	}

	sfo_entry = sfo_find_entry(sfo, "ATTRIBUTE");
	if (sfo_entry) {
		if (sfo_entry->format != SFO_FORMAT_UINT32 || sfo_entry->size != sizeof(sfo_uint_value)) {
			warning("Invalid format of ATTRIBUTE entry in system file object.");
			goto error;
		}
		sfo_uint_value = LE32(*(uint32_t*)sfo_entry->value);
		attr = sfo_uint_value;
	} else {
		warning("No ATTRIBUTE entry in system file object.");
		goto error;
	}

	sfo_entry = sfo_find_entry(sfo, "APP_TYPE");
	if (sfo_entry) {
		if (sfo_entry->format != SFO_FORMAT_UINT32 || sfo_entry->size != sizeof(sfo_uint_value)) {
			warning("Invalid format of APP_TYPE entry in system file object.");
			goto error;
		}
		sfo_uint_value = LE32(*(uint32_t*)sfo_entry->value);
		switch (sfo_uint_value) {
			case APP_TYPE_PAID_STANDALONE_FULL: app_type = "full"; break;
#if 1
			case APP_TYPE_UPGRADABLE: app_type = "full"; break;
#else
			case APP_TYPE_UPGRADABLE: app_type = "upgradable"; break;
#endif
			case APP_TYPE_DEMO: app_type = "demo"; break;
			case APP_TYPE_FREEMIUM: app_type = "freemium"; break;
			default: app_type = NULL; break;
		}
		if (app_type)
			utstring_printf(package_params_xml, " app_type=\"%s\"", app_type);
	}

	sfo_entry = sfo_find_entry(sfo, "IRO_TAG");
	if (sfo_entry) {
		if (sfo_entry->format != SFO_FORMAT_UINT32 || sfo_entry->size != sizeof(sfo_uint_value)) {
			warning("Invalid format of IRO_TAG entry in system file object.");
			goto error;
		}
		sfo_uint_value = LE32(*(uint32_t*)sfo_entry->value);
		iro_tag = sfo_uint_value;
		has_iro_tag = 1;
	}

	sfo_entry = sfo_find_entry(sfo, "REMASTER_TYPE");
	if (sfo_entry) {
		if (sfo_entry->format != SFO_FORMAT_UINT32 || sfo_entry->size != sizeof(sfo_uint_value)) {
			warning("Invalid format of REMASTER_TYPE entry in system file object.");
			goto error;
		}
		sfo_uint_value = LE32(*(uint32_t*)sfo_entry->value);
		is_remaster = (sfo_uint_value == 1);
	}

	sfo_entry = sfo_find_entry(sfo, "CATEGORY");
	if (sfo_entry) {
		if (sfo_entry->format != SFO_FORMAT_STRING || sfo_entry->size < 1) {
			warning("Invalid format of CATEGORY entry in system file object.");
			goto error;
		}
		sfo_str_value = strdup((const char*)sfo_entry->value);
		if (!sfo_str_value || strlen(sfo_str_value) == 0) {
			warning("Invalid value of CATEGORY entry in system file object.");
			goto error;
		}
		if (starts_with(sfo_str_value, "gd")) {
			if (!is_remaster)
				volume_type = "pkg_ps4_app";
			else
				volume_type = "pkg_ps4_remaster";
		} else if (starts_with(sfo_str_value, "gp")) {
			volume_type = "pkg_ps4_patch";
		} else if (strcmp(sfo_str_value, "ac") == 0) {
			volume_type = "pkg_ps4_ac_data";
			if (attr == 0) {
				if (has_iro_tag) {
					if (iro_tag == 1)
						volume_type = "pkg_ps4_sf_theme";
					else if (iro_tag == 2)
						volume_type = "pkg_ps4_theme";
					else {
						warning("Unsupported value of IRO_TAG entry in system file object, making it as additional content package.");
						volume_type = "pkg_ps4_ac_data";
					}
				}
			}
		} else if (strcmp(sfo_str_value, "gdo") == 0 || strcmp(sfo_str_value, "gde") == 0) {
			volume_type = "pkg_ps4_app";
		}
		free(sfo_str_value);
		sfo_str_value = NULL;
	}
	if (!volume_type) {
		warning("Unable to determine volume type.");
		goto error;
	}

	root_dir_entry = (struct dir_tree_entry*)malloc(sizeof(*root_dir_entry));
	if (!root_dir_entry) {
		warning("Unable to allocate memory for root directory entry.");
		goto error;
	}
	memset(root_dir_entry, 0, sizeof(*root_dir_entry));
	{
		root_dir_entry->name = strdup("/");
	}

	if (has_playgo) {
		utstring_new(chunks_xml);
		playgo_manifest_xml_data = (char*)pkg_locate_entry_data(pkg, PKG_ENTRY_ID__PLAYGO_MANIFEST_XML, NULL, &playgo_manifest_xml_data_size);
		if (playgo_manifest_xml_data) {
			if (!find_xml_tag(playgo_manifest_xml_data, "<chunk_info ", "</chunk_info>", &chunk_info_xml_offset, &chunk_info_xml_size))
				goto error;
			if (!find_xml_tag(playgo_manifest_xml_data, "<scenarios ", "</scenarios>", &scenarios_xml_offset, &scenarios_xml_size)) {
				if (!find_xml_tag(playgo_manifest_xml_data, "<scenarios>", "</scenarios>", &scenarios_xml_offset, &scenarios_xml_size))
					goto error;
			}
			if (scenarios_xml_offset <= chunk_info_xml_offset || scenarios_xml_size >= chunk_info_xml_size) {
				warning("Invalid playgo manifest xml.");
				goto error;
			}

			utstring_printf(chunks_xml, "    ");
			utstring_bincpy(chunks_xml, playgo_manifest_xml_data + chunk_info_xml_offset, scenarios_xml_offset - chunk_info_xml_offset);

			utstring_new(chunks_params_xml);
			if (plgo->chunk_count > 0) {
				utstring_new(supported_languages);
				utstring_new(default_language);

				if (!playgo_get_languages(plgo, supported_languages, default_language, &use_all_langs)) {
					warning("Unable to get available languages.");
					goto error;
				}
				if (utstring_len(supported_languages) > 0) {
					utstring_printf(chunks_params_xml, " supported_languages=\"%s\"", utstring_body(supported_languages));

					if (utstring_len(default_language) > 0)
						utstring_printf(chunks_params_xml, " default_language=\"%s\"", utstring_body(default_language));
				} else {
					use_all_langs = 1;
				}
			}

			utstring_printf(chunks_xml, "<chunks%s", utstring_body(chunks_params_xml));
			if (plgo->chunk_count > 0) {
				utstring_printf(chunks_xml, ">\n");

				for (i = 0; i < plgo->chunk_count; ++i) {
					chunk_attr = plgo->chunk_attrs + i;

					utstring_printf(chunks_xml, "        <chunk id=\"%" PRIuMAX "\"", (uintmax_t)i);

					utstring_renew(chunks_params_xml);
					utstring_printf(chunks_params_xml, " disc_no=\"%u\"", chunk_attr->disc_no);
					utstring_printf(chunks_params_xml, " layer_no=\"%u\"", chunk_attr->layer_no);
					if (chunk_attr->label && strlen(chunk_attr->label) > 0)
						utstring_printf(chunks_params_xml, " label=\"%s\"", chunk_attr->label);

					if (!use_all_langs) {
						utstring_renew(supported_languages);
						if (!playgo_get_chunk_languages(plgo, i, supported_languages)) {
							warning("Unable to get chunk language.");
							goto error;
						}
						if (utstring_len(supported_languages) > 0)
							utstring_printf(chunks_params_xml, " languages=\"%s\"", utstring_body(supported_languages));
					}

					utstring_printf(chunks_xml, "%s/>\n", utstring_body(chunks_params_xml));
				}
				utstring_printf(chunks_xml, "      </chunks>\n      ");
			} else {
					utstring_printf(chunks_xml, "/>\n        ");
			}
			utstring_bincpy(chunks_xml, playgo_manifest_xml_data + scenarios_xml_offset, chunk_info_xml_size - (scenarios_xml_offset - chunk_info_xml_offset));
			utstring_printf(chunks_xml, "\n");

			has_playgo_manifest = 1;
		} else {
			warning("Playgo manifest xml is not found, using default one...");

			utstring_printf(chunks_xml,
				"    <chunk_info chunk_count=\"1\" scenario_count=\"1\">\n"
				"      <chunks>\n"
				"        <chunk id=\"0\" layer_no=\"0\" label=\"Chunk #0\"/>\n"
				"      </chunks>\n"
				"      <scenarios default_id=\"0\">\n"
				"        <scenario id=\"0\" type=\"sp\" initial_chunk_count=\"1\" label=\"Scenario #0\">0</scenario>\n"
				"      </scenarios>\n"
				"    </chunk_info>\n"
			);
		}
	}

	utstring_new(files_xml);
	utstring_printf(files_xml,
		"  <files img_no=\"0\">\n"
	);
	{
		memset(&enum_entries_args, 0, sizeof(enum_entries_args));
		{
			enum_entries_args.plgo = plgo;
			enum_entries_args.files_xml = files_xml;
			enum_entries_args.output_directory = output_directory;
			enum_entries_args.meta_data_dict = meta_data_dict;
			enum_entries_args.out_meta_data_fp = out_meta_data_fp;
			enum_entries_args.has_playgo_manifest = has_playgo_manifest;
			enum_entries_args.all_compressed = 0;
		}

		enum_entries_args.is_sc_entry = 1;
		pkg_enum_entries(pkg, &enum_sc_entries_for_gp4_cb, &enum_entries_args, 0);

		enum_entries_args.is_sc_entry = 0;
		enum_entries_args.all_compressed = all_compressed;
		pfs_enum_user_root_directory(pfs, &enum_pfs_entries_for_gp4_cb, &enum_entries_args);
	}
	utstring_printf(files_xml,
		"  </files>\n"
	);

	memset(&build_dir_tree_from_entries_args, 0, sizeof(build_dir_tree_from_entries_args));
	{
		build_dir_tree_from_entries_args.root_dir_entry = root_dir_entry;
	}

	pkg_enum_entries(pkg, &build_dir_tree_from_sc_entries_cb, &build_dir_tree_from_entries_args, 0);
	pfs_enum_user_root_directory(pfs, &build_dir_tree_from_pfs_entries_cb, &build_dir_tree_from_entries_args);

	utstring_new(dirs_xml);
	print_dir_tree(dirs_xml, root_dir_entry, 0, "  ");
	cleanup_dir_tree(root_dir_entry);
	root_dir_entry = NULL;

	utstring_new(psproject_xml);
	utstring_printf(psproject_xml,
		"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
		"<psproject fmt=\"gp4\" version=\"1000\">\n"
		"  <volume>\n"
		"    <volume_type>%s</volume_type>\n"
		"    <volume_id>%s</volume_id>\n"
		"    <volume_ts>%s</volume_ts>\n"
		"    <package%s/>\n",
		volume_type, volume_id, volume_timestamp, utstring_body(package_params_xml)
	);
	if (has_playgo)
		utstring_concat(psproject_xml, chunks_xml);
	utstring_printf(psproject_xml,
		"  </volume>\n"
	);
	utstring_concat(psproject_xml, files_xml);
	utstring_concat(psproject_xml, dirs_xml);
	utstring_printf(psproject_xml,
		"</psproject>\n"
	);

	if (!write_to_file(gp4_file_path, utstring_body(psproject_xml), utstring_len(psproject_xml), NULL, 0644)) {
		warning("Unable to write file '%s'.", gp4_file_path);
		goto error;
	}

	status = 1;

error:
	if (default_language)
		utstring_free(default_language);
	if (supported_languages)
		utstring_free(supported_languages);

	if (dirs_xml)
		utstring_free(dirs_xml);
	if (files_xml)
		utstring_free(files_xml);
	if (chunks_params_xml)
		utstring_free(chunks_params_xml);
	if (chunks_xml)
		utstring_free(chunks_xml);
	if (package_params_xml)
		utstring_free(package_params_xml);
	if (psproject_xml)
		utstring_free(psproject_xml);

	if (root_dir_entry)
		free(root_dir_entry);

	if (sfo_str_value)
		free(sfo_str_value);

	if (out_meta_data_fp)
		fclose(out_meta_data_fp);
	if (in_meta_data_fp)
		fclose(in_meta_data_fp);

	if (meta_data_dict)
		string_dict_free(meta_data_dict);

	if (plgo)
		playgo_free(plgo);
	if (sfo)
		sfo_free(sfo);

	return status;
}
