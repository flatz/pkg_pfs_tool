#if defined(_MSC_VER)
#	include <getopt_win.h>

#	ifdef getopt
#		undef getopt
#	endif
#	define getopt getopt_a
#	ifdef getopt_long
#		undef getopt_long
#	endif
#	define getopt_long getopt_long_a
#	ifdef getopt_long_only
#		undef getopt_long_only
#	endif
#	define getopt_long_only getopt_long_only_a
#	ifdef option
#		undef option
#	endif
#	define option option_a
#	ifdef optarg
#		undef optarg
#	endif
#	define optarg optarg_a
#else
#	include <getopt.h>

#	define ARG_NULL no_argument
#	define ARG_NONE no_argument
#	define ARG_REQ required_argument
#	define ARG_OPT optional_argument
#endif /* _WIN32 */

#include "pkg.h"
#include "self.h"
#include "gp4.h"
#include "sfo.h"
#include "playgo.h"
#include "crypto.h"
#include "mapped_file.h"
#include "util.h"
#include "keymgr.h"

#include <dirent.h>
#include <utarray.h>
#include <utstring.h>

static char* s_input_file_path = NULL;
#if defined(ENABLE_REPACK_SUPPORT)
static char* s_plaintext_elf_directory = NULL;
#endif
static char* s_output_file_path = NULL;
static char s_output_directory[PATH_MAX];

static int s_cmd_info = 0;
static int s_cmd_list = 0;
static int s_cmd_unpack = 0;
#if defined(ENABLE_REPACK_SUPPORT)
static int s_cmd_repack = 0;
#endif

static int s_opt_key_content_id_flag = 0;
#if defined(ENABLE_REPACK_SUPPORT)
static int s_opt_content_id_flag = 0;
#endif
static int s_opt_passcode_flag = 0;
#ifdef ENABLE_SD_KEYGEN
static int s_opt_sealed_key_file_flag = 0;
#endif
static int s_opt_encdec_tweak_key_flag = 0;
static int s_opt_encdec_data_key_flag = 0;
static int s_opt_sign_key_flag = 0;
static int s_opt_sc0_key_flag = 0;
static int s_opt_use_meta_data_flag = 0;
static int s_opt_dump_meta_data_flag = 0;
static int s_opt_pfs_image_data_file_flag = 0;
static int s_opt_gp4_file_flag = 0;
static int s_opt_unpack_outer_pfs_flag = 0;
static int s_opt_unpack_inner_pfs_flag = 0;
static int s_opt_unpack_sc_entries_flag = 0;
static int s_opt_unpack_extra_sc_entries_flag = 0;
static int s_opt_use_splitted_files_flag = 0;
static int s_opt_no_unpack_flag = 0;
static int s_opt_no_signature_check_flag = 0;
static int s_opt_no_icv_check_flag = 0;
#if defined(ENABLE_REPACK_SUPPORT)
static int s_opt_no_hash_recalc_flag = 0;
static int s_opt_no_elf_repack_flag = 0;
#endif
static int s_opt_dump_sfo_flag = 0;
static int s_opt_dump_playgo_flag = 0;
static int s_opt_dump_final_keys_flag = 0;
#if defined(ENABLE_SD_KEYGEN)
static int s_opt_dump_sd_info_flag = 0;
#endif
static int s_opt_use_random_passcode_flag = 0;
static int s_opt_all_compressed_flag = 0;

static char* s_key_content_id = NULL;
#if defined(ENABLE_REPACK_SUPPORT)
static char* s_content_id = NULL;
#endif
static char* s_passcode = NULL;
#ifdef ENABLE_SD_KEYGEN
static char* s_sealed_key_file = NULL;
#endif
static uint8_t* s_encdec_tweak_key = NULL;
static uint8_t* s_encdec_data_key = NULL;
static uint8_t* s_sign_key = NULL;
static uint8_t* s_sc0_key = NULL;
static char* s_meta_data_in_file = NULL;
static char* s_meta_data_out_file = NULL;
static char* s_pfs_image_data_file = NULL;
static char* s_gp4_file = NULL;
static int s_unpack_outer_pfs = 0;
static int s_unpack_inner_pfs = 0;
static int s_unpack_sc_entries = 0;
static int s_unpack_extra_sc_entries = 0;
static int s_use_splitted_files = 0;
static int s_no_unpack = 0;
static int s_no_signature_check = -1;
static int s_no_icv_check = -1;
#if defined(ENABLE_REPACK_SUPPORT)
static int s_no_hash_recalc = 0;
static int s_no_elf_repack = 0;
#endif
static int s_dump_sfo = 0;
static int s_dump_playgo = 0;
static int s_dump_final_keys = 0;
#if defined(ENABLE_SD_KEYGEN)
static int s_dump_sd_info = 0;
#endif
static int s_use_random_passcode = 0;
static int s_all_compressed = 0;
static UT_array* s_file_paths = NULL;

static uint8_t s_pkg_magic[] = { '\x7F', 'C', 'N', 'T' };

static struct pkg* s_pkg = NULL;
static struct pfs* s_pfs = NULL;

static void show_version(void);
static void show_usage(char* argv[]);

static void cleanup(void);

struct pfs_io_context {
	struct file_map* map;
	uint64_t offset;
};

#if defined(ENABLE_REPACK_SUPPORT)
	struct pfs_repack_process_dir_cb_args {
		struct file_map* map;
	};

	struct pfs_repack_dump_indirect_block_cb_args {
		struct file_map* map;
	};

	struct pkg_repack_self_cb_args {
		struct pkg* pkg;
		const char* elf_directory;
	};
#endif

struct pkg_unpack_sc_entries_cb_args {
	const char* output_directory;
	pfs_unpack_pre_cb pre_cb;
	void* pre_cb_arg;
};

static int pfs_get_size_cb(void* arg, uint64_t* size);
static int pfs_get_outer_location_cb(void* arg, uint64_t offset, uint64_t* outer_offset);
static int pfs_get_offset_size_cb(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed);
static int pfs_seek_cb(void* arg, uint64_t offset);
static int pfs_read_cb(void* arg, void* data, uint64_t data_size);
static int pfs_write_cb(void* arg, void* data, uint64_t data_size);
static int pfs_can_seek_cb(void* arg, uint64_t offset);
static int pfs_can_read_cb(void* arg, uint64_t data_size);
static int pfs_can_write_cb(void* arg, uint64_t data_size);

typedef int (*cmd_handler_t)(void* arg);

#if defined(ENABLE_REPACK_SUPPORT)
#	define RIGHT_SPRX_PATH "/sce_sys/about/right.sprx"

	int test_fself(void) {
		struct file_map* self_map = NULL;
		struct file_map* elf_map = NULL;
		uint8_t* new_self_data = NULL;
		struct self* new_self = NULL;
		struct self* self = NULL;
		struct elf* elf = NULL;
		int status = 0;

		self_map = map_file("eboot.bin");
		if (!self_map)
			goto error;

		elf_map = map_file("eboot.bin.elf");
		if (!elf_map)
			goto error;

		self = self_alloc(self_map->data, self_map->size);
		if (!self)
			goto error;

		elf = elf_alloc(elf_map->data, elf_map->size, 0);
		if (!elf)
			goto error;

		new_self_data = (uint8_t*)malloc(self_map->size);
		if (!new_self_data)
			goto error;
		memset(new_self_data, 0, self_map->size);
		memcpy(new_self_data, self_map->data, self_map->size);

		new_self = self_alloc(new_self_data, self_map->size);
		if (!new_self)
			goto error;

		status = self_make_fake_signed(new_self, elf);
		if (!status) {
			warning("Unable to make fake signed elf.");
			goto error;
		}

		if (!write_to_file("eboot.fself", new_self_data, self_map->size, NULL, 0644))
			warning("Unable to write file.");

error:
		if (new_self)
			self_free(new_self);

		if (new_self_data)
			free(new_self_data);

		if (elf)
			elf_free(elf);

		if (self)
			self_free(self);

		if (elf_map)
			unmap_file(elf_map);

		if (self_map)
			unmap_file(self_map);

		return status;
	}
#endif

static enum cb_result pkg_pfs_unpack_pre_cb(void* arg, const char* path, enum pfs_entry_type type, int* needed) {
	const char* type_str;
	const char* tmp_path = path;
	const char* file_name = NULL;
	char** p;
	int match;

	UNUSED(arg);

	while (*tmp_path == '/')
		++tmp_path;
	if (*tmp_path == '\0')
		tmp_path = path;

	if (type == PFS_ENTRY_FILE) {
		file_name = strrchr(tmp_path, '/');
		if (file_name)
			++file_name;
		else
			file_name = tmp_path;
		if (file_name == tmp_path || *file_name == '\0')
			file_name = NULL;
	}

	if (s_file_paths) {
		p = NULL;
		match = 0;
		while ((p = (char**)utarray_next(s_file_paths, p))) {
			if (!*p)
				continue;
			if (wildcard_match(tmp_path, *p)) {
				match = 1;
				break;
			}
			if (file_name && wildcard_match(file_name, *p)) {
				match = 1;
				break;
			}
		}
	} else {
		match = 1;
	}

	if (match) {
		switch (type) {
			case PFS_ENTRY_FILE: type_str = "file"; break;
			case PFS_ENTRY_DIRECTORY: type_str = "directory"; break;
			default: type_str = "<unknown type>"; break;
		}

		info("Unpacking %s: %s", type_str, tmp_path);
	}

	if (needed)
		*needed = match;

	return CB_RESULT_CONTINUE;
}

static int tweak_pfs_options(struct pfs_options* opts, struct pkg* pkg) {
	int status = 0;

	assert(opts != NULL);

	if (s_no_signature_check > 0)
		opts->skip_signature_check = 1;
	if (s_no_icv_check > 0)
		opts->skip_block_hash_check = 1;

	if (pkg) {
		if (s_key_content_id)
			opts->content_id = pkg->hdr->content_id;
		if (s_key_content_id) {
			if (opts->keyset) {
				if (strcmp(opts->keyset->content_id, s_key_content_id) != 0)
					opts->keyset = keymgr_get_title_keyset(s_key_content_id);
			} else {
				opts->keyset = keymgr_get_title_keyset(s_key_content_id);
			}
		}
	} else {
#if defined(ENABLE_SD_KEYGEN)
		if (s_key_content_id && !opts->is_sd) {
#else
		if (s_key_content_id) {
#endif
			opts->keyset = keymgr_get_title_keyset(s_key_content_id);
		} else {
			opts->keyset = keymgr_alloc_title_keyset(KEYMGR_FAKE_CONTENT_ID, 0);
		}
	}

	if (opts->keyset) {
#if defined(ENABLE_SD_KEYGEN)
		if (s_passcode && !opts->is_sd) {
#else
		if (s_passcode) {
#endif
			memcpy(opts->keyset->passcode, s_passcode, sizeof(opts->keyset->passcode));
			opts->keyset->flags.has_passcode = 1;
		}
#if defined(ENABLE_SD_KEYGEN)
		if (s_sealed_key_file) {
			memset(opts->keyset->mkey, 0, sizeof(opts->keyset->mkey));
			if (!pfs_decrypt_sealed_key_from_file(s_sealed_key_file, opts->keyset->mkey))
				goto error;
			opts->keyset->flags.has_mkey = 1;
		}
#endif
		if (s_encdec_tweak_key) {
			memcpy(opts->keyset->enc_tweak_key, s_encdec_tweak_key, sizeof(opts->keyset->enc_tweak_key));
			opts->keyset->flags.has_enc_tweak_key = 1;
		}
		if (s_encdec_data_key) {
			memcpy(opts->keyset->enc_data_key, s_encdec_data_key, sizeof(opts->keyset->enc_data_key));
			opts->keyset->flags.has_enc_data_key = 1;
		}
		if (s_sign_key) {
			memcpy(opts->keyset->sig_hmac_key, s_sign_key, sizeof(opts->keyset->sig_hmac_key));
			opts->keyset->flags.has_sig_hmac_key = 1;
		}
		if (s_sc0_key) {
			memcpy(opts->keyset->sc0_key, s_sc0_key, sizeof(opts->keyset->sc0_key));
			opts->keyset->flags.has_sc0_key = 1;
		}
	}

	status = 1;

error:
	return status;
}

static int set_pkg_pfs_options_cb(void* arg, struct pkg* pkg, struct pfs_options* opts) {
	assert(pkg != NULL);
	assert(opts != NULL);

	UNUSED(arg);

	opts->disable_pkg_pfs_usage = (s_pfs != NULL);

	if (!s_gp4_file)
		opts->skip_keygen = s_no_unpack && s_unpack_sc_entries ? 1 : 0;

	if (s_cmd_info)
		opts->skip_keygen = 2;

	opts->dump_final_keys = s_dump_final_keys;
#if defined(ENABLE_SD_KEYGEN)
	opts->dump_sd_info = s_dump_sd_info;
#endif

	return tweak_pfs_options(opts, pkg);
}

static void cleanup_pfs(struct pfs_io_context* ctx) {
	assert(ctx != NULL);

	if (s_pfs) {
		pfs_free(s_pfs);
		s_pfs = NULL;
	}

	if (ctx->map)
		unmap_file(ctx->map);
}

static int setup_pfs(struct pfs_io_context* ctx, struct pfs_io_callbacks* io, const char* file_path, int inside_pkg) {
	struct pfs_options pfs_opts;

	assert(ctx != NULL);
	assert(io != NULL);
	assert(file_path != NULL);

	memset(ctx, 0, sizeof(*ctx));

	ctx->map = map_file(file_path);
	if (!ctx->map)
		goto error;

	ctx->offset = 0;

	memset(io, 0, sizeof(*io));
	{
		io->arg = ctx;
		io->get_size = &pfs_get_size_cb;
		io->get_outer_location = &pfs_get_outer_location_cb;
		io->get_offset_size = &pfs_get_offset_size_cb;
		io->seek = &pfs_seek_cb;
		io->read = &pfs_read_cb;
		io->write = &pfs_write_cb;
		io->can_seek = &pfs_can_seek_cb;
		io->can_read = &pfs_can_read_cb;
		io->can_write = &pfs_can_write_cb;
	}

	memset(&pfs_opts, 0, sizeof(pfs_opts));
	{
		pfs_opts.content_id = NULL;
		pfs_opts.finalized = 1;
		pfs_opts.playgo = 0;
		pfs_opts.case_sensitive = 0;
		pfs_opts.skip_signature_check = 1;
		pfs_opts.skip_block_hash_check = 0;
		pfs_opts.dump_final_keys = s_dump_final_keys;
#if defined(ENABLE_SD_KEYGEN)
		pfs_opts.dump_sd_info = s_dump_sd_info;
		pfs_opts.is_sd = !inside_pkg && s_sealed_key_file;
#else
		UNUSED(inside_pkg);
#endif
	}

	if (!tweak_pfs_options(&pfs_opts, NULL))
		goto error;

	s_pfs = pfs_alloc(io, &pfs_opts, 0);
	if (!s_pfs)
		goto error;

	return 1;

error:
	cleanup_pfs(ctx);

	return 0;
}

static int process_pfs(cmd_handler_t handler) {
	struct pfs_io_context ctx;
	struct pfs_io_callbacks io;
	int ret = 1;

	if (!setup_pfs(&ctx, &io, s_input_file_path, 0))
		goto error;

	if (handler)
		ret = (*handler)(&ctx.map->size);
	else
		ret = 1;

	cleanup_pfs(&ctx);

error:
	return ret;
}

static int pfs_list_handler(void* arg) {
	assert(s_pfs != NULL);

	UNUSED(arg);

	if (!pfs_list_user_root_directory(s_pfs))
		error("Unable to list entries from PFS file: %s", s_input_file_path);

	return 0;
}

static int pfs_unpack_handler(void* arg) {
	assert(s_pfs != NULL);

	UNUSED(arg);

	if (!s_no_unpack) {
		if (!pfs_unpack_all(s_pfs, s_output_directory, &pkg_pfs_unpack_pre_cb, NULL))
			error("Unable to unpack PFS file: %s", s_input_file_path);
	}

	return 0;
}

#if defined(ENABLE_REPACK_SUPPORT)
	static int pfs_repack_dump_indirect_block_cb(void* arg, struct pfs* pfs, uint64_t block_no, uint64_t block_count, uint8_t* block_data) {
		struct pfs_repack_dump_indirect_block_cb_args* args = (struct pfs_repack_dump_indirect_block_cb_args*)arg;
		uint8_t* data;
		uint64_t data_size;
		int status = 0;

		assert(args != NULL);
		assert(args->map != NULL);
		assert(pfs != NULL);
		assert(block_data != NULL);

		data = args->map->data + pfs_block_no_to_offset(pfs, block_no);
		data_size = pfs_block_no_to_offset(pfs, block_count);

		memcpy(data, block_data, data_size);

		status = 1;

		return status;
	}

	static int pfs_repack_process_file(struct pfs* pfs, struct file_map* map, struct pfs_file_context* file, int as_is) {
		uint8_t* chunk;
		size_t chunk_size;
		uint64_t* blocks;
		uint8_t* data;
		uint64_t offset, size_left;
		uint64_t block_count;
		size_t block_size;
		size_t cur_size;
		uint64_t i; // FIXME: it was uint64_t
		int status = 0;

		assert(pfs != NULL);
		assert(file != NULL);

		if (file->dinode_block_no != 0) {
			data = map->data + pfs_block_no_to_offset(pfs, file->dinode_block_no) + file->dinode_offset;
			memcpy(data, &file->dinode, pfs->dinode_struct_size);
		}

		if (file->file_size > 0) {
			if (as_is) {
				assert(file->block_list != NULL);
				block_count = file->block_list->count;
				assert(block_count != 0);
				blocks = file->block_list->blocks;
				assert(blocks != NULL);

				block_size = pfs->basic_block_size;

				for (i = 0; i < block_count; ++i) {
				//for (i = block_count - 0; i >= 0; --i) {
					if (!pfs_read_blocks(pfs, blocks[i], file->tmp_block, 1))
						goto error;

#if 1 // FIXME
					data = map->data + pfs_block_no_to_offset(pfs, blocks[i]);
					memcpy(data, file->tmp_block, block_size);
#elif 0
					if (!pfs_write_blocks(pfs, blocks[i], file->tmp_block, 1))
						goto error;
#endif
				}
			} else {
				// TODO: need to rebuild blocks

				assert(file->block_list != NULL);
				block_count = file->block_list->count;
				assert(block_count != 0);
				blocks = file->block_list->blocks;
				assert(blocks != NULL);

				chunk = file->tmp_block;
				chunk_size = pfs->basic_block_size;

				data = map->data + pfs_block_no_to_offset(pfs, blocks[0]);

				for (i = 0; i < block_count; ++i) {
					printf("%ld ", blocks[i]);
				}
				printf("\n");

				memset(chunk, 0, chunk_size);

				offset = 0;
				size_left = file->file_size;
				while (size_left != 0) {
					cur_size = (size_left > chunk_size) ? chunk_size : (size_t)size_left;

					if (!pfs_file_read(file, offset, chunk, cur_size))
						goto error;

					memcpy(data, chunk, cur_size);

					data += cur_size;
					offset += cur_size;
					size_left -= cur_size;
				}
			}
		}

		status = 1;

error:
		return status;
	}

	static inline int pfs_repack_process_ino(struct pfs* pfs, struct file_map* map, pfs_ino ino, int as_is) {
		struct pfs_repack_dump_indirect_block_cb_args dump_args;
		struct pfs_file_context* file = NULL;
		int status = 0;

		assert(pfs != NULL);
		assert(map != NULL);

		memset(&dump_args, 0, sizeof(dump_args));

		dump_args.map = map;

		file = pfs_get_file_ex(pfs, ino, &pfs_repack_dump_indirect_block_cb, &dump_args);
		if (!file)
			goto error;

		status = pfs_repack_process_file(pfs, map, file, as_is);

error:
		if (file)
			pfs_free_file(file);

		return status;
	}

	static enum cb_result pfs_repack_process_dir_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* name) {
		struct pfs_repack_process_dir_cb_args* args = (struct pfs_repack_process_dir_cb_args*)arg;
		struct pfs_file_context* file = NULL;
		int as_is;
		uint8_t* data = NULL;

		assert(args != NULL);

		assert(pfs != NULL);

#		if defined(DECOMPRESS_INNER_PFS)
			as_is = strcmp(name, PKG_PFS_IMAGE_FILE_NAME) != 0;
#		else
			as_is = 1;
#		endif

		pfs_repack_process_ino(pfs, args->map, ino, as_is);

		file = pfs_get_file(pfs, ino);
		if (!file)
			goto error;

		if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
			if (type == PFS_ENTRY_DIRECTORY) {
				data = (uint8_t*)malloc(file->file_size);
				if (!data)
					goto error;
				memset(data, 0, file->file_size);

				if (!pfs_file_read(file, 0, data, file->file_size))
					goto error;

				pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_repack_process_dir_cb, arg);
			}
		}

done:
		if (data)
			free(data);

		if (file)
			pfs_free_file(file);

		return CB_RESULT_CONTINUE;

error:
		warning("Unable to get file: %s", name);
		goto done;
	}

	static int pfs_repack_process_dir(struct pfs* pfs, struct file_map* map, pfs_ino dir_ino) {
		struct pfs_repack_process_dir_cb_args args;
		struct pfs_file_context* file = NULL;
		uint8_t* data = NULL;
		int status = 0;

		assert(pfs != NULL);
		assert(map != NULL);

		file = pfs_get_file(pfs, dir_ino);
		if (!file)
			goto error;

		status = pfs_repack_process_ino(pfs, map, dir_ino, 1);
		if (!status)
			goto error;

		data = (uint8_t*)malloc(file->file_size);
		if (!data)
			goto error;
		memset(data, 0, file->file_size);

		if (!pfs_file_read(file, 0, data, file->file_size))
			goto error;

		memset(&args, 0, sizeof(args));
		{
			args.map = map;
		}

		pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_repack_process_dir_cb, &args);

		status = 1;

error:
		if (data)
			free(data);

		if (file)
			pfs_free_file(file);

		return status;
	}

	static int pfs_repack_internal(struct pfs* pfs, struct file_map* map) {
		struct pfs_header hdr;
		uint8_t* header_data = NULL;
		int status = 0;

		assert(pfs != NULL);
		assert(map != NULL);

		memcpy(&hdr, &pfs->hdr, sizeof(pfs->hdr));

		//hdr.mode &= ~LE16(PFS_MODE_SIGNED_FLAG);
		//hdr.mode &= ~LE16(PFS_MODE_ENCRYPTED_FLAG); // FIXME: uncomment

		header_data = (uint8_t*)malloc(PFS_HEADER_SIZE);
		if (!header_data)
			goto error;
		memset(header_data, 0, PFS_HEADER_SIZE);
		memcpy(header_data, &hdr, PFS_HEADER_COVER_SIZE_FOR_ICV);
		pfs_sign_buffer(pfs, header_data, PFS_HEADER_SIZE, hdr.header_hash);

		memcpy(map->data, &hdr, sizeof(hdr));

		//pfs_repack_process_ino(s_pfs, map, s_pfs->super_root_dir_ino);
		/*if (s_pfs->block_bitmap_ino > 0)
			pfs_repack_process_ino(s_pfs, map, s_pfs->block_bitmap_ino);
		if (s_pfs->ino_bitmap_ino > 0)
			pfs_repack_process_ino(s_pfs, map, s_pfs->ino_bitmap_ino);
		if (s_pfs->user_root_dir_ino > 0)
			pfs_repack_process_ino(s_pfs, map, s_pfs->user_root_dir_ino);
		if (s_pfs->block_addr_table_ino > 0)
			pfs_repack_process_ino(s_pfs, map, s_pfs->block_addr_table_ino);
		if (s_pfs->flat_path_table_ino > 0)
			pfs_repack_process_ino(s_pfs, map, s_pfs->flat_path_table_ino);
		if (s_pfs->collision_resolver_ino > 0)
			pfs_repack_process_ino(s_pfs, map, s_pfs->collision_resolver_ino);*/

		/*
		super_root_dir_ino = 0
		block_bitmap_ino = 2
		ino_bitmap_ino = 4
		user_root_dir_ino = 1
		block_addr_table_ino = 5
		flat_path_table_ino = 0
		collision_resolver_ino = 0
		*/

		pfs_repack_process_dir(pfs, map, pfs->super_root_dir_ino);
		//pfs_repack_process_dir(pfs, map, pfs->user_root_dir_ino);

		status = 1;

error:
		if (header_data)
			free(header_data);

		return status;
	}

	static int pfs_repack_handler(void* arg) {
		uint64_t file_size;
		struct file_map* map = NULL;
		int status = 0;

		assert(s_pfs != NULL);
		assert(arg != NULL);

		file_size = *(uint64_t*)arg;

		map = map_file_for_write(s_output_file_path, file_size, 0644);
		if (!map)
			goto error;

		status = pfs_repack_internal(s_pfs, map);

error:
		if (map)
			unmap_file(map);

		return status;
	}
#endif

static int process_pkg(cmd_handler_t handler) {
	struct pfs_io_context pfs_ctx;
	struct pfs_io_callbacks pfs_io;
	int ret = 1;

	if (s_pfs_image_data_file) {
		if (!setup_pfs(&pfs_ctx, &pfs_io, s_pfs_image_data_file, 1)) {
			warning("Unable to load PFS file: %s", s_pfs_image_data_file);
			goto error;
		}
	}

	s_pkg = pkg_alloc(s_input_file_path, &set_pkg_pfs_options_cb, NULL);
	if (!s_pkg)
		error("Unable to load PKG file: %s", s_input_file_path);

	if (handler)
		ret = (*handler)(&s_pkg->map->size);
	else
		ret = 1;

error:
	if (s_pfs_image_data_file)
		cleanup_pfs(&pfs_ctx);

	pkg_free(s_pkg);
	s_pkg = NULL;

	return ret;
}

static int pkg_list_handler(void* arg) {
	assert(s_pkg != NULL);

	UNUSED(arg);

	if (!s_pfs_image_data_file) {
		if (!pfs_list_user_root_directory(s_pkg->inner_pfs))
			error("Unable to list entries from PKG file: %s", s_input_file_path);
	} else {
		if (!pfs_list_user_root_directory(s_pfs))
			error("Unable to list entries from PFS file: %s", s_pfs_image_data_file);
	}

	return 0;
}

static enum cb_result pkg_unpack_sc_entries_cb(void* arg, struct pkg* pkg, struct pkg_entry_desc* desc) {
	struct pkg_unpack_sc_entries_cb_args* args = (struct pkg_unpack_sc_entries_cb_args*)arg;
	char file_path[PATH_MAX], directory[PATH_MAX];
	struct pkg_entry_keyset entry_keyset;
	uint8_t* new_data = NULL;
	uint8_t* data;
	uint32_t data_size, data_size_aligned;
	uint64_t data_offset;
	int needed;
	enum cb_result ret = CB_RESULT_CONTINUE;

	assert(args != NULL);
	assert(args->output_directory != NULL);

	assert(pkg != NULL);
	assert(desc != NULL);

	snprintf(file_path, sizeof(file_path), "%s%s", args->output_directory, desc->name);
	path_get_directory(directory, sizeof(directory), file_path);

	data = pkg_locate_entry_data(pkg, desc->id, &data_offset, &data_size);
	if (!data)
		error("Unable to find data for entry '%s'.", desc->name);

	data_size_aligned = align_up_32(data_size, 16);

	if (desc->is_encrypted || desc->use_new_algo) {
		if (!pkg_get_entry_keyset(pkg, desc->id, &entry_keyset)) {
			if (pkg->finalized) { /* could skip some known undecryptable files? */
				switch (desc->id) {
					case PKG_ENTRY_ID__LICENSE_INFO:
						goto done;
					default:
						break;
				}
			}
			warning("Unable to get key for entry '%s', skipping...", desc->name);
			goto done;
		}
	}

	if (args->pre_cb) {
		ret = (*args->pre_cb)(args->pre_cb_arg, file_path, PFS_ENTRY_FILE, &needed);
		if (ret == CB_RESULT_STOP)
			goto done;
		else if (ret == CB_RESULT_CONTINUE && !needed)
			goto done;
	}

	if (*directory != '\0')
		make_directories(directory, 0755);

	new_data = (uint8_t*)malloc(data_size_aligned);
	if (!new_data)
		error("Unable to allocate memory for data of size 0x%08" PRIX32 " bytes for entry '%s'.", data_size_aligned, desc->name);

	memset(new_data, 0, data_size_aligned);
	if (desc->use_new_algo)
		aes_decrypt_oex(entry_keyset.key, sizeof(entry_keyset.key), data_offset, data, new_data, data_size);
	else if (desc->is_encrypted)
		aes_decrypt_cbc_cts(entry_keyset.key, sizeof(entry_keyset.key), entry_keyset.iv, data, new_data, data_size_aligned);
	else
		memcpy(new_data, data, data_size);

	if (!write_to_file(file_path, new_data, data_size, NULL, 0644))
		error("Unable to write file '%s'.", file_path);

done:
	if (new_data)
		free(new_data);

	return ret;
}

static int pkg_create_dummy_shareparam_json(struct pkg* pkg, const char* output_directory, const char* name, int* created) {
	char file_path[PATH_MAX], directory[PATH_MAX];
	struct sfo* sfo = NULL;
	struct sfo_entry* sfo_entry;
	uint8_t* sfo_data;
	uint32_t sfo_data_size;
	char app_ver_str[sizeof("00.00")];
	UT_string* content = NULL;
	int status = 0;

	assert(pkg != NULL);
	assert(output_directory != NULL);
	assert(name != NULL);

	if (created)
		*created = 0;

	sfo_data = pkg_locate_entry_data(pkg, PKG_ENTRY_ID__PARAM_SFO, NULL, &sfo_data_size);
	if (!sfo_data) {
		// No param.sfo (package file is not a game package?).
		goto done;
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

	sfo_entry = sfo_find_entry(sfo, "APP_VER");
	if (sfo_entry) {
		if (sfo_entry->format != SFO_FORMAT_STRING || sfo_entry->size < strlen("00.00") + 1) {
			warning("Invalid format of APP_VER entry in system file object.");
			goto error;
		}
		snprintf(app_ver_str, sizeof(app_ver_str), "%s", (const char*)sfo_entry->value);
	} else {
		snprintf(app_ver_str, sizeof(app_ver_str), "%02u.%02u", 1, 0);
		warning("No APP_VER entry in system file object, using default app version '%s'.", app_ver_str);
	}

	utstring_new(content);
	utstring_printf(content,
		"{\n"
		"\t\"ps4_share_param_version\":\"%02u.%02u\",\n"
		"\t\"game_version\":\"%s\",\n"
#if 0
		"\t\"client\":\"\",\n"
#endif
		"\t\"overlay_position\":{\n"
		"\t\t\"x\":0,\n"
		"\t\t\"y\":0\n"
		"\t}\n"
		"}\n",
		PKG_SHAREPARAM_FILE_VERSION_MAJOR, PKG_SHAREPARAM_FILE_VERSION_MINOR,
		app_ver_str
	);

	snprintf(file_path, sizeof(file_path), "%s%s", output_directory, name);

	path_get_directory(directory, sizeof(directory), file_path);
	if (*directory != '\0')
		make_directories(directory, 0755);

	if (!write_to_file(file_path, utstring_body(content), utstring_len(content), NULL, 0644)) {
		warning("Unable to write file '%s'.", file_path);
		goto error;
	}

	if (created)
		*created = 1;

done:
	status = 1;

error:
	if (content)
		utstring_free(content);
	if (sfo)
		sfo_free(sfo);

	return status;
}

static int pkg_info_handler(void* arg) {
	char output_directory[PATH_MAX];
	struct pkg_unpack_sc_entries_cb_args unpack_sc_entries_args;
	uint8_t* data;
	uint32_t data_size;
	struct sfo* sfo = NULL;
	struct playgo* plgo = NULL;
	int ret = 1;

	assert(s_pkg != NULL);

	UNUSED(arg);

	if (s_unpack_sc_entries) {
		memset(&unpack_sc_entries_args, 0, sizeof(unpack_sc_entries_args));
		{
			snprintf(output_directory, sizeof(output_directory), "%s/Sc0/", s_output_directory);
			unpack_sc_entries_args.output_directory = output_directory;
			unpack_sc_entries_args.pre_cb = &pkg_pfs_unpack_pre_cb;
			unpack_sc_entries_args.pre_cb_arg = NULL;
		}
		pkg_enum_entries(s_pkg, &pkg_unpack_sc_entries_cb, &unpack_sc_entries_args, s_unpack_extra_sc_entries);
	}

	if (s_dump_sfo) {
		data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PARAM_SFO, NULL, &data_size);
		if (data) {
			sfo = sfo_alloc();
			if (!sfo) {
				warning("Unable to allocate memory for system file object.");
				goto error;
			}
			if (!sfo_load_from_memory(sfo, data, data_size)) {
				warning("Unable to load system file object.");
				goto error;
			}
			sfo_dump(sfo);

			sfo_free(sfo);
			sfo = NULL;
		} else {
			warning("System file object data is not found.");
		}
	}

	if (s_dump_playgo) {
		data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PLAYGO_CHUNK_DAT, NULL, &data_size);
		if (data) {
			plgo = playgo_alloc();
			if (!plgo) {
				warning("Unable to allocate memory for playgo object.");
				goto error;
			}
			if (!playgo_load_from_memory(plgo, data, data_size)) {
				warning("Unable to load playgo file object.");
				goto error;
			}
			playgo_dump(plgo);

			playgo_free(plgo);
			plgo = NULL;
		} else {
			if (BE32(s_pkg->hdr->content_type) == CONTENT_TYPE_GD)
				warning("Playgo data is not found.");
		}
	}

	ret = 0;

error:
	if (plgo)
		playgo_free(plgo);
	if (sfo)
		sfo_free(sfo);

	return ret;
}

static int pkg_unpack_handler(void* arg) {
	char output_directory[PATH_MAX];
	struct pkg_table_entry* entry;
	struct pkg_unpack_sc_entries_cb_args unpack_sc_entries_args;
	struct pfs* inner_pfs = NULL;
	struct pfs* outer_pfs = NULL;
	uint8_t* data;
	uint32_t data_size;
	struct sfo* sfo = NULL;
	struct playgo* plgo = NULL;
	int shareparam_created;
	int ret = 1;

	assert(s_pkg != NULL);

	UNUSED(arg);

	if (!s_pfs) {
		outer_pfs = s_pkg->pfs;
		inner_pfs = s_pkg->inner_pfs;
	} else {
		inner_pfs = s_pfs;
	}

	if (s_unpack_sc_entries) {
		memset(&unpack_sc_entries_args, 0, sizeof(unpack_sc_entries_args));
		{
			snprintf(output_directory, sizeof(output_directory), "%s/Sc0/", s_output_directory);
			unpack_sc_entries_args.output_directory = output_directory;
			unpack_sc_entries_args.pre_cb = &pkg_pfs_unpack_pre_cb;
			unpack_sc_entries_args.pre_cb_arg = NULL;
		}
		pkg_enum_entries(s_pkg, &pkg_unpack_sc_entries_cb, &unpack_sc_entries_args, s_unpack_extra_sc_entries);

		if (s_gp4_file && BE32(s_pkg->hdr->content_type) == CONTENT_TYPE_GD && !pkg_is_patch(s_pkg)) {
			// Create shareparam.json for game data if not exists.
			entry = pkg_find_entry(s_pkg, PKG_ENTRY_ID__SHAREPARAM_JSON);
			if (!entry) {
				if (pkg_create_dummy_shareparam_json(s_pkg, output_directory, PKG_ENTRY_NAME__SHAREPARAM_JSON, &shareparam_created)) {
					if (shareparam_created)
						warning("Share parameters file is not found, dummy file was created.");
				} else {
					warning("Unable to create share parameters file.");
				}
			}
		}
	}

	if (s_dump_sfo) {
		data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PARAM_SFO, NULL, &data_size);
		if (data) {
			sfo = sfo_alloc();
			if (!sfo) {
				warning("Unable to allocate memory for system file object.");
				goto error;
			}
			if (!sfo_load_from_memory(sfo, data, data_size)) {
				warning("Unable to load system file object.");
				goto error;
			}
			sfo_dump(sfo);

			sfo_free(sfo);
			sfo = NULL;
		} else {
			warning("System file object data is not found.");
		}
	}

	if (s_dump_playgo) {
		data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PLAYGO_CHUNK_DAT, NULL, &data_size);
		if (data) {
			plgo = playgo_alloc();
			if (!plgo) {
				warning("Unable to allocate memory for playgo object.");
				goto error;
			}
			if (!playgo_load_from_memory(plgo, data, data_size)) {
				warning("Unable to load playgo file object.");
				goto error;
			}
			playgo_dump(plgo);

			playgo_free(plgo);
			plgo = NULL;
		} else {
			if (BE32(s_pkg->hdr->content_type) == CONTENT_TYPE_GD)
				warning("Playgo data is not found.");
		}
	}

	if (s_gp4_file) {
		if (!pkg_generate_gp4_project(s_pkg, s_pfs ? s_pfs : s_pkg->inner_pfs, s_meta_data_in_file, s_gp4_file, s_output_directory, s_meta_data_out_file, s_use_random_passcode, s_all_compressed))
			warning("Unable to generate GP4 project file for PKG file: %s", s_input_file_path);
	}

	if (s_unpack_outer_pfs && outer_pfs) {
		// XXX: reuse path variable
		snprintf(output_directory, sizeof(output_directory), "%s/outer_pfs_image.dat", s_output_directory);

		if (!pfs_dump_to_file(outer_pfs, output_directory, &pkg_pfs_unpack_pre_cb, NULL))
			warning("Unable to unpack file '%s' from PKG file: %s", "outer_pfs_image.dat", s_input_file_path);
	}

	if (s_unpack_inner_pfs && outer_pfs) {
		snprintf(output_directory, sizeof(output_directory), "%s/", s_output_directory);

		if (!pfs_unpack_single(outer_pfs, PKG_PFS_IMAGE_FILE_NAME, output_directory, &pkg_pfs_unpack_pre_cb, NULL))
			warning("Unable to unpack file '%s' from PKG file: %s", PKG_PFS_IMAGE_FILE_NAME, s_input_file_path);
	}

	if (!s_no_unpack) {
		snprintf(output_directory, sizeof(output_directory), "%s/Image0", s_output_directory);

		if (!pfs_unpack_all(inner_pfs, output_directory, &pkg_pfs_unpack_pre_cb, NULL)) {
			if (!s_pfs)
				error("Unable to unpack PKG file: %s", s_input_file_path);
			else
				error("Unable to unpack PFS file: %s", s_pfs_image_data_file);
		}
	}

	ret = 0;

error:
	if (plgo)
		playgo_free(plgo);
	if (sfo)
		sfo_free(sfo);

	return ret;
}

#if defined(ENABLE_REPACK_SUPPORT)
	static int pkg_repack_self(struct pkg* pkg, const char* file_path, const char* real_file_path) {
		struct pfs_file_context* file = NULL;
		struct self* self = NULL;
		struct self* new_self = NULL;
		struct file_map* elf_map = NULL;
		struct elf* elf = NULL;
		uint8_t* data = NULL;
		uint8_t* new_self_data = NULL;
		pfs_ino ino;
		int status = 0;

		assert(pkg != NULL);
		assert(pkg->inner_pfs != NULL);
		assert(file_path != NULL);
		assert(real_file_path != NULL);

		if (!pfs_lookup_path_user(pkg->inner_pfs, file_path, &ino)) {
			warning("Unable to lookup SELF file: %s\n", file_path);
			goto error;
		}

		file = pfs_get_file(pkg->inner_pfs, ino);
		if (!file) {
			warning("Unable to get SELF file: %s\n", file_path);
			goto error;
		}

		elf_map = map_file(real_file_path);
		if (!elf_map)
			goto error;

		elf = elf_alloc(elf_map->data, elf_map->size, 0);
		if (!elf)
			goto error;

		data = (uint8_t*)malloc(file->file_size);
		if (!data)
			goto error;
		memset(data, 0, file->file_size);

		if (!pfs_file_read(file, 0, data, file->file_size))
			goto error;

		self = self_alloc(data, (size_t)file->file_size);
		if (!self)
			goto error;

		new_self_data = (uint8_t*)malloc(file->file_size);
		if (!new_self_data)
			goto error;
		memcpy(new_self_data, data, file->file_size);

		new_self = self_alloc(new_self_data, (size_t)file->file_size);
		if (!new_self)
			goto error;

		status = self_make_fake_signed(new_self, elf);
		if (!status) {
			warning("Unable to make fake signed elf.");
			goto error;
		}

		if (!write_to_file("test.fself", new_self_data, file->file_size, NULL, 0644))
			warning("Unable to write file.");

error:
		if (new_self)
			self_free(new_self);

		if (new_self_data)
			free(new_self_data);

		if (self)
			self_free(self);

		if (data)
			free(data);

		if (elf)
			elf_free(elf);

		if (elf_map)
			unmap_file(elf_map);

		if (file)
			pfs_free_file(file);

		return status;
	}

	static int pkg_repack_self_cb(void* arg, const char* parent_name, const char* child_name, unsigned int mode) {
		struct pkg_repack_self_cb_args* args = (struct pkg_repack_self_cb_args*)arg;
		char file_path[PATH_MAX];
		char file_path_fixed[PATH_MAX];
		uint32_t elf_magic = ELF_MAGIC;
		size_t i;
		int found;
		char* p;

		static const char* extensions[] = {
			".bin",
			".self",
			".sprx",
			".elf",
			".prx",
		};
		static const size_t extension_count = COUNT_OF(extensions);

		assert(args != NULL);
		assert(args->pkg != NULL);
		assert(args->elf_directory != NULL);
		assert(parent_name != NULL);
		assert(child_name != NULL);

		snprintf(file_path, sizeof(file_path), "%s/%s", parent_name, child_name);

		p = strstr(file_path, args->elf_directory);
		if (p)
			strncpy(file_path_fixed, p + strlen(args->elf_directory), sizeof(file_path_fixed));
		else
			strncpy(file_path_fixed, args->elf_directory, sizeof(file_path_fixed));

		if (ends_with_nocase(file_path_fixed, RIGHT_SPRX_PATH)) {
			info("Skipping SELF file: %s", file_path_fixed);
			goto done;
		}

		if (S_ISREG(mode)) {
			found = 0;
			for (i = 0; i < extension_count; ++i) {
				if (ends_with_nocase(child_name, extensions[i])) {
					found = 1;
					break;
				}
			}
			if (!found)
				goto done;

			if (!is_file(file_path) && !is_readable(file_path))
				goto done;
			if (!file_has_magic(file_path, &elf_magic, sizeof(elf_magic)))
				goto done;

			info("Repacking SELF file: %s", file_path_fixed);
			pkg_repack_self(args->pkg, file_path_fixed, file_path);
		}

done:
		return CB_RESULT_CONTINUE;
	}

	static int pkg_repack_handler(void* arg) {
		uint64_t file_size;
		struct file_map* map = NULL;
		struct file_map* submap = NULL;
		struct pkg_header hdr;
		uint8_t* entry_data;
		uint32_t entry_size;
		uint64_t playgo_chunk_count, playgo_chunk_idx;
		uint8_t playgo_chunk_hash[PKG_HASH_SIZE];
		struct pkg_repack_self_cb_args repack_self_args;
		int ret = 1;

		assert(s_pkg != NULL);
		assert(arg != NULL);

		file_size = *(uint64_t*)arg;

		memcpy(&hdr, s_pkg->hdr, sizeof(*s_pkg->hdr));

		map = map_file_for_write(s_output_file_path, file_size, 0644);
		if (!map)
			goto error;

		memcpy(map->data, s_pkg->map->data, s_pkg->pfs_image_offset);

		submap = map_file_sub_region(map, s_pkg->pfs_image_offset, s_pkg->pfs_image_size);
		if (!submap)
			goto error;

		ret = pfs_repack_internal(s_pkg->pfs, submap);

		if (!s_no_elf_repack) {
			memset(&repack_self_args, 0, sizeof(repack_self_args));

			repack_self_args.pkg = s_pkg;
			repack_self_args.elf_directory = s_plaintext_elf_directory;

			list_directory_r(s_plaintext_elf_directory, &pkg_repack_self_cb, &repack_self_args);
		}

		if (!s_no_hash_recalc) {
			entry_data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PLAYGO_CHUNK_SHA, &entry_size);
			if (entry_data) {
				entry_data = map->data + (entry_data - s_pkg->map->data) + PKG_PLAYGO_CHUNK_HASH_TABLE_OFFSET;
				playgo_chunk_count = s_pkg->pfs_image_size / PKG_PLAYGO_PFS_CHUNK_SIZE;
				for (playgo_chunk_idx = 0; playgo_chunk_idx < playgo_chunk_count; ++playgo_chunk_idx) {
					sha256_buffer(submap->data + playgo_chunk_idx * PKG_PLAYGO_PFS_CHUNK_SIZE, PKG_PLAYGO_PFS_CHUNK_SIZE, playgo_chunk_hash);
					memcpy(entry_data, playgo_chunk_hash, PKG_PLAYGO_CHUNK_HASH_SIZE);
					entry_data += PKG_PLAYGO_CHUNK_HASH_SIZE;
				}
			}

			sha256_buffer(submap->data, s_pkg->pfs_signed_size, hdr.pfs_signed_digest);
			sha256_buffer(submap->data, s_pkg->pfs_image_size, hdr.pfs_image_digest);
		}

		memcpy(map->data, &hdr, sizeof(hdr));

error:
		if (submap)
			unmap_file(submap);

		if (map)
			unmap_file(map);

		return ret;
	}
#endif

static int parse_args(int argc, char* argv[]) {
	int option_index;
	size_t size;
	const char* part;
	const char* separator;
	size_t part_length;
	char* tmp_path;
	char* p;
	int c;
	int status = 1;

	static const char* short_options = "hi:l:u:r:";
	static struct option long_options[] = {
		{ "help", ARG_NONE, ARG_NULL, 'h' },

		{ "info", ARG_REQ, ARG_NULL, 'i' },
		{ "list", ARG_REQ, ARG_NULL, 'l' },
		{ "unpack", ARG_REQ, ARG_NULL, 'u' },
#if defined(ENABLE_REPACK_SUPPORT)
		{ "repack", ARG_REQ, ARG_NULL, 'r' },
#endif

		{ "key-content-id", ARG_REQ, &s_opt_key_content_id_flag, 1 },
#if defined(ENABLE_REPACK_SUPPORT)
		{ "content-id", ARG_NONE, &s_opt_content_id_flag, 1 },
#endif
		{ "passcode", ARG_REQ, &s_opt_passcode_flag, 1 },
#ifdef ENABLE_SD_KEYGEN
		{ "sealed-key-file", ARG_REQ, &s_opt_sealed_key_file_flag, 1 },
#endif
		{ "encdec-tweak-key", ARG_REQ, &s_opt_encdec_tweak_key_flag, 1 },
		{ "encdec-data-key", ARG_REQ, &s_opt_encdec_data_key_flag, 1 },
		{ "sign-key", ARG_REQ, &s_opt_sign_key_flag, 1 },
		{ "sc0-key", ARG_REQ, &s_opt_sc0_key_flag, 1 },
		{ "use-meta-data-file", ARG_REQ, &s_opt_use_meta_data_flag, 1 },
		{ "dump-meta-data-file", ARG_REQ, &s_opt_dump_meta_data_flag, 1 },
		{ "pfs-image-data-file", ARG_REQ, &s_opt_pfs_image_data_file_flag, 1 },
		{ "generate-gp4", ARG_REQ, &s_opt_gp4_file_flag, 1 },
		{ "unpack-outer-pfs", ARG_NONE, &s_opt_unpack_outer_pfs_flag, 1 },
		{ "unpack-inner-pfs", ARG_NONE, &s_opt_unpack_inner_pfs_flag, 1 },
		{ "unpack-sc-entries", ARG_NONE, &s_opt_unpack_sc_entries_flag, 1 },
		{ "unpack-extra-sc-entries", ARG_NONE, &s_opt_unpack_extra_sc_entries_flag, 1 },
		{ "use-splitted-files", ARG_NONE, &s_opt_use_splitted_files_flag, 1 },
		{ "no-unpack", ARG_NONE, &s_opt_no_unpack_flag, 1 },
		{ "no-signature-check", ARG_NONE, &s_opt_no_signature_check_flag, 1 },
		{ "no-icv-check", ARG_NONE, &s_opt_no_icv_check_flag, 1 },
#if defined(ENABLE_REPACK_SUPPORT)
		{ "no-hash-recalc", ARG_NONE, &s_opt_no_hash_recalc_flag, 1 },
		{ "no-elf-repack", ARG_NONE, &s_opt_no_elf_repack_flag, 1 },
#endif
		{ "dump-sfo", ARG_NONE, &s_opt_dump_sfo_flag, 1 },
		{ "dump-playgo", ARG_NONE, &s_opt_dump_playgo_flag, 1 },
		{ "dump-final-keys", ARG_NONE, &s_opt_dump_final_keys_flag, 1 },
#if defined(ENABLE_SD_KEYGEN)
		{ "dump-sd-info", ARG_NONE, &s_opt_dump_sd_info_flag, 1 },
#endif
		{ "use-random-passcode", ARG_NONE, &s_opt_use_random_passcode_flag, 1 },
		{ "all-compressed", ARG_NONE, &s_opt_all_compressed_flag, 1 },

		{ 0, 0, 0, 0 },
	};

	while ((c = option_index = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {
		switch (c) {
			case '?':
				status = 0;
				goto done;

			case 'h':
				show_version();
				show_usage(argv);
				goto done;

			case 'i':
				s_cmd_info = 1;
				if (s_input_file_path)
					free(s_input_file_path);
				s_input_file_path = strdup(optarg);
				goto get_args;

			case 'l':
				s_cmd_list = 1;
				if (s_input_file_path)
					free(s_input_file_path);
				s_input_file_path = strdup(optarg);
				goto done;

			case 'u':
				s_cmd_unpack = 1;
				if (s_input_file_path)
					free(s_input_file_path);
				s_input_file_path = strdup(optarg);
				goto get_args;

#if defined(ENABLE_REPACK_SUPPORT)
			case 'r':
				s_cmd_repack = 1;
				if (s_input_file_path)
					free(s_input_file_path);
				s_input_file_path = strdup(optarg);
				goto get_args;
#endif

			case 0:
				if (s_opt_key_content_id_flag) {
					s_key_content_id = strdup(optarg); s_opt_key_content_id_flag = 0;
#if 0
					if (!s_key_content_id) || strlen(s_key_content_id) != KEYMGR_CONTENT_ID_SIZE)
						error("Invalid key content ID specified.");
#else
					if (!s_key_content_id)
					error("Invalid key content ID specified.");
#endif
				}
#if defined(ENABLE_REPACK_SUPPORT)
				if (s_opt_content_id_flag) {
					s_content_id = strdup(optarg); s_opt_content_id_flag = 0;
					if (!s_content_id || strlen(s_content_id) != KEYMGR_CONTENT_ID_SIZE)
						error("Invalid content ID specified.");
				}
#endif
				if (s_opt_passcode_flag) {
					s_passcode = strdup(optarg); s_opt_passcode_flag = 0;
					if (!s_passcode || strlen(s_passcode) != KEYMGR_PASSCODE_SIZE)
						error("Invalid passcode specified.");
				}
#ifdef ENABLE_SD_KEYGEN
				if (s_opt_sealed_key_file_flag) {
					s_sealed_key_file = strdup(optarg); s_opt_sealed_key_file_flag = 0;
					if (!s_sealed_key_file || !is_file(s_sealed_key_file))
						error("Invalid sealed key file specified.");
				}
#endif
				if (s_opt_encdec_tweak_key_flag) {
					s_encdec_tweak_key = x_to_u8_buffer(optarg, &size); s_opt_encdec_tweak_key_flag = 0;
					if (!s_encdec_tweak_key || size != KEYMGR_AES_KEY_SIZE)
						error("Invalid enc/dec tweak key specified.");
				}
				if (s_opt_encdec_data_key_flag) {
					s_encdec_data_key = x_to_u8_buffer(optarg, &size); s_opt_encdec_data_key_flag = 0;
					if (!s_encdec_data_key || size != KEYMGR_AES_KEY_SIZE)
						error("Invalid enc/dec data key specified.");
				}
				if (s_opt_sign_key_flag) {
					s_sign_key = x_to_u8_buffer(optarg, &size); s_opt_sign_key_flag = 0;
					if (!s_sign_key || size != KEYMGR_HMAC_KEY_SIZE)
						error("Invalid signing key specified.");
				}
				if (s_opt_sc0_key_flag) {
					s_sc0_key = x_to_u8_buffer(optarg, &size); s_opt_sc0_key_flag = 0;
					if (!s_sc0_key || size != KEYMGR_SC0_KEY_SIZE)
						error("Invalid sc0 key specified.");
				}
				if (s_opt_use_meta_data_flag) {
					s_meta_data_in_file = strdup(optarg); s_opt_use_meta_data_flag = 0;
					if (!s_meta_data_in_file || ((is_exists(s_meta_data_in_file) && !is_readable(s_meta_data_in_file)) || is_directory(s_meta_data_in_file)))
						error("Invalid input meta data file specified.");
				}
				if (s_opt_dump_meta_data_flag) {
					s_meta_data_out_file = strdup(optarg); s_opt_dump_meta_data_flag = 0;
					if (!s_meta_data_out_file || ((is_exists(s_meta_data_out_file) && !is_writeable(s_meta_data_out_file)) || is_directory(s_meta_data_out_file)))
						error("Invalid output meta data file specified.");
				}
				if (s_opt_pfs_image_data_file_flag) {
					s_pfs_image_data_file = strdup(optarg); s_opt_pfs_image_data_file_flag = 0;
					if (!s_pfs_image_data_file || ((is_exists(s_pfs_image_data_file) && !is_readable(s_pfs_image_data_file)) || is_directory(s_pfs_image_data_file)))
						error("Invalid PFS image data file specified.");
				}
				if (s_opt_gp4_file_flag) {
					s_gp4_file = strdup(optarg); s_opt_gp4_file_flag = 0;
					if (!s_gp4_file || ((is_exists(s_gp4_file) && !is_writeable(s_gp4_file)) || is_directory(s_gp4_file)))
						error("Invalid GP4 file specified.");
				}
				if (s_opt_no_unpack_flag) {
					s_no_unpack = 1;
					s_opt_no_unpack_flag = 0;
				}
				if (s_opt_unpack_outer_pfs_flag) {
					s_unpack_outer_pfs = 1;
					s_opt_unpack_outer_pfs_flag = 0;
				}
				if (s_opt_unpack_inner_pfs_flag) {
					s_unpack_inner_pfs = 1;
					s_opt_unpack_inner_pfs_flag = 0;
				}
				if (s_opt_unpack_sc_entries_flag) {
					s_unpack_sc_entries = 1;
					s_opt_unpack_sc_entries_flag = 0;
				}
				if (s_opt_unpack_extra_sc_entries_flag) {
					s_unpack_extra_sc_entries = 1;
					s_opt_unpack_extra_sc_entries_flag = 0;
				}
				if (s_opt_use_splitted_files_flag) {
					s_use_splitted_files = 1;
					s_opt_use_splitted_files_flag = 0;
				}
				if (s_opt_no_signature_check_flag) {
					s_no_signature_check = 1;
					s_opt_no_signature_check_flag = 0;
				}
				if (s_opt_no_icv_check_flag) {
					s_no_icv_check = 1;
					s_opt_no_icv_check_flag = 0;
				}
#if defined(ENABLE_REPACK_SUPPORT)
				if (s_opt_no_hash_recalc_flag) {
					s_no_hash_recalc = 1;
					s_opt_no_hash_recalc_flag = 0;
				}
				if (s_opt_no_elf_repack_flag) {
					s_no_elf_repack = 1;
					s_opt_no_elf_repack_flag = 0;
				}
#endif
				if (s_opt_dump_sfo_flag) {
					s_dump_sfo = 1;
					s_opt_dump_sfo_flag = 0;
				}
				if (s_opt_dump_playgo_flag) {
					s_dump_playgo = 1;
					s_opt_dump_playgo_flag = 0;
				}
				if (s_opt_dump_final_keys_flag) {
					s_dump_final_keys = 1;
					s_opt_dump_final_keys_flag = 0;
				}
#if defined(ENABLE_SD_KEYGEN)
				if (s_opt_dump_sd_info_flag) {
					s_dump_sd_info = 1;
					s_opt_dump_sd_info_flag = 0;
				}
#endif
				if (s_opt_use_random_passcode_flag) {
					s_use_random_passcode = 1;
					s_opt_use_random_passcode_flag = 0;
				}
				if (s_opt_all_compressed_flag) {
					s_all_compressed = 1;
					s_opt_all_compressed_flag = 0;
				}
				break;

			default:
				abort();
		}
	}

get_args:;
	if (s_cmd_info) {
		if (s_unpack_sc_entries) {
			if (argc - optind < 1) {
				error("Info command needs output directory if you want to unpack SC entries!\n");
			} else {
				strncpy(s_output_directory, argv[optind++], sizeof(s_output_directory));
			}
		}
		goto done;
	}

	if (s_cmd_unpack) {
		if (argc - optind < 1) {
			error("Unpack command needs output directory!\n");
		} else {
			strncpy(s_output_directory, argv[optind++], sizeof(s_output_directory));
			if (optind < argc) {
				utarray_new(s_file_paths, &ut_str_icd);
				while (optind < argc) {
					p = argv[optind++];
					size = strlen(p);
					if (size > 0) {
						part = p;
						while (*part != '\0') {
							separator = path_get_separator(part);
							if (*separator != '\0')
								part_length = separator - p;
							else
								part_length = size;
							if (part_length > 0) {
								tmp_path = (char*)malloc(part_length + 1);
								if (!tmp_path)
									error("No memory.");
								strncpy(tmp_path, p, part_length);
								tmp_path[part_length] = '\0';
								utarray_push_back(s_file_paths, &tmp_path);
							}
							part = path_skip_separator(separator);
						}
					}
				}
			}
		}

		if ((s_meta_data_in_file || s_meta_data_out_file) && !s_gp4_file)
			error("Meta data file options are working in conjunction with GP4 project generation!");

		if (s_meta_data_in_file && !s_pfs_image_data_file)
			error("Input meta data file option needs to be used with pfs image data file option!");

		goto done;
	}

#if defined(ENABLE_REPACK_SUPPORT)
	if (s_cmd_repack) {
		if (s_no_elf_repack) {
			if (argc - optind < 1)
				error("Repack command needs output file path!\n");
			else
				s_output_file_path = strdup(argv[optind++]);
		} else {
			if (argc - optind < 1)
				error("Repack command needs output file path!\n");
			else if (argc - optind < 2)
				error("Repack command needs plaintext elf directory!\n");
			else {
				s_output_file_path = strdup(argv[optind++]);
				s_plaintext_elf_directory = strdup(argv[optind++]);
			}
		}

		goto done;
	}
#endif

done:
	return status;
}

int main(int argc, char* argv[]) {
	char program_directory[PATH_MAX];
	char config_file_path[PATH_MAX];
	int is_package_input_file, any_cmd;
	char* p;
	int ret = 0;

	if (argc < 2) {
		show_version();
		show_usage(argv);
		exit(1);
	}

	atexit(&cleanup);

	char *program_path = argv[0];
	#ifdef _WIN32
	_get_pgmptr(&program_path);
	#endif
	path_get_directory(program_directory, sizeof(program_directory), program_path);
	snprintf(config_file_path, sizeof(config_file_path), "%s%s%s", program_directory, (*program_directory != '\0') ? "/" : "", CONFIG_FILE);

	if (!crypto_initialize())
		error("Unable to initialize crypto.");

	if (!keymgr_initialize(config_file_path))
		error("Unable to initialize key manager.");

	if (!parse_args(argc, argv))
		exit(1);

	any_cmd = 0;
	any_cmd |= s_cmd_info;
	any_cmd |= s_cmd_list;
	any_cmd |= s_cmd_unpack;
#if defined(ENABLE_REPACK_SUPPORT)
	any_cmd |= s_cmd_repack;
#endif

	if (any_cmd) {
		if (s_use_splitted_files) {
			p = strrchr(s_input_file_path, '%');
			if (!p)
				error("Using splitted files but input file pattern doesn't contain %% symbol: %s", s_input_file_path);
		}

		if (!is_file(s_input_file_path) || !is_readable(s_input_file_path)) {
			if (s_use_splitted_files) {
				if (p) {
					is_package_input_file = 1;
					goto input_file_ok;
				}
			}
error_invalid_input_file:
			error("Invalid input file specified: %s", s_input_file_path);
		}

		is_package_input_file = file_has_magic(s_input_file_path, s_pkg_magic, sizeof(s_pkg_magic));

input_file_ok:
		if (s_cmd_unpack || (s_cmd_info && s_unpack_sc_entries)) {
			rtrim_slashes(s_output_directory);
			if (is_exists(s_output_directory)) {
				if (!is_directory(s_output_directory) || !is_writeable(s_output_directory))
					error("Invalid output directory specified: %s", s_output_directory);
			} else {
				if (!make_directories(s_output_directory, 0755))
					error("Unable to create output directory: %s", s_output_directory);
			}
		}

#if defined(ENABLE_REPACK_SUPPORT)
		if (s_cmd_repack) {
			if (!s_no_elf_repack) {
				if (is_package_input_file) {
					if (!is_directory(s_plaintext_elf_directory))
						error("Invalid plaintext elf directory specified: %s", s_plaintext_elf_directory);
				}
			}
			if ((is_exists(s_output_file_path) && !is_writeable(s_output_file_path)) || is_directory(s_output_file_path))
				error("Invalid output file specified: %s", s_output_file_path);
		}
#endif

		if (is_package_input_file) {
			if (s_cmd_info)
				ret = process_pkg(&pkg_info_handler) != 0;
			else if (s_cmd_list)
				ret = process_pkg(&pkg_list_handler) != 0;
			else if (s_cmd_unpack)
				ret = process_pkg(&pkg_unpack_handler) != 0;
#if defined(ENABLE_REPACK_SUPPORT)
			else if (s_cmd_repack)
				ret = process_pkg(&pkg_repack_handler) == 0;
#endif
		} else {
			if (s_cmd_list)
				ret = process_pfs(&pfs_list_handler) != 0;
			else if (s_cmd_unpack)
				ret = process_pfs(&pfs_unpack_handler) != 0;
#if defined(ENABLE_REPACK_SUPPORT)
			else if (s_cmd_repack)
				ret = process_pfs(&pfs_repack_handler) != 0;
#endif
		}
	} else {
		exit(0);
	}

	return ret;
}

static void show_version(void) {
	printf("PS4 PKG/PFS Tool " PKG_PFS_TOOL_VERSION " (c) 2017-2021 by flatz\n");
	printf("--------------------------------------------\n");
}

static void show_usage(char* argv[]) {
	char exe_name[PATH_MAX];
	path_get_file_name(exe_name, sizeof(exe_name), argv[0]);

	printf("USAGE: %s [options] command\n", exe_name);
	printf("\n");
	printf("COMMANDS                 PARAMETERS                    DESCRIPTION\n");
	printf("------------------------------------------------------------------------------\n");
	printf("  -h, --help                                            Print this help\n");
	printf("  -i, --info <img file>                                 Show information about image\n");
	printf("  -l, --list <img file>                                 List of entries\n");
	printf("  -u, --unpack <img file> <out dir> [file1 file2...]    Unpack files from image\n");
#if defined(ENABLE_REPACK_SUPPORT)
	printf("  -r, --repack <src img file> <dst img file> [elfs dir] Repack image file (with plaintext elfs)\n");
#endif
	printf("\n");

	printf("OPTIONS                  PARAMETERS                     DESCRIPTION\n");
	printf("------------------------------------------------------------------------------\n");
	printf("  --key-content-id <content id>                         Use keyset of specific content ID\n");
#if defined(ENABLE_REPACK_SUPPORT)
	printf("  --content-id <content id>                             Replace content ID on repacking\n");
#endif
	printf("  --passcode <passcode>                                 Use specific passcode\n");
#ifdef ENABLE_SD_KEYGEN
	printf("  --sealed-key-file <sealed key file>                   Use sealed key file for keys generation\n");
#endif
	printf("  --encdec-tweak-key <key>                              Use specific AES XTS tweak key for enc/dec\n");
	printf("  --encdec-data-key <key>                               Use specific AES XTS data key for enc/dec\n");
	printf("  --sign-key <key>                                      Use specific HMAC SHA256 key for signing\n");
	printf("  --sc0-key <key>                                       Use specific Sc0 key for enc/dec\n");
	printf("  --use-meta-data-file <meta data file>                 Load GP4 meta data from file\n");
	printf("  --dump-meta-data-file <meta data file>                Save GP4 meta data to file\n");
	printf("  --pfs-image-data-file <pfs_image.dat file>            Use plain pfs_image.dat as PFS content of PKG file\n");
	printf("  --generate-gp4 <gp4 file>                             Generate GP4 project from PKG file\n");
	printf("  --unpack-inner-pfs                                    Unpack inner PFS file from PKG file\n");
	printf("  --unpack-outer-pfs                                    Unpack outer PFS file from PKG file\n");
	printf("  --unpack-sc-entries                                   Unpack SC entries from PKG file\n");
	printf("  --unpack-extra-sc-entries                             Unpack extra SC entries from PKG file\n");
	printf("  --use-splitted-files                                  Use splitted PKG chunks\n");
	printf("  --no-unpack                                           Don't unpack main PFS files from PKG file\n");
	printf("  --no-signature-check                                  Skip signature checking\n");
	printf("  --no-icv-check                                        Skip ICV hash checking\n");
#if defined(ENABLE_REPACK_SUPPORT)
	printf("  --no-hash-recalc                                      Skip recalculation of hashes on repacking\n");
	printf("  --no-elf-repack                                       Skip ELFs repacking\n");
#endif
	printf("  --dump-sfo                                            Dump SFO structure from PKG file\n");
	printf("  --dump-playgo                                         Dump Playgo structure from PKG file\n");
#if defined(ENABLE_EKC_KEYGEN)
	printf("  --dump-final-keys                                     Dump final keys to use with the tool\n");
#endif
#if defined(ENABLE_SD_KEYGEN)
	printf("  --dump-sd-info                                        Dump SD info\n");
#endif
	printf("  --use-random-passcode                                 Use random passcode for GP4 project\n");
	printf("  --all-compressed                                      Use compression for all files in GP4 project\n");
	printf("\n");
}

static void cleanup(void) {
	if (s_pkg)
		pkg_free(s_pkg);
	if (s_pfs)
		pfs_free(s_pfs);

	if (s_key_content_id)
		free(s_key_content_id);
#if defined(ENABLE_REPACK_SUPPORT)
	if (s_content_id)
		free(s_content_id);
#endif
	if (s_passcode)
		free(s_passcode);
#ifdef ENABLE_SD_KEYGEN
	if (s_sealed_key_file)
		free(s_sealed_key_file);
#endif
	if (s_encdec_tweak_key)
		free(s_encdec_tweak_key);
	if (s_encdec_data_key)
		free(s_encdec_data_key);
	if (s_sign_key)
		free(s_sign_key);
	if (s_sc0_key)
		free(s_sc0_key);
	if (s_meta_data_in_file)
		free(s_meta_data_in_file);
	if (s_meta_data_out_file)
		free(s_meta_data_out_file);
	if (s_pfs_image_data_file)
		free(s_pfs_image_data_file);
	if (s_gp4_file)
		free(s_gp4_file);
	if (s_file_paths)
		utarray_free(s_file_paths);

	if (s_input_file_path)
		free(s_input_file_path);
#if defined(ENABLE_REPACK_SUPPORT)
	if (s_plaintext_elf_directory)
		free(s_plaintext_elf_directory);
#endif
	if (s_output_file_path)
		free(s_output_file_path);

	keymgr_finalize();
	crypto_finalize();
}

static int pfs_get_size_cb(void* arg, uint64_t* size) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);

	if (size)
		*size = ctx->map->size;

	return 1;
}

static int pfs_get_outer_location_cb(void* arg, uint64_t offset, uint64_t* outer_offset) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);

	if (offset > ctx->map->size)
		return 0;

	if (outer_offset)
		*outer_offset = offset;

	return 1;
}

static int pfs_get_offset_size_cb(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);

	if (ctx->offset + data_size > ctx->map->size)
		return 0;

	if (real_offset)
		*real_offset = ctx->offset;

	if (size_to_read)
		*size_to_read = data_size;

	if (compressed)
		*compressed = 0;

	return 1;
}

static int pfs_seek_cb(void* arg, uint64_t offset) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);

	if (offset > ctx->map->size)
		return 0;

	ctx->offset = offset;

	return 1;
}

static int pfs_read_cb(void* arg, void* data, uint64_t data_size) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);
	assert(data != NULL);

	if (ctx->offset + data_size > ctx->map->size)
		return 0;

	memcpy(data, ctx->map->data + ctx->offset, data_size);

	return 1;
}

static int pfs_write_cb(void* arg, void* data, uint64_t data_size) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);
	assert(data != NULL);

	if (ctx->offset + data_size > ctx->map->size)
		return 0;

	memcpy(ctx->map->data + ctx->offset, data, data_size);

	return 1;
}

static int pfs_can_seek_cb(void* arg, uint64_t offset) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);

	if (offset > ctx->map->size)
		return 0;

	return 1;
}

static int pfs_can_read_cb(void* arg, uint64_t data_size) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);

	if (ctx->offset + data_size > ctx->map->size)
		return 0;

	return 1;
}

static int pfs_can_write_cb(void* arg, uint64_t data_size) {
	struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

	assert(ctx != NULL);

	if (ctx->offset + data_size > ctx->map->size)
		return 0;

	return 1;
}
