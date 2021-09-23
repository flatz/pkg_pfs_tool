#include "pfs.h"
#include "crypto.h"
#include "keymgr.h"
#include "keys.h"
#include "util.h"

#define CHUNK_SIZE 16384

#ifndef _DEBUG
//#	define DONT_UNPACK_IF_EXISTS
#endif

struct pfs_unpack_cb_args {
	pfs_unpack_pre_cb pre_cb;
	void* pre_cb_arg;
	char output_directory[PATH_MAX];
	char parent_directory[PATH_MAX];
};

struct pfs_read_chunk_cb_args {
	struct pfs* pfs;
	uint64_t offset;
	uint64_t size;
	int start;
};

int pfs_signature_check_read_chunk(void* arg, uint8_t* chunk, size_t chunk_size, size_t* n) {
	struct pfs_read_chunk_cb_args* args = (struct pfs_read_chunk_cb_args*)arg;
	uint64_t size_left;
	int status = 0;

	assert(arg != NULL);
	assert(chunk != NULL);
	assert(n != NULL);

	if (args->start) {
		if (!pfs_io_can_seek(args->pfs, 0))
			goto error;
		args->start = 0;
	}

	size_left = args->size - args->offset;
	if (size_left > 0) {
		if (size_left < chunk_size)
			chunk_size = (size_t)size_left;
		if (!pfs_io_can_read(args->pfs, chunk_size))
			goto error;
		if (!pfs_io_read(args->pfs, chunk, chunk_size))
			goto error;
		args->offset += chunk_size;
	} else {
		chunk_size = 0;
	}
	*n = chunk_size;

	status = 1;

error:
	return status;
}

struct pfs* pfs_alloc(struct pfs_io_callbacks* io, const struct pfs_options* opts, int is_inner) {
	struct pfs* pfs = NULL;
	uint8_t* header_data = NULL;
	size_t basic_block_size;
	uint8_t hash[PFS_HASH_SIZE];
	int64_t indirect_ptr_count;
	const char* content_id = NULL;
	char enc_tweak_key_str[KEYMGR_AES_KEY_SIZE * 2 + 1];
	char enc_data_key_str[KEYMGR_AES_KEY_SIZE * 2 + 1];
	char sign_hmac_key_str[KEYMGR_HMAC_KEY_SIZE * 2 + 1];
	char sc0_key_str[KEYMGR_SC0_KEY_SIZE * 2 + 1];
#if defined(ENABLE_SD_KEYGEN)
	char open_psid_digest_str[KEYMGR_AES_KEY_SIZE * 2 + 1];
	char partial_idps_str[sizeof(pfs->hdr.info_data.partial_idps) * 2 + 1];
	char hash_str[PFS_HASH_SIZE * 2 + 1];
	uint8_t sd_content_key[KEYMGR_CONTENT_KEY_SIZE];
	struct sd_auth_code_info sd_auth_code_info;
	unsigned int sd_key_ver;
#endif
	uint8_t image_key[KEYMGR_HASH_SIZE];
	char image_key_str[KEYMGR_HASH_SIZE * 2 + 1];
	int has_auth_code;
	size_t i;
	int status = 0;

	assert(io != NULL);
	assert(io->get_size != NULL);
	assert(io->get_outer_location != NULL);
	assert(io->get_offset_size != NULL);
	assert(io->seek != NULL);
	assert(io->read != NULL);
	assert(io->write != NULL);
	assert(io->can_seek != NULL);
	assert(io->can_read != NULL);
	assert(io->can_write != NULL);

	pfs = (struct pfs*)malloc(sizeof(*pfs));
	if (!pfs)
		goto error;
	memset(pfs, 0, sizeof(*pfs));

	pfs->io = io;
	pfs->is_inner = is_inner;

	if (opts) {
		pfs->opts = pfs_clone_options(opts);
		if (!pfs->opts)
			goto error;
	}

	if (!pfs_io_seek(pfs, 0)) {
		warning("Unable to seek to PFS header.");
		goto error;
	}
	if (!pfs_io_read(pfs, &pfs->hdr, sizeof(pfs->hdr))) {
		warning("Unable to read PFS header.");
		goto error;
	}

	if (LE32(pfs->hdr.magic) < PFS_FS_MAGIC) {
		warning("Old PFS format is not supported.");
		goto error;
	}

	pfs->is_signed = (LE16(pfs->hdr.mode) & PFS_MODE_SIGNED_FLAG) != 0;
	pfs->is_encrypted = (LE16(pfs->hdr.mode) & PFS_MODE_ENCRYPTED_FLAG) != 0;

	if (pfs->opts) {
		if (pfs->opts->case_sensitive)
			pfs->flags |= PFS_FLAGS_CASE_SENSITIVE;
		content_id = pfs->opts->content_id;
	} else if ((LE16(pfs->hdr.mode) & PFS_MODE_CASE_INSENSITIVE_FLAG) == 0) {
		pfs->flags |= PFS_FLAGS_CASE_SENSITIVE;
	}

	if (pfs->is_encrypted || pfs->is_signed) {
		if (!pfs->opts) {
			warning("No options specified to use with encrypted/signed file.");
			goto error;
		} else if (!pfs->opts->keyset) {
			if (pfs->opts->skip_keygen)
				goto proceed_anyway;
			warning("No title keyset found for encrypted/signed file.");
			goto error;
		}

#if defined(ENABLE_SD_KEYGEN)
		if (pfs->opts->is_sd) {
			if (!pfs_get_sd_content_key(pfs, sd_content_key)) {
				warning("Unable to get content key.");
				goto error;
			}
			status = keymgr_generate_keys_for_sd(pfs->opts->keyset, sd_content_key, pfs->hdr.crypt_seed);
		}
#endif

#if defined(ENABLE_SD_KEYGEN)
		if (!pfs->opts->is_sd) {
#endif
			status = keymgr_generate_keys_for_title_keyset(pfs->opts->keyset, content_id, pfs->hdr.crypt_seed, 0, image_key);
			if (!status) {
gen_keys_failed:
				warning("Unable to generate encryption/signing keys to use with encrypted/signed file.");
				goto error;
			}
#if defined(ENABLE_SD_KEYGEN)
		}
#endif

		if (pfs->is_signed) {
			header_data = (uint8_t*)malloc(PFS_HEADER_SIZE);
			if (!header_data)
				goto error;
			memset(header_data, 0, PFS_HEADER_SIZE);
			memcpy(header_data, &pfs->hdr, PFS_HEADER_COVER_SIZE_FOR_ICV);

			pfs_sign_buffer(pfs, header_data, PFS_HEADER_SIZE, hash);
			if (memcmp(hash, pfs->hdr.header_hash, sizeof(hash)) != 0) {
#if defined(ENABLE_SD_KEYGEN)
				if (!pfs->opts->is_sd) {
#endif
					status = keymgr_generate_keys_for_title_keyset(pfs->opts->keyset, content_id, pfs->hdr.crypt_seed, 1, image_key);
					if (!status) {
						goto gen_keys_failed;
					}
					pfs_sign_buffer(pfs, header_data, PFS_HEADER_SIZE, hash);
					if (memcmp(hash, pfs->hdr.header_hash, sizeof(hash)) != 0) {
invalid_header_hash:
						warning("Invalid header hash.");
						goto error;
					}
#if defined(ENABLE_SD_KEYGEN)
				} else {
					goto invalid_header_hash;
				}
#endif
			}

			free(header_data);
			header_data = NULL;
		}

		if (pfs->opts->dump_final_keys) {
			snprintf_hex(enc_tweak_key_str, sizeof(enc_tweak_key_str), pfs->opts->keyset->enc_tweak_key, sizeof(pfs->opts->keyset->enc_tweak_key));
			snprintf_hex(enc_data_key_str, sizeof(enc_data_key_str), pfs->opts->keyset->enc_data_key, sizeof(pfs->opts->keyset->enc_data_key));
			snprintf_hex(sign_hmac_key_str, sizeof(sign_hmac_key_str), pfs->opts->keyset->sig_hmac_key, sizeof(pfs->opts->keyset->sig_hmac_key));
			snprintf_hex(sc0_key_str, sizeof(sc0_key_str), pfs->opts->keyset->sc0_key, sizeof(pfs->opts->keyset->sc0_key));
			snprintf_hex(image_key_str, sizeof(image_key_str), image_key, sizeof(image_key));
			info("Config params:\n[%s]\nenc_tweak_key=%s\nenc_data_key=%s\nsig_hmac_key=%s\nimage_key=%s\nsc0_key=%s\n", content_id, enc_tweak_key_str, enc_data_key_str, sign_hmac_key_str, image_key_str, sc0_key_str);
		}
	}

proceed_anyway:
	for (basic_block_size = PFS_MIN_BLOCK_SIZE; basic_block_size <= PFS_MAX_BLOCK_SIZE; basic_block_size *= 2) {
		if (basic_block_size == LE32(pfs->hdr.basic_block_size))
			break;
	}
	if (basic_block_size > PFS_MAX_BLOCK_SIZE) {
		warning("Unsupported basic block size.");
		goto error;
	}

	pfs->basic_block_size = LE32(pfs->hdr.basic_block_size);
	pfs->basic_block_mask = ~(pfs->basic_block_size - 1);
	pfs->basic_block_qmask = ~pfs->basic_block_mask;
	pfs->basic_block_size_shift = ilog2_64(pfs->basic_block_size);

	pfs->dev_block_size = PFS_DEVICE_BLOCK_SIZE;
	pfs->dev_block_mask = ~(pfs->dev_block_size - 1);
	pfs->dev_block_qmask = ~pfs->dev_block_mask;
	pfs->dev_block_size_shift = ilog2_64(pfs->dev_block_size);

	pfs->encdec_sector_size = PFS_ENCDEC_SECTOR_SIZE;
	pfs->encdec_sector_mask = ~(pfs->encdec_sector_size - 1);
	pfs->encdec_sector_qmask = ~pfs->encdec_sector_mask;
	pfs->encdec_sector_size_shift = ilog2_64(pfs->encdec_sector_size);

	pfs->format = (enum pfs_format)(LE16(pfs->hdr.mode) & PFS_MODE_FORMAT_MASK);
	switch (pfs->format) {
		case PFS_FORMAT_32:
			pfs->dinode_struct_size = PFS_DINODE_TOP_STRUCT_SIZE + PFS_DINODE32_STRUCT_SIZE;
			pfs->block_info_struct_size = sizeof(struct pfs_block32);
			break;
		case PFS_FORMAT_64:
			pfs->dinode_struct_size = PFS_DINODE_TOP_STRUCT_SIZE + PFS_DINODE64_STRUCT_SIZE;
			pfs->block_info_struct_size = sizeof(struct pfs_block64);
			break;
		case PFS_FORMAT_32_SIGNED:
			pfs->dinode_struct_size = PFS_DINODE_TOP_STRUCT_SIZE + PFS_SDINODE32_STRUCT_SIZE;
			pfs->block_info_struct_size = sizeof(struct pfs_sblock32);
			break;
		case PFS_FORMAT_64_SIGNED:
			pfs->dinode_struct_size = PFS_DINODE_TOP_STRUCT_SIZE + PFS_SDINODE64_STRUCT_SIZE;
			pfs->block_info_struct_size = sizeof(struct pfs_sblock64);
			break;
		default:
			warning("Unsupported format.");
			goto error;
	}

	pfs->indirect_ptrs_per_block = pfs->basic_block_size / pfs->block_info_struct_size;
	pfs->inodes_per_block = pfs->basic_block_size / pfs->dinode_struct_size;

	pfs->max_direct_block_count = PFS_DIRECT_BLOCK_MAX_COUNT;
	indirect_ptr_count = pfs->indirect_ptrs_per_block;
	for (i = 0; i < COUNT_OF(pfs->indirect_ptrs_per_block_for_level); ++i) {
		pfs->indirect_ptrs_per_block_for_level[i] = indirect_ptr_count;
		indirect_ptr_count *= pfs->indirect_ptrs_per_block;
	}

	if (pfs->is_signed) {
#if defined(ENABLE_SD_KEYGEN)
		if (pfs->opts && !pfs->opts->is_sd && !pfs->opts->skip_signature_check) {
#else
		if (pfs->opts && !pfs->opts->skip_signature_check) {
#endif
			if (check_rsa_key_filled(&g_rsa_keyset_pfs_sig_key, 0)) {
				if (!rsa_pkcsv15_verify(&g_rsa_keyset_pfs_sig_key, &pfs->hdr, PFS_SUPERBLOCK_SIGNATURE_COVER_SIZE, pfs->hdr.super_block_signature, sizeof(pfs->hdr.super_block_signature))) {
					warning("Package super block signature verification failed.");
					goto error;
				}
			}
		}
	}

#if defined(ENABLE_SD_KEYGEN)
	if (pfs->opts && pfs->opts->is_sd) {
		if (!pfs_get_sd_key_ver(pfs, &sd_key_ver)) {
			warning("SD key revision not found.");
			goto error;
		}
		if (pfs->opts && !pfs->opts->skip_block_hash_check && sd_key_ver > 2) {
			if (!g_sd_hdr_sig_key) {
				warning("SD header signature key not found.");
				goto error;
			}
			hmac_sha256_buffer(g_sd_hdr_sig_key, KEYMGR_SD_HEADER_SIG_KEY_SIZE, &pfs->hdr, PFS_SD_HEADER_SIZE, hash);
			if (memcmp(hash, pfs->hdr.bottom_signature, sizeof(hash)) != 0) {
				warning("Invalid SD header signature.");
				goto error;
			}
		}

		memset(&sd_auth_code_info, 0, sizeof(sd_auth_code_info));
		if (!pfs_parse_sd_auth_code(pfs, &sd_auth_code_info, &has_auth_code)) {
			warning("Unable to parse SD auth code.");
		} else if (has_auth_code) {
			if (!g_sd_hdr_data_key) {
				warning("SD header data key not found.");
				goto error;
			}
			aes_decrypt_cbc_cts(g_sd_hdr_data_key, KEYMGR_SD_HEADER_DATA_KEY_SIZE, NULL, &pfs->hdr.info_data, &pfs->hdr.info_data, sizeof(pfs->hdr.info_data));

#if 1
			printf("SD auth code info dump:\n");
			fprintf_hex(stdout, &sd_auth_code_info, sizeof(sd_auth_code_info), 2);
#endif

#if 1
			printf("PFS header info dump:\n");
			fprintf_hex(stdout, &pfs->hdr.info_data, sizeof(pfs->hdr.info_data), 2);
#endif

			if (pfs->opts && !pfs->opts->skip_block_hash_check && memcmp(sd_auth_code_info.pfs_hdr_hash1, pfs->hdr.header_hash, sizeof(pfs->hdr.header_hash)) != 0)
				warning("Invalid PFS header hash in SD auth code.");

			if (pfs->opts->dump_sd_info) {
				snprintf_hex(open_psid_digest_str, sizeof(open_psid_digest_str), pfs->hdr.info_data.open_psid_digest, sizeof(pfs->hdr.info_data.open_psid_digest));
				info("Open PSID digest: %s", open_psid_digest_str);

				snprintf_hex(partial_idps_str, sizeof(partial_idps_str), pfs->hdr.info_data.partial_idps, sizeof(pfs->hdr.info_data.partial_idps));
				info("Partial IDPS: %s", partial_idps_str);

				info("Game paid: 0x%016" PRIX64, LE64(pfs->hdr.info_data.game_paid));
				info("ShellUI paid: 0x%016" PRIX64, LE64(pfs->hdr.info_data.shellui_paid));

				snprintf_hex(hash_str, sizeof(hash_str), sd_auth_code_info.pfs_hdr_hash1, sizeof(sd_auth_code_info.pfs_hdr_hash1));
				info("PFS header hash #1: %s", hash_str);

				snprintf_hex(hash_str, sizeof(hash_str), sd_auth_code_info.pfs_hdr_hash2, sizeof(sd_auth_code_info.pfs_hdr_hash2));
				info("PFS header hash #2: %s", hash_str);

				info("Copy counter: %" PRIu64, LE64(sd_auth_code_info.copy_ctr));

				info("");
			}

			if (pfs->opts && !pfs->opts->skip_block_hash_check) {
				if (!g_open_psid) {
					warning("Open PSID not found.");
					goto error;
				}
				if (!g_open_psid_sig_key) {
					warning("Open PSID signature key not found.");
					goto error;
				}
				aes_cmac(g_open_psid_sig_key, KEYMGR_OPEN_PSID_SIG_KEY_SIZE, g_open_psid, KEYMGR_OPEN_PSID_SIZE, hash);
				if (memcmp(hash, pfs->hdr.info_data.open_psid_digest, sizeof(pfs->hdr.info_data.open_psid_digest)) != 0) {
					warning("Invalid Open PSID digest.");
					//goto error;
				}
			}

			if (LE64(pfs->hdr.info_data.shellui_paid) != 0 &&
			    LE64(pfs->hdr.info_data.shellui_paid) != SD_SHELLCORE_PAID &&
			    LE64(pfs->hdr.info_data.shellui_paid) != SD_SHELLUI_PAID &&
			    LE64(pfs->hdr.info_data.shellui_paid) != SD_NPXS21003_PAID &&
			    LE64(pfs->hdr.info_data.shellui_paid) != SD_SECURE_UI_PROCESS_PAID) {
				warning("Unexpected PAID: 0x%016" PRIX64, LE64(pfs->hdr.info_data.shellui_paid));
			}
		}
	}
#endif

	if (pfs->is_encrypted) {
		pfs->encdec = encdec_device_alloc(pfs->opts->keyset->enc_tweak_key, sizeof(pfs->opts->keyset->enc_tweak_key), pfs->opts->keyset->enc_data_key, sizeof(pfs->opts->keyset->enc_data_key), pfs->encdec_sector_size);
		if (!pfs->encdec)
			goto error;
	}

	//
	// super root directory
	//

	pfs->super_root_dir_ino = (pfs_ino)LE64(pfs->hdr.super_root_dir_ino);
	if (!pfs_parse_super_root_directory(pfs)) {
		warning("Unable to parse super root directory.");
		goto error;
	}

	return pfs;

error:
	if (pfs) {
		if (pfs->encdec)
			encdec_device_free(pfs->encdec);

		if (header_data)
			free(header_data);

		if (pfs->opts)
			free(pfs->opts);

		free(pfs);
	}

	return NULL;
}

void pfs_free(struct pfs* pfs) {
	if (!pfs)
		return;

	if (pfs->encdec)
		encdec_device_free(pfs->encdec);

	pfs_free_options(pfs->opts);

	free(pfs);
}

int pfs_dump_indirect_blocks(struct pfs* pfs, pfs_ino ino, pfs_dump_indirect_block_cb dump_cb, void* dump_cb_arg) {
	struct pfs_dinode dinode;
	struct pfs_block_list* block_list = NULL;
	int status = 0;

	assert(pfs != NULL);

	if (!pfs_get_dinode(pfs, ino, &dinode, NULL, NULL)) {
		warning("Unable to find dinode with ino: %" PRIuMAX, (uintmax_t)ino);
		goto error;
	}

	block_list = pfs_get_block_list(pfs, &dinode, dump_cb, dump_cb_arg);
	if (!block_list) {
		warning("Unable to find block list for dinode with ino: %" PRIuMAX, (uintmax_t)ino);
		goto error;
	}

	status = 1;

error:
	if (block_list)
		pfs_free_block_list(pfs, block_list);

	return status;
}

struct pfs_file_context* pfs_get_file_ex(struct pfs* pfs, pfs_ino ino, pfs_dump_indirect_block_cb dump_cb, void* dump_cb_arg) {
	struct pfs_file_context* file = NULL;
	struct pfsc_header* pfsc_hdr;
	uint32_t mode;

	assert(pfs != NULL);

	file = (struct pfs_file_context*)malloc(sizeof(*file));
	if (!file)
		goto error;
	memset(file, 0, sizeof(*file));

	file->pfs = pfs;
	file->ino = ino;

	if (!pfs_get_dinode(pfs, ino, &file->dinode, &file->dinode_block_no, &file->dinode_offset)) {
		warning("Unable to find dinode with ino: %" PRIuMAX, (uintmax_t)ino);
		goto error;
	}

	file->block_list = pfs_get_block_list(pfs, &file->dinode, dump_cb, dump_cb_arg);
	if (!file->block_list) {
		warning("Unable to find block list for dinode with ino: %" PRIuMAX, (uintmax_t)ino);
		goto error;
	}

	file->tmp_block = (uint8_t*)malloc(pfs->basic_block_size * 2);
	if (!file->tmp_block) {
		warning("Unable to allocate memory for temporary block.");
		goto error;
	}
	memset(file->tmp_block, 0, pfs->basic_block_size * 2);

	mode = LE32(file->dinode.mode);

	file->type = (enum pfs_file_type)(mode & PFS_FILE_TYPE_MASK);
	file->perms = (enum pfs_file_perms)(mode & PFS_FILE_PERMS_MASK);
	file->flags = LE32(file->dinode.flags);

	if (file->flags & PFS_FILE_COMPRESSED) {
		file->file_size = LE64(file->dinode.size_uncompressed);

		if (file->block_list->count == 0)
			goto error;

		if (!pfs_read_blocks(pfs, file->block_list->blocks[0], file->tmp_block, 1))
			goto error;

		pfsc_hdr = (struct pfsc_header*)file->tmp_block;
		if (LE32(pfsc_hdr->magic) != PFSC_MAGIC) {
			warning("Not PFSC format.");
			goto error;
		}

		file->cmp.rounded_file_size = LE64(pfsc_hdr->rounded_file_size);
		file->cmp.block_table_offset = LE64(pfsc_hdr->block_table_offset);
		file->cmp.block_data_offset = LE64(pfsc_hdr->block_data_offset);
		file->cmp.block_size = LE32(pfsc_hdr->block_size);
		file->cmp.alignment = LE32(pfsc_hdr->alignment);

		file->cmp.block_size_shift = ilog2_64(file->cmp.block_size);
		file->cmp.block_size_mask = ~(file->cmp.block_size - 1);
		file->cmp.block_size_qmask = ~file->cmp.block_size_mask;
		file->cmp.block_count = file->cmp.rounded_file_size / file->cmp.block_size + 1;

		if (file->cmp.block_count > 0) {
			file->cmp.block_offsets = (uint64_t*)malloc(file->cmp.block_count * sizeof(*file->cmp.block_offsets));
			if (!file->cmp.block_offsets)
				goto error;
		}

		if (!pfs_file_read_raw(file, file->cmp.block_table_offset, file->cmp.block_offsets, file->cmp.block_count * sizeof(*file->cmp.block_offsets)))
			goto error;

		file->cmp.work_data = (uint8_t*)malloc(PFSC_WORK_DATA_SIZE);
		if (!file->cmp.work_data)
			goto error;
		memset(file->cmp.work_data, 0, PFSC_WORK_DATA_SIZE);

		file->cmp.loaded = 1;
	} else {
		file->file_size = LE64(file->dinode.size);
		if (pfs->is_inner) {
			if (file->file_size != LE64(file->dinode.size_uncompressed)) {
				warning("Unexpected size for uncompressed file (expected: 0x%" PRIX64 ", got: 0x%" PRIX64 ").", LE64(file->dinode.size_uncompressed), file->file_size);
				goto error;
			}
		}
	}

	return file;

error:
	if (file) {
		if (file->cmp.loaded) {
			if (file->cmp.work_data)
				free(file->cmp.work_data);

			if (file->cmp.block_offsets)
				free(file->cmp.block_offsets);
		}

		if (file->block_list)
			pfs_free_block_list(pfs, file->block_list);

		free(file);
	}

	return NULL;
}

struct pfs_file_context* pfs_get_file(struct pfs* pfs, pfs_ino ino) {
	assert(pfs != NULL);

	return pfs_get_file_ex(pfs, ino, NULL, NULL);
}

void pfs_free_file(struct pfs_file_context* file) {
	if (!file)
		return;

	assert(file->pfs != NULL);

	if (file->cmp.loaded) {
		if (file->cmp.work_data)
			free(file->cmp.work_data);

		if (file->cmp.block_offsets)
			free(file->cmp.block_offsets);
	}

	if (file->block_list)
		pfs_free_block_list(file->pfs, file->block_list);

	if (file->tmp_block)
		free(file->tmp_block);

	free(file);
}

int pfs_unpack_single(struct pfs* pfs, const char* path, const char* output_directory, pfs_unpack_pre_cb pre_cb, void* pre_cb_arg) {
	struct pfs_file_context* file = NULL;
	char file_path[PATH_MAX];
	char directory[PATH_MAX];
	uint8_t chunk[CHUNK_SIZE];
	const size_t chunk_size = sizeof(chunk);
	pfs_ino ino;
	uint64_t offset;
	uint64_t size_left;
	size_t cur_size;
	enum pfs_entry_type entry_type;
#ifdef DONT_UNPACK_IF_EXISTS
	size_t existing_file_size;
#endif
	int fd = -1;
	int needed;
	enum cb_result ret;
	int status = 0;

	assert(pfs != NULL);
	assert(path != NULL);
	assert(output_directory != NULL);

	if (!pfs_lookup_path_user(pfs, path, &ino))
		goto error;

	file = pfs_get_file(pfs, ino);
	if (!file)
		goto error;

	if (file->type == PFS_FILE_TYPE_DIR)
		entry_type = PFS_ENTRY_DIRECTORY;
	else
		entry_type = PFS_ENTRY_FILE;

	snprintf(file_path, sizeof(file_path), "%s%s%s", output_directory, path, file->type == PFS_FILE_TYPE_DIR ? "/" : "");
	path_get_directory(directory, sizeof(directory), file_path);

	if (pre_cb) {
		ret = (*pre_cb)(pre_cb_arg, path, entry_type, &needed);
		if (ret == CB_RESULT_STOP)
			goto done;
		else if (ret == CB_RESULT_CONTINUE && !needed)
			goto done;
	}

	if (*directory != '\0')
		make_directories(directory, 0755);

	if (entry_type == PFS_ENTRY_DIRECTORY)
		goto done;

#ifdef DONT_UNPACK_IF_EXISTS
	existing_file_size = get_file_size(file_path);
	if (existing_file_size != (uint64_t)-1 && existing_file_size == file->file_size && 0)
		goto done;
#endif

	fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE | O_BINARY, 0644);
	if (fd < 0)
		goto error;

	memset(chunk, 0, sizeof(chunk));

	offset = 0;
	size_left = file->file_size;
	while (size_left != 0) {
		cur_size = (size_left > chunk_size) ? chunk_size : (size_t)size_left;

		if (!pfs_file_read(file, offset, chunk, cur_size))
			goto error;

		if (write(fd, chunk, cur_size) != (ssize_t)cur_size)
			goto error;

		offset += cur_size;
		size_left -= cur_size;
	}

done:
	status = 1;

error:
	if (fd > 0)
		close(fd);

	if (file)
		pfs_free_file(file);

	return status;
}

static enum cb_result pfs_unpack_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* name) {
	struct pfs_unpack_cb_args* args = (struct pfs_unpack_cb_args*)arg;
	struct pfs_unpack_cb_args new_args;
	struct pfs_file_context* file = NULL;
	uint8_t* data = NULL;
	char file_path[PATH_MAX + 1];
	char directory[PATH_MAX + 1];
	int needed;
	enum cb_result ret = CB_RESULT_CONTINUE;

	assert(args != NULL);

	assert(pfs != NULL);

	file = pfs_get_file(pfs, ino);
	if (!file)
		goto error;

	file_path[PATH_MAX] = '\0';
	directory[PATH_MAX] = '\0';

	snprintf(file_path, sizeof(file_path) - 1, "%s%s%s", args->parent_directory, name[0] != '/' ? "/" : "", name);

	if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
		if (type == PFS_ENTRY_DIRECTORY) {
			data = (uint8_t*)malloc(file->file_size);
			if (!data)
				goto error;
			memset(data, 0, file->file_size);

			if (!pfs_file_read(file, 0, data, file->file_size))
				goto error;

			memset(&new_args, 0, sizeof(new_args));
			{
				new_args.pre_cb = args->pre_cb;
				new_args.pre_cb_arg = args->pre_cb_arg;

				strncpy(new_args.output_directory, args->output_directory, sizeof(new_args.output_directory));
				strncpy(new_args.parent_directory, file_path, sizeof(new_args.parent_directory));
			}

			strncpy(directory, args->output_directory, sizeof(directory) - 1);
			strncat(directory, file_path, sizeof(directory) - 1);

			if (*args->pre_cb) {
				ret = (*args->pre_cb)(args->pre_cb_arg, file_path, type, &needed);
				if (ret == CB_RESULT_STOP)
					goto done;
				else if (ret == CB_RESULT_CONTINUE && !needed)
					goto done;
			}

			if (*directory != '\0')
				make_directories(directory, 0755);

			pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_unpack_cb, &new_args);
		} else if (type == PFS_ENTRY_FILE) {
			if (!pfs_unpack_single(pfs, file_path, args->output_directory, args->pre_cb, args->pre_cb_arg))
				error("Unable to unpack PKG file: %s", file_path);
		}
	}

done:
	if (data)
		free(data);

	if (file)
		pfs_free_file(file);

	return ret;

error:
	warning("Unable to get file: %s", name);
	goto done;
}

int pfs_unpack_all(struct pfs* pfs, const char* output_directory, pfs_unpack_pre_cb pre_cb, void* pre_cb_arg) {
	struct pfs_unpack_cb_args args;
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
		args.pre_cb = pre_cb;
		args.pre_cb_arg = pre_cb_arg;

		strncpy(args.output_directory, output_directory, sizeof(args.output_directory));
		args.parent_directory[0] = '\0';
	}

	pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_unpack_cb, &args);

	status = 1;

error:
	if (data)
		free(data);

	if (file)
		pfs_free_file(file);

	return status;
}

int pfs_dump_to_file(struct pfs* pfs, const char* path, pfs_unpack_pre_cb pre_cb, void* pre_cb_arg) {
	char directory[PATH_MAX + 1];
	uint8_t* block = NULL;
	size_t block_size;
	uint64_t start_block_no, block_count;
	uint64_t total_size, i;
#ifdef DONT_UNPACK_IF_EXISTS
	size_t existing_file_size;
#endif
	int fd = -1;
	int needed;
	enum cb_result ret;
	int status = 0;

	assert(pfs != NULL);
	assert(path != NULL);

	if (pre_cb) {
		ret = (*pre_cb)(pre_cb_arg, path, PFS_ENTRY_FILE, &needed);
		if (ret == CB_RESULT_STOP)
			goto done;
		else if (ret == CB_RESULT_CONTINUE && !needed)
			goto done;
	}

	path_get_directory(directory, sizeof(directory), path);
	directory[PATH_MAX] = '\0';

	if (*directory != '\0')
		make_directories(directory, 0755);

#ifdef DONT_UNPACK_IF_EXISTS
	existing_file_size = get_file_size(path);
	if (existing_file_size != (uint64_t)-1 && existing_file_size == file->file_size)
		goto done;
#endif

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE | O_BINARY, 0644);
	if (fd < 0)
		goto error;

	block_size = pfs->basic_block_size;
	block = (uint8_t*)malloc(block_size);
	if (!block)
		goto error;
	memset(block, 0, block_size);

	if (!pfs_io_get_size(pfs, &total_size))
		goto error;

	start_block_no = pfs->is_inner ? 0 : 1;
	block_count = total_size / block_size;

	if (start_block_no > 0) {
		for (i = 0; i < start_block_no; ++i) {
			if (!pfs_io_seek(pfs, i * block_size))
				goto error;
			if (!pfs_io_read(pfs, block, block_size))
				goto error;

			if (write(fd, block, block_size) != (ssize_t)block_size)
				goto error;
		}
	}

	for (i = start_block_no; i < block_count; ++i) {
		if (!pfs_read_blocks(pfs, i, block, 1))
			goto error;

		if (write(fd, block, block_size) != (ssize_t)block_size)
			goto error;
	}

done:
	status = 1;

error:
	if (block)
		free(block);

	if (fd > 0)
		close(fd);

	return status;
}
