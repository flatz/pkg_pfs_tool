#include "pfs.h"
#include "crypto.h"

#if defined(ENABLE_SD_KEYGEN)
int pfs_get_sd_key_ver(struct pfs* pfs, unsigned int* key_ver) {
	int status = 0;

	assert(pfs != NULL);

	if (LE64(pfs->hdr.version) != 1)
		goto error;

	if (key_ver)
		*key_ver = LE32(pfs->hdr.sd_key_ver);

	status = 1;

error:
	return status;
}
#endif

int pfs_check_cipher_block(struct pfs* pfs, const struct pfs_dinode* dinode, int type) {
	assert(pfs != NULL);

	if (!pfs->is_encrypted)
		return 0;
	if (type != 1 && type != 2)
		return 0;

	if (!dinode)
		return 1;
	if (!PFS_IS_REG(LE16(dinode->mode)))
		return 1;
	if (LE32(dinode->flags) & PFS_FILE_ENCRYPTED)
		return 1;

	return 0;
}

void pfs_encrypt(struct pfs* pfs, const void* in, void* out, uint64_t offset, uint64_t data_size) {
	assert(pfs != NULL);
	assert(in != NULL);
	assert(out != NULL);

	encdec_device_encrypt(pfs->encdec, in, out, offset >> pfs->encdec_sector_size_shift, data_size);
}

void pfs_decrypt(struct pfs* pfs, const void* in, void* out, uint64_t offset, uint64_t data_size) {
	assert(pfs != NULL);
	assert(in != NULL);
	assert(out != NULL);

	encdec_device_decrypt(pfs->encdec, in, out, offset >> pfs->encdec_sector_size_shift, data_size);
}

void pfs_sign_buffer(struct pfs* pfs, const void* data, uint64_t data_size, uint8_t hash[PFS_HASH_SIZE]) {
	assert(pfs != NULL);
	assert(data != NULL);
	assert(hash != NULL);

	assert(pfs->opts != NULL);
	assert(pfs->opts->keyset != NULL);

	hmac_sha256_buffer(pfs->opts->keyset->sig_hmac_key, sizeof(pfs->opts->keyset->sig_hmac_key), data, data_size, hash);
}

struct pfs_options* pfs_clone_options(const struct pfs_options* opts) {
	struct pfs_options* new_opts = NULL;

	assert(opts != NULL);

	new_opts = (struct pfs_options*)malloc(sizeof(*new_opts));
	if (!new_opts)
		goto error;
	memset(new_opts, 0, sizeof(*new_opts));

	new_opts->content_id = opts->content_id ? strdup(opts->content_id) : NULL;
	new_opts->keyset = opts->keyset;

	new_opts->case_sensitive = opts->case_sensitive;
	new_opts->playgo = opts->playgo;
	new_opts->finalized = opts->finalized;
#if defined(ENABLE_SD_KEYGEN)
	new_opts->is_sd = opts->is_sd;
#endif

	new_opts->skip_signature_check = opts->skip_signature_check;
	new_opts->skip_block_hash_check = opts->skip_block_hash_check;

	new_opts->skip_keygen = opts->skip_keygen;
	new_opts->disable_pkg_pfs_usage = opts->disable_pkg_pfs_usage;
	new_opts->dump_final_keys = opts->dump_final_keys;
#if defined(ENABLE_SD_KEYGEN)
	new_opts->dump_sd_info = opts->dump_sd_info;
#endif

	return new_opts;

error:
	pfs_free_options(new_opts);

	return NULL;
}

void pfs_free_options(struct pfs_options* opts) {
	if (!opts)
		return;
	if (opts->content_id)
		free(opts->content_id);
	free(opts);
}
