#include "pfs.h"
#include "keys.h"
#include "util.h"

#if defined(ENABLE_SD_KEYGEN)
int pfs_get_sd_content_key(struct pfs* pfs, uint8_t content_key[KEYMGR_CONTENT_KEY_SIZE]) {
	const uint8_t* content_keys[] = {
		g_sd_content_key_1,
		g_sd_content_key_2,
		g_sd_content_key_3,
		g_sd_content_key_4,
		g_sd_content_key_5,
		g_sd_content_key_6,
		g_sd_content_key_7,
		g_sd_content_key_8,
		g_sd_content_key_9,
	};
	unsigned int key_ver;
	int status = 0;

	assert(pfs != NULL);
	assert(pfs != NULL);

	if (!pfs_get_sd_key_ver(pfs, &key_ver)) {
		warning("SD key revision not found.");
		goto error;
	}
	if (!(key_ver > 0 && key_ver <= COUNT_OF(content_keys))) {
		warning("Unsupported SD key revision: %u", key_ver);
		goto error;
	}

	memcpy(content_key, content_keys[key_ver - 1], KEYMGR_CONTENT_KEY_SIZE);

	status = 1;

error:
	return status;
}

int pfs_decrypt_sealed_key(const struct sealed_key* key, uint8_t mkey[KEYMGR_MKEY_SIZE]) {
	const uint64_t magic = SEALED_KEY_MAGIC;
	const uint8_t* enc_keys[] = {
		g_sealed_key_enc_key_1,
		g_sealed_key_enc_key_2,
		g_sealed_key_enc_key_3,
		g_sealed_key_enc_key_4,
		g_sealed_key_enc_key_5,
		g_sealed_key_enc_key_6,
		g_sealed_key_enc_key_7,
		g_sealed_key_enc_key_8,
		g_sealed_key_enc_key_9,
		g_sealed_key_enc_key_10,
	};
	const uint8_t* sign_keys[] = {
		g_sealed_key_sign_key_1,
		g_sealed_key_sign_key_2,
		g_sealed_key_sign_key_3,
		g_sealed_key_sign_key_4,
		g_sealed_key_sign_key_5,
		g_sealed_key_sign_key_6,
		g_sealed_key_sign_key_7,
		g_sealed_key_sign_key_8,
		g_sealed_key_sign_key_9,
		g_sealed_key_sign_key_10,
	};
	uint16_t key_ver;
	uint8_t iv[0x10];
	uint8_t hash[PFS_HASH_SIZE];
	int status = 0;

	assert(key != NULL);
	assert(mkey != NULL);

	assert(COUNT_OF(enc_keys) == COUNT_OF(sign_keys));

	if (!has_magic((uint8_t*)&key->magic, sizeof(key->magic), &magic, sizeof(magic))) {
		warning("Invalid sealed key magic.");
		goto error;
	}

	key_ver = LE16(key->version);
	if (!(key_ver > 0 && key_ver <= COUNT_OF(enc_keys))) {
		warning("Unsupported sealed key version.");
		goto error;
	}
	if (!enc_keys[key_ver - 1]) {
		warning("Encryption key for sealed key not found.");
		goto error;
	}
	if (!sign_keys[key_ver - 1]) {
		warning("Signing key for sealed key not found.");
		goto error;
	}

	hmac_sha256_buffer(sign_keys[key_ver - 1], KEYMGR_SEALED_KEY_SIGN_KEY_SIZE, key, PFS_SD_HEADER_COVER_SIZE, hash);
	if (memcmp(hash, key->hash, sizeof(hash)) != 0) {
		warning("Invalid sealed key digest.");
		goto error;
	}

	memcpy(iv, key->iv, sizeof(iv));
	aes_decrypt_cbc_cts(enc_keys[key_ver - 1], KEYMGR_SEALED_KEY_ENC_KEY_SIZE, iv, key->data, mkey, sizeof(key->data));

	status = 1;

error:
	return status;
}

int pfs_decrypt_sealed_key_from_file(const char* path, uint8_t mkey[KEYMGR_MKEY_SIZE]) {
	FILE* fp = NULL;
	struct sealed_key key;
	int status = 0;

	assert(path != NULL);
	assert(mkey != NULL);

	fp = fopen(path, "rb");
	if (!fp) {
		warning("Unable to open sealed key file: %s", path);
		goto error;
	}

	memset(&key, 0, sizeof(key));
	if (fread(&key, 1, sizeof(key), fp) != sizeof(key)) {
		warning("Unable to read sealed key file: %s", path);
		goto error;
	}

	status = pfs_decrypt_sealed_key(&key, mkey);

error:
	if (fp)
		fclose(fp);

	return status;
}

int pfs_parse_sd_auth_code(struct pfs* pfs, struct sd_auth_code_info* info, int* has_auth_code) {
	const uint64_t magic = SD_AUTH_CODE_MAGIC;
	struct sd_auth_code auth_code;
	int status = 0;

	assert(pfs != NULL);
	assert(info != NULL);

	if (has_auth_code)
		*has_auth_code = 0;

	if (!pfs_io_seek(pfs, SD_AUTH_CODE_OFFSET)) {
		warning("Unable to seek to SD auth code.");
		goto error;
	}

	memset(&auth_code, 0, sizeof(auth_code));
	if (!pfs_io_read(pfs, &auth_code, sizeof(auth_code))) {
		warning("Unable to read SD auth code.");
		goto error;
	}

	if (!has_magic((uint8_t*)&auth_code.magic, sizeof(auth_code.magic), &magic, sizeof(magic)))
		goto done;

	if (has_auth_code)
		*has_auth_code = 1;

	if (LE32(auth_code.version_major) > 1 || LE32(auth_code.version_minor) > 1) {
		warning("Unsupported SD auth code version (%" PRIu32 "/%\" PRIu32 \").", auth_code.version_major, auth_code.version_minor);
		goto error;
	}

	if (!g_sd_auth_code_key) {
		warning("No SD auth code key found.");
		goto error;
	}
	aes_decrypt_cbc_cts(g_sd_auth_code_key, KEYMGR_SD_AUTH_CODE_KEY_SIZE, auth_code.iv, auth_code.data, auth_code.data, sizeof(auth_code.data));
	memcpy(info, &auth_code.info, sizeof(*info));

#if 1
	printf("SD auth code dump:\n");
	fprintf_hex(stdout, &auth_code, sizeof(auth_code), 2);
#endif

done:
	status = 1;

error:
	return status;
}
#endif
