#include "keymgr.h"
#include "keys.h"
#include "config.h"
#include "crypto.h"
#include "util.h"

#include <utarray.h>

enum value_type {
	TYPE_STRING,
	TYPE_BYTE_ARRAY,
};

static struct {
	const char* key;
	void* value;
	enum value_type type;
	size_t len;
	int optional;
} s_common_key_value_map[] = {
	{ "pkg_entry_key_3:n", &g_rsa_keyset_pkg_entry_key_3.n, TYPE_STRING, 256 * 2, 1 },
	{ "pkg_entry_key_3:e", &g_rsa_keyset_pkg_entry_key_3.e, TYPE_STRING, 3 * 2, 1 },
	{ "pkg_entry_key_3:d", &g_rsa_keyset_pkg_entry_key_3.d, TYPE_STRING, 256 * 2, 1 },
	{ "pkg_entry_key_3:p", &g_rsa_keyset_pkg_entry_key_3.p, TYPE_STRING, 128 * 2, 1 },
	{ "pkg_entry_key_3:q", &g_rsa_keyset_pkg_entry_key_3.q, TYPE_STRING, 128 * 2, 1 },
	{ "pkg_entry_key_3:dp", &g_rsa_keyset_pkg_entry_key_3.dp, TYPE_STRING, 128 * 2, 1 },
	{ "pkg_entry_key_3:dq", &g_rsa_keyset_pkg_entry_key_3.dq, TYPE_STRING, 128 * 2, 1 },
	{ "pkg_entry_key_3:qp", &g_rsa_keyset_pkg_entry_key_3.qp, TYPE_STRING, 128 * 2, 1 },

#if defined(ENABLE_EKC_KEYGEN)
	{ "debug_ekpfs_key:n", &g_rsa_keyset_pkg_debug_ekpfs_key.n, TYPE_STRING, 256 * 2, 1 },
	{ "debug_ekpfs_key:e", &g_rsa_keyset_pkg_debug_ekpfs_key.e, TYPE_STRING, 256 * 2, 1 },

	{ "retail_ekpfs_key_0:n", &g_rsa_keyset_pkg_retail_ekpfs_key_0.n, TYPE_STRING, 256 * 2, 1 },
	{ "retail_ekpfs_key_0:e", &g_rsa_keyset_pkg_retail_ekpfs_key_0.e, TYPE_STRING, 3 * 2, 1 },

	{ "retail_ekpfs_key_1:n", &g_rsa_keyset_pkg_retail_ekpfs_key_1.n, TYPE_STRING, 256 * 2, 1 },
	{ "retail_ekpfs_key_1:e", &g_rsa_keyset_pkg_retail_ekpfs_key_1.e, TYPE_STRING, 3 * 2, 1 },

	{ "ekpfs_obf_key_1", &g_ekpfs_obf_key_1, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_2", &g_ekpfs_obf_key_2, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_3", &g_ekpfs_obf_key_3, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_4", &g_ekpfs_obf_key_4, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_5", &g_ekpfs_obf_key_5, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_6", &g_ekpfs_obf_key_6, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_7", &g_ekpfs_obf_key_7, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_8", &g_ekpfs_obf_key_8, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_9", &g_ekpfs_obf_key_9, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_10", &g_ekpfs_obf_key_10, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_11", &g_ekpfs_obf_key_11, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_12", &g_ekpfs_obf_key_12, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_13", &g_ekpfs_obf_key_13, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ekpfs_obf_key_14", &g_ekpfs_obf_key_14, TYPE_BYTE_ARRAY, 16, 1 },

	{ "gdgp_ekc_key_0", &g_gdgp_ekc_key_0, TYPE_BYTE_ARRAY, 16, 1 },
	{ "gdgp_ekc_key_1", &g_gdgp_ekc_key_1, TYPE_BYTE_ARRAY, 16, 1 },
	{ "gdgp_ekc_key_2", &g_gdgp_ekc_key_2, TYPE_BYTE_ARRAY, 16, 1 },

	{ "gdgp_content_key_obf_key", &g_gdgp_content_key_obf_key, TYPE_BYTE_ARRAY, 16, 1 },
	{ "ac_content_key", &g_ac_content_key, TYPE_BYTE_ARRAY, 16, 1 },
#endif

#if defined(ENABLE_SD_KEYGEN)
	{ "idps", &g_idps, TYPE_BYTE_ARRAY, 16, 1 },
	{ "open_psid", &g_open_psid, TYPE_BYTE_ARRAY, 16, 1 },

	{ "sealed_key_enc_key_1", &g_sealed_key_enc_key_1, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_2", &g_sealed_key_enc_key_2, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_3", &g_sealed_key_enc_key_3, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_4", &g_sealed_key_enc_key_4, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_5", &g_sealed_key_enc_key_5, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_6", &g_sealed_key_enc_key_6, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_7", &g_sealed_key_enc_key_7, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_8", &g_sealed_key_enc_key_8, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_9", &g_sealed_key_enc_key_9, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_enc_key_10", &g_sealed_key_enc_key_10, TYPE_BYTE_ARRAY, 16, 1 },

	{ "sealed_key_sign_key_1", &g_sealed_key_sign_key_1, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_2", &g_sealed_key_sign_key_2, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_3", &g_sealed_key_sign_key_3, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_4", &g_sealed_key_sign_key_4, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_5", &g_sealed_key_sign_key_5, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_6", &g_sealed_key_sign_key_6, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_7", &g_sealed_key_sign_key_7, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_8", &g_sealed_key_sign_key_8, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_9", &g_sealed_key_sign_key_9, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sealed_key_sign_key_10", &g_sealed_key_sign_key_10, TYPE_BYTE_ARRAY, 16, 1 },

	{ "sd_auth_code_key", &g_sd_auth_code_key, TYPE_BYTE_ARRAY, 16, 1 },

	{ "sd_hdr_data_key", &g_sd_hdr_data_key, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_hdr_sig_key", &g_sd_hdr_sig_key, TYPE_BYTE_ARRAY, 16, 1 },

	{ "open_psid_sig_key", &g_open_psid_sig_key, TYPE_BYTE_ARRAY, 16, 1 },

	{ "sd_content_key_1", &g_sd_content_key_1, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_content_key_2", &g_sd_content_key_2, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_content_key_3", &g_sd_content_key_3, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_content_key_4", &g_sd_content_key_4, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_content_key_5", &g_sd_content_key_5, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_content_key_6", &g_sd_content_key_6, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_content_key_7", &g_sd_content_key_7, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_content_key_8", &g_sd_content_key_8, TYPE_BYTE_ARRAY, 16, 1 },
	{ "sd_content_key_9", &g_sd_content_key_9, TYPE_BYTE_ARRAY, 16, 1 },
#endif

	{ "fake_ekpfs_key:n", &g_rsa_keyset_pkg_fake_ekpfs_key.n, TYPE_STRING, 256 * 2, 1 },
	{ "fake_ekpfs_key:e", &g_rsa_keyset_pkg_fake_ekpfs_key.e, TYPE_STRING, 3 * 2, 1 },
	{ "fake_ekpfs_key:d", &g_rsa_keyset_pkg_fake_ekpfs_key.d, TYPE_STRING, 256 * 2, 1 },
	{ "fake_ekpfs_key:p", &g_rsa_keyset_pkg_fake_ekpfs_key.p, TYPE_STRING, 128 * 2, 1 },
	{ "fake_ekpfs_key:q", &g_rsa_keyset_pkg_fake_ekpfs_key.q, TYPE_STRING, 128 * 2, 1 },
	{ "fake_ekpfs_key:dp", &g_rsa_keyset_pkg_fake_ekpfs_key.dp, TYPE_STRING, 128 * 2, 1 },
	{ "fake_ekpfs_key:dq", &g_rsa_keyset_pkg_fake_ekpfs_key.dq, TYPE_STRING, 128 * 2, 1 },
	{ "fake_ekpfs_key:qp", &g_rsa_keyset_pkg_fake_ekpfs_key.qp, TYPE_STRING, 128 * 2, 1 },

	{ "pfs_sig_key:n", &g_rsa_keyset_pfs_sig_key.n, TYPE_STRING, 256 * 2, 1 },
	{ "pfs_sig_key:e", &g_rsa_keyset_pfs_sig_key.e, TYPE_STRING, 3 * 2, 1 },
	{ "pfs_sig_key:d", &g_rsa_keyset_pfs_sig_key.d, TYPE_STRING, 256 * 2, 1 },
	{ "pfs_sig_key:p", &g_rsa_keyset_pfs_sig_key.p, TYPE_STRING, 128 * 2, 1 },
	{ "pfs_sig_key:q", &g_rsa_keyset_pfs_sig_key.q, TYPE_STRING, 128 * 2, 1 },
	{ "pfs_sig_key:dp", &g_rsa_keyset_pfs_sig_key.dp, TYPE_STRING, 128 * 2, 1 },
	{ "pfs_sig_key:dq", &g_rsa_keyset_pfs_sig_key.dq, TYPE_STRING, 128 * 2, 1 },
	{ "pfs_sig_key:qp", &g_rsa_keyset_pfs_sig_key.qp, TYPE_STRING, 128 * 2, 1 },
};

static UT_array* s_config_params = NULL;

static struct keymgr_title_keyset* s_title_keysets = NULL;

static void cleanup_config_params(void) {
	if (s_config_params) {
		utarray_free(s_config_params);
		s_config_params = NULL;
	}
}

static int config_cb(void* arg, const char* section, const char* name, const char* value) {
	struct keymgr_title_keyset* keyset;
	uint8_t* data = NULL;
	size_t size = 0;
	size_t i;

	UNUSED(arg);

	assert(section != NULL);
	assert(name != NULL);
	assert(value != NULL);

	if (strcasecmp(section, "common") == 0) {
		for (i = 0; i < COUNT_OF(s_common_key_value_map); ++i) {
			if (strcasecmp(name, s_common_key_value_map[i].key) != 0)
				continue;
			if (s_common_key_value_map[i].type == TYPE_STRING) {
				char** p_value = s_common_key_value_map[i].value;
				if (*p_value)
					free(*p_value);
				*p_value = strdup(value);
				utarray_push_back(s_config_params, &value);
			} else if (s_common_key_value_map[i].type == TYPE_BYTE_ARRAY) {
				data = x_to_u8_buffer(value, &size);
				if (!data)
					goto unexpected_error;
				if (size != s_common_key_value_map[i].len)
					goto tk_invalid_param_len;
				uint8_t** p_value = s_common_key_value_map[i].value;
				if (*p_value)
					free(*p_value);
				*p_value = data;
				utarray_push_back(s_config_params, &data);
				// Leave it allocated
				data = NULL;
			}
		}
	} else {
		keyset = keymgr_alloc_title_keyset(section, 1);
		if (!keyset)
			goto unexpected_error;

		if (strcasecmp(name, "passcode") == 0) {
			size = strlen(value);
			if (size != sizeof(keyset->passcode))
				goto tk_invalid_param_len;
			memcpy(keyset->passcode, value, size);
			keyset->flags.has_passcode = 1;
		} else if (strcasecmp(name, "enc_tweak_key") == 0) {
			data = x_to_u8_buffer(value, &size);
			if (!data)
				goto tk_invalid_param;
			if (size != sizeof(keyset->enc_tweak_key))
				goto tk_invalid_param_len;
			memcpy(keyset->enc_tweak_key, data, size);
			keyset->flags.has_enc_tweak_key = 1;
		} else if (strcasecmp(name, "enc_data_key") == 0) {
			data = x_to_u8_buffer(value, &size);
			if (!data)
				goto tk_invalid_param;
			if (size != sizeof(keyset->enc_data_key))
				goto tk_invalid_param_len;
			memcpy(keyset->enc_data_key, data, size);
			keyset->flags.has_enc_data_key = 1;
		} else if (strcasecmp(name, "sig_hmac_key") == 0) {
			data = x_to_u8_buffer(value, &size);
			if (!data)
				goto tk_invalid_param;
			if (size != sizeof(keyset->sig_hmac_key))
				goto tk_invalid_param_len;
			memcpy(keyset->sig_hmac_key, data, size);
			keyset->flags.has_sig_hmac_key = 1;
		} else if (strcasecmp(name, "image_key") == 0) {
			data = x_to_u8_buffer(value, &size);
			if (!data)
				goto tk_invalid_param;
			if (size != sizeof(keyset->image_key))
				goto tk_invalid_param_len;
			memcpy(keyset->image_key, data, size);
			keyset->flags.has_image_key = 1;
		} else if (strcasecmp(name, "sc0_key") == 0) {
			data = x_to_u8_buffer(value, &size);
			if (!data)
				goto tk_invalid_param;
			if (size != sizeof(keyset->sc0_key))
				goto tk_invalid_param_len;
			memcpy(keyset->sc0_key, data, size);
			keyset->flags.has_sc0_key = 1;
#if defined(ENABLE_EKC_KEYGEN)
		} else if (strcasecmp(name, "content_key_seed") == 0) {
			data = x_to_u8_buffer(value, &size);
			if (!data)
				goto tk_invalid_param;
			if (size != sizeof(keyset->content_key_seed))
				goto tk_invalid_param_len;
			memcpy(keyset->content_key_seed, data, size);
			keyset->flags.has_content_key_seed = 1;
		} else if (strcasecmp(name, "self_key_seed") == 0) {
			data = x_to_u8_buffer(value, &size);
			if (!data)
				goto tk_invalid_param;
			if (size != sizeof(keyset->self_key_seed))
				goto tk_invalid_param_len;
			memcpy(keyset->self_key_seed, data, size);
			keyset->flags.has_self_key_seed = 1;
		} else if (strcasecmp(name, "ekc") == 0) {
			data = x_to_u8_buffer(value, &size);
			if (!data)
				goto tk_invalid_param;
			if (size != sizeof(keyset->content_key_seed) + sizeof(keyset->self_key_seed))
				goto tk_invalid_param_len;
			memcpy(keyset->content_key_seed, data, sizeof(keyset->content_key_seed));
			memcpy(keyset->self_key_seed, data + sizeof(keyset->content_key_seed), sizeof(keyset->self_key_seed));
			keyset->flags.has_content_key_seed = 1;
			keyset->flags.has_self_key_seed = 1;
#endif
		}
	}

done:
	if (data)
		free(data);

	return 0;

tk_invalid_param:
	warning("Parameter '%s' for title keyset '%s' have invalid value: %s", name, section, value);
	goto done;

tk_invalid_param_len:
	warning("Parameter '%s' for title keyset '%s' have invalid length: %" PRIuMAX, name, section, (uintmax_t)size);
	goto done;

unexpected_error:
	warning("Unexpected error occured when handling parameter '%s' for title keyset '%s'", name, section);
	goto done;
}

int keymgr_initialize(const char* config_file_path) {
	size_t len, i;
	int has_errors = 0;
	int ret;

	assert(config_file_path != NULL);

	utarray_new(s_config_params, &ut_str_icd);
	atexit(&cleanup_config_params);

	if ((ret = parse_config_file(config_file_path, &config_cb, NULL)) != 0) {
		if (ret < 0)
			error("Unable to read configuration file: %s", config_file_path);
		else
			error("Unable to parse configuration file: %s(%d)", config_file_path, ret);
		return 0;
	}

	for (i = 0; i < COUNT_OF(s_common_key_value_map); ++i) {
		if (s_common_key_value_map[i].optional)
			continue;
		assert(s_common_key_value_map[i].value != NULL);
		if (*(char**)s_common_key_value_map[i].value) {
			len = strlen(*(char**)s_common_key_value_map[i].value);
			if (len != s_common_key_value_map[i].len) {
				warning("Common parameter '%s' should have %" PRIuMAX " bytes in hex representation.", s_common_key_value_map[i].key, (uintmax_t)s_common_key_value_map[i].len);
				has_errors = 1;
			}
		} else {
			warning("Common parameter '%s' is not set.", s_common_key_value_map[i].key);
			has_errors = 1;
		}
	}

	if (has_errors)
		error("Not all common parameters are set in configuration file.");

	return 1;
}

void keymgr_finalize(void) {
	struct keymgr_title_keyset* keyset;
	struct keymgr_title_keyset* tmp;

	HASH_ITER(hh, s_title_keysets, keyset, tmp) {
		HASH_DEL(s_title_keysets, keyset);
		free(keyset);
	}
}

struct keymgr_title_keyset* keymgr_alloc_title_keyset(const char* content_id, int is_real) {
	struct keymgr_title_keyset* keyset = NULL;

	assert(content_id != NULL);

	if (is_real && strcmp(content_id, KEYMGR_FAKE_CONTENT_ID) == 0) {
		warning("Content ID \'%s\' is reserved for internal use.", content_id);
		goto error;
	}

#if 0
	if (strlen(content_id) != KEYMGR_CONTENT_ID_SIZE) {
		warning("Invalid length for content ID \'%s\'.", content_id);
		goto error;
	}
#endif

	HASH_FIND_STR(s_title_keysets, content_id, keyset);
	if (!keyset) {
		keyset = (struct keymgr_title_keyset*)malloc(sizeof(*keyset));
		if (!keyset)
			return NULL;
		memset(keyset, 0, sizeof(*keyset));

		strncpy(keyset->content_id, content_id, sizeof(keyset->content_id));

		HASH_ADD_STR(s_title_keysets, content_id, keyset);
	}

error:
	return keyset;
}

void keymgr_free_title_keyset(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);

	HASH_DEL(s_title_keysets, keyset);

	free(keyset);
}

struct keymgr_title_keyset* keymgr_get_title_keyset(const char* content_id) {
	struct keymgr_title_keyset* keyset;

	assert(content_id != NULL);

#if 0
	if (strlen(content_id) != KEYMGR_CONTENT_ID_SIZE)
		return NULL;
#endif

	HASH_FIND_STR(s_title_keysets, content_id, keyset);

	return keyset;
}

static void gen_specific_key(const char* content_id, const char* passcode, unsigned int index, uint8_t key_blob[KEYMGR_HASH_SIZE]) {
	uint32_t d1;
	uint8_t d2[0x30], d3[2 * KEYMGR_HASH_SIZE + KEYMGR_PASSCODE_SIZE];

	assert(content_id != NULL);
	assert(passcode != NULL);
	assert(key_blob != NULL);

	memset(d2, 0, sizeof(d2));
	memset(d3, 0, sizeof(d3));

	d1 = BE32(index);
	sha256_buffer(&d1, sizeof(d1), d3);

	memcpy(d2, content_id, KEYMGR_CONTENT_ID_SIZE);
	sha256_buffer(d2, sizeof(d2), d3 + KEYMGR_HASH_SIZE);

	memcpy(d3 + 2 * KEYMGR_HASH_SIZE, passcode, KEYMGR_PASSCODE_SIZE);
	sha256_buffer(d3, sizeof(d3), key_blob);
}

static inline void gen_image_key(const char* content_id, const char* passcode, uint8_t image_key[KEYMGR_HASH_SIZE]) {
	assert(content_id != NULL);
	assert(passcode != NULL);
	assert(image_key != NULL);

	return gen_specific_key(content_id, passcode, 1, image_key);
}

static void gen_crypto_key(uint8_t image_key[KEYMGR_HASH_SIZE], uint8_t seed[KEYMGR_SEED_SIZE], unsigned int index, uint8_t key[KEYMGR_HASH_SIZE]) {
	uint8_t d[4 + KEYMGR_SEED_SIZE];

	assert(image_key != NULL);
	assert(seed != NULL);
	assert(key != NULL);

	memset(d, 0, sizeof(d));

	*(uint32_t*)d = LE32(index);
	memcpy(d + sizeof(uint32_t), seed, KEYMGR_SEED_SIZE);

	hmac_sha256_buffer(image_key, KEYMGR_HASH_SIZE, d, sizeof(d), key);
}

static inline void gen_encryption_key(uint8_t image_key[KEYMGR_HASH_SIZE], uint8_t seed[KEYMGR_SEED_SIZE], uint8_t key[KEYMGR_HASH_SIZE]) {
	assert(image_key != NULL);
	assert(seed != NULL);
	assert(key != NULL);

	return gen_crypto_key(image_key, seed, 1, key);
}

static inline void gen_signing_key(uint8_t image_key[KEYMGR_HASH_SIZE], uint8_t seed[KEYMGR_SEED_SIZE], uint8_t key[KEYMGR_HASH_SIZE]) {
	assert(image_key != NULL);
	assert(seed != NULL);
	assert(key != NULL);

	return gen_crypto_key(image_key, seed, 2, key);
}

int keymgr_generate_keys_for_title_keyset(struct keymgr_title_keyset* keyset, const char content_id[KEYMGR_CONTENT_ID_SIZE], uint8_t seed[KEYMGR_SEED_SIZE], int use_new_algo, uint8_t* out_image_key) {
	uint8_t image_key[KEYMGR_HASH_SIZE];
	uint8_t tmp_key[KEYMGR_HASH_SIZE];
	uint8_t key[KEYMGR_HASH_SIZE];
	int status = 0;

	assert(keyset != NULL);
	assert(seed != NULL);

	if (!content_id)
		content_id = keyset->content_id;

	if (keymgr_has_passcode(keyset) || keymgr_has_image_key(keyset)) {
		if (keymgr_has_passcode(keyset)) {
			gen_image_key(content_id, keyset->passcode, tmp_key);

			if (use_new_algo)
				hmac_sha256_buffer(tmp_key, KEYMGR_HASH_SIZE, seed, KEYMGR_SEED_SIZE, image_key);
			else
				memcpy(image_key, tmp_key, sizeof(image_key));

			memcpy(keyset->image_key, image_key, sizeof(keyset->image_key));
			keyset->flags.has_image_key = 1;
		} else if (keymgr_has_image_key(keyset)) {
			memcpy(image_key, keyset->image_key, sizeof(keyset->image_key));
		}

		if (out_image_key)
			memcpy(out_image_key, image_key, sizeof(image_key));

		gen_encryption_key(image_key, seed, key);
		memcpy(keyset->enc_tweak_key, key, KEYMGR_AES_KEY_SIZE);
		memcpy(keyset->enc_data_key, key + KEYMGR_AES_KEY_SIZE, KEYMGR_AES_KEY_SIZE);

		gen_signing_key(image_key, seed, key);
		memcpy(keyset->sig_hmac_key, key, KEYMGR_HMAC_KEY_SIZE);

		keyset->flags.has_enc_data_key = 1;
		keyset->flags.has_enc_tweak_key = 1;
		keyset->flags.has_sig_hmac_key = 1;
	} else {
		if (!keymgr_has_encryption_key(keyset) || !keymgr_has_signing_key(keyset))
			goto error;
	}

	status = 1;

error:
	return status;
}

#if defined(ENABLE_SD_KEYGEN)
int keymgr_generate_keys_for_sd(struct keymgr_title_keyset* keyset, uint8_t content_key[KEYMGR_CONTENT_KEY_SIZE], uint8_t seed[KEYMGR_SEED_SIZE]) {
	uint8_t image_key[KEYMGR_MKEY_SIZE];
	uint8_t key[KEYMGR_HASH_SIZE];
	int status = 0;

	assert(keyset != NULL);
	assert(content_key != NULL);
	assert(seed != NULL);

	if (keymgr_has_mkey(keyset)) {
		aes_decrypt_cbc_cts(content_key, KEYMGR_CONTENT_KEY_SIZE, NULL, keyset->mkey, image_key, sizeof(image_key));

		gen_encryption_key(image_key, seed, key);
		memcpy(keyset->enc_tweak_key, key, KEYMGR_AES_KEY_SIZE);
		memcpy(keyset->enc_data_key, key + KEYMGR_AES_KEY_SIZE, KEYMGR_AES_KEY_SIZE);

		gen_signing_key(image_key, seed, key);
		memcpy(keyset->sig_hmac_key, key, KEYMGR_HMAC_KEY_SIZE);

		keyset->flags.has_enc_data_key = 1;
		keyset->flags.has_enc_tweak_key = 1;
		keyset->flags.has_sig_hmac_key = 1;
	} else {
		if (!keymgr_has_encryption_key(keyset) || !keymgr_has_signing_key(keyset))
			goto error;
	}

	if (!keyset->flags.has_sc0_key)
		keyset->flags.has_sc0_key = 0;

	status = 1;

error:
	return status;
}
#endif
