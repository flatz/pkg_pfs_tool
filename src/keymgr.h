#pragma once

#include "common.h"

#include <uthash.h>

#define KEYMGR_CONTENT_ID_SIZE          0x24
#define KEYMGR_PASSCODE_SIZE            0x20
#define KEYMGR_AES_KEY_SIZE             0x10
#define KEYMGR_HMAC_KEY_SIZE            0x20
#define KEYMGR_HASH_SIZE                0x20
#define KEYMGR_SEED_SIZE                0x10
#define KEYMGR_IMAGE_KEY_ENC_SIZE       0x100
#define KEYMGR_EKPFS_SIZE               0x20
#define KEYMGR_CONTENT_KEY_SIZE         0x10
#define KEYMGR_SC0_KEY_SIZE             0x10
#define KEYMGR_SELF_KEY_SIZE            0x10
#define KEYMGR_MKEY_SIZE                0x20
#define KEYMGR_SEALED_KEY_ENC_KEY_SIZE  0x10
#define KEYMGR_SEALED_KEY_SIGN_KEY_SIZE 0x10
#define KEYMGR_SD_HEADER_SIG_KEY_SIZE   0x10
#define KEYMGR_SD_HEADER_DATA_KEY_SIZE  0x10
#define KEYMGR_SD_AUTH_CODE_KEY_SIZE    0x10
#define KEYMGR_IDPS_SIZE                0x10
#define KEYMGR_OPEN_PSID_SIZE           0x10
#define KEYMGR_OPEN_PSID_SIG_KEY_SIZE   0x10

#define KEYMGR_FAKE_CONTENT_ID "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

#if defined(ENABLE_SD_KEYGEN)
struct pfs;
#endif

struct keymgr_title_keyset {
	char content_id[KEYMGR_CONTENT_ID_SIZE + 1 + 0x10];
	char passcode[KEYMGR_PASSCODE_SIZE];
#if defined(ENABLE_SD_KEYGEN)
	uint8_t mkey[KEYMGR_MKEY_SIZE];
#endif
	uint8_t image_key[KEYMGR_HASH_SIZE];

	uint8_t enc_tweak_key[KEYMGR_AES_KEY_SIZE];
	uint8_t enc_data_key[KEYMGR_AES_KEY_SIZE];
	uint8_t sig_hmac_key[KEYMGR_HMAC_KEY_SIZE];
	uint8_t sc0_key[KEYMGR_SC0_KEY_SIZE];

#if defined(ENABLE_EKC_KEYGEN)
	uint8_t content_key_seed[KEYMGR_CONTENT_KEY_SIZE];
	uint8_t self_key_seed[KEYMGR_SELF_KEY_SIZE];
#endif

	struct {
		unsigned int has_passcode: 1;
#if defined(ENABLE_SD_KEYGEN)
		unsigned int has_mkey: 1;
#endif
		unsigned int has_image_key: 1;
		unsigned int has_enc_tweak_key: 1;
		unsigned int has_enc_data_key: 1;
		unsigned int has_sig_hmac_key: 1;
		unsigned int has_sc0_key: 1;
#if defined(ENABLE_EKC_KEYGEN)
		unsigned int has_content_key_seed: 1;
		unsigned int has_self_key_seed: 1;
#endif
	} flags;

	UT_hash_handle hh;
};

int keymgr_initialize(const char* config_file_path);
void keymgr_finalize(void);

struct keymgr_title_keyset* keymgr_alloc_title_keyset(const char* content_id, int is_real);
void keymgr_free_title_keyset(struct keymgr_title_keyset* keyset);

struct keymgr_title_keyset* keymgr_get_title_keyset(const char* content_id);

static inline int keymgr_has_passcode(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_passcode;
}

static inline int keymgr_has_image_key(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_image_key;
}

static inline int keymgr_has_encryption_key(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_enc_data_key &&keyset->flags.has_enc_tweak_key;
}

static inline int keymgr_has_signing_key(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_sig_hmac_key;
}

static inline int keymgr_has_sc0_key(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_sc0_key;
}

#if defined(ENABLE_EKC_KEYGEN)
static inline int keymgr_has_content_key_seed(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_content_key_seed;
}

static inline int keymgr_has_self_key_seed(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_self_key_seed;
}

static inline int keymgr_has_ekc(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_content_key_seed && keyset->flags.has_self_key_seed;
}
#endif

#if defined(ENABLE_SD_KEYGEN)
static inline int keymgr_has_mkey(struct keymgr_title_keyset* keyset) {
	assert(keyset != NULL);
	return keyset->flags.has_mkey;
}
#endif

int keymgr_generate_keys_for_title_keyset(struct keymgr_title_keyset* keyset, const char content_id[KEYMGR_CONTENT_ID_SIZE], uint8_t seed[KEYMGR_SEED_SIZE], int use_new_algo, uint8_t* out_image_key);

#if defined(ENABLE_SD_KEYGEN)
int keymgr_generate_keys_for_sd(struct keymgr_title_keyset* keyset, uint8_t content_key[KEYMGR_CONTENT_KEY_SIZE], uint8_t seed[KEYMGR_SEED_SIZE]);
#endif
