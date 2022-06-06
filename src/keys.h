#pragma once

#include "crypto.h"
#include "keymgr.h"

extern struct rsa_keyset g_rsa_keyset_pkg_entry_key_3;

#if defined(ENABLE_EKC_KEYGEN)
extern struct rsa_keyset g_rsa_keyset_pkg_debug_ekpfs_key;
extern struct rsa_keyset g_rsa_keyset_pkg_retail_ekpfs_key_0;
extern struct rsa_keyset g_rsa_keyset_pkg_retail_ekpfs_key_1;
#endif

extern struct rsa_keyset g_rsa_keyset_pkg_fake_ekpfs_key;

extern struct rsa_keyset g_rsa_keyset_pfs_sig_key;

extern const uint8_t g_debug_pfs_zero_crypt_seed[0x10];

#if defined(ENABLE_EKC_KEYGEN)
extern uint8_t* g_ekpfs_obf_key_1;
extern uint8_t* g_ekpfs_obf_key_2;
extern uint8_t* g_ekpfs_obf_key_3;
extern uint8_t* g_ekpfs_obf_key_4;
extern uint8_t* g_ekpfs_obf_key_5;
extern uint8_t* g_ekpfs_obf_key_6;
extern uint8_t* g_ekpfs_obf_key_7;
extern uint8_t* g_ekpfs_obf_key_8;

extern uint8_t* g_gdgp_ekc_key_0;
extern uint8_t* g_gdgp_ekc_key_1;
extern uint8_t* g_gdgp_ekc_key_2;

extern uint8_t* g_gdgp_content_key_obf_key;
extern uint8_t* g_ac_content_key;
#endif

#if defined(ENABLE_SD_KEYGEN)
extern uint8_t* g_idps;
extern uint8_t* g_open_psid;

extern uint8_t* g_sealed_key_enc_key_1;
extern uint8_t* g_sealed_key_enc_key_2;
extern uint8_t* g_sealed_key_enc_key_3;
extern uint8_t* g_sealed_key_enc_key_4;
extern uint8_t* g_sealed_key_enc_key_5;
extern uint8_t* g_sealed_key_enc_key_6;
extern uint8_t* g_sealed_key_enc_key_7;
extern uint8_t* g_sealed_key_enc_key_8;
extern uint8_t* g_sealed_key_enc_key_9;
extern uint8_t* g_sealed_key_enc_key_10;

extern uint8_t* g_sealed_key_sign_key_1;
extern uint8_t* g_sealed_key_sign_key_2;
extern uint8_t* g_sealed_key_sign_key_3;
extern uint8_t* g_sealed_key_sign_key_4;
extern uint8_t* g_sealed_key_sign_key_5;
extern uint8_t* g_sealed_key_sign_key_6;
extern uint8_t* g_sealed_key_sign_key_7;
extern uint8_t* g_sealed_key_sign_key_8;
extern uint8_t* g_sealed_key_sign_key_9;
extern uint8_t* g_sealed_key_sign_key_10;

extern uint8_t* g_sd_auth_code_key;

extern uint8_t* g_sd_hdr_data_key;
extern uint8_t* g_sd_hdr_sig_key;

extern uint8_t* g_open_psid_sig_key;

extern uint8_t* g_sd_content_key_1;
extern uint8_t* g_sd_content_key_2;
extern uint8_t* g_sd_content_key_3;
extern uint8_t* g_sd_content_key_4;
extern uint8_t* g_sd_content_key_5;
extern uint8_t* g_sd_content_key_6;
extern uint8_t* g_sd_content_key_7;
extern uint8_t* g_sd_content_key_8;
extern uint8_t* g_sd_content_key_9;
#endif

int check_rsa_key_filled(const struct rsa_keyset* key, int is_private);
