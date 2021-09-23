#pragma once

#include "crypto.h"
#include "keymgr.h"

struct rsa_keyset g_rsa_keyset_pkg_entry_key_3;

#if defined(ENABLE_EKC_KEYGEN)
struct rsa_keyset g_rsa_keyset_pkg_debug_ekpfs_key;
struct rsa_keyset g_rsa_keyset_pkg_retail_ekpfs_key_0;
struct rsa_keyset g_rsa_keyset_pkg_retail_ekpfs_key_1;
#endif

struct rsa_keyset g_rsa_keyset_pkg_fake_ekpfs_key;

struct rsa_keyset g_rsa_keyset_pfs_sig_key;

const uint8_t g_debug_pfs_zero_crypt_seed[0x10];

#if defined(ENABLE_EKC_KEYGEN)
uint8_t* g_ekpfs_obf_key_1;
uint8_t* g_ekpfs_obf_key_2;
uint8_t* g_ekpfs_obf_key_3;
uint8_t* g_ekpfs_obf_key_4;
uint8_t* g_ekpfs_obf_key_5;
uint8_t* g_ekpfs_obf_key_6;
uint8_t* g_ekpfs_obf_key_7;
uint8_t* g_ekpfs_obf_key_8;

uint8_t* g_gdgp_ekc_key_0;
uint8_t* g_gdgp_ekc_key_1;
uint8_t* g_gdgp_ekc_key_2;

uint8_t* g_gdgp_content_key_obf_key;
uint8_t* g_ac_content_key;
#endif

#if defined(ENABLE_SD_KEYGEN)
uint8_t* g_idps;
uint8_t* g_open_psid;

uint8_t* g_sealed_key_enc_key_1;
uint8_t* g_sealed_key_enc_key_2;
uint8_t* g_sealed_key_enc_key_3;
uint8_t* g_sealed_key_enc_key_4;
uint8_t* g_sealed_key_enc_key_5;
uint8_t* g_sealed_key_enc_key_6;
uint8_t* g_sealed_key_enc_key_7;
uint8_t* g_sealed_key_enc_key_8;
uint8_t* g_sealed_key_enc_key_9;
uint8_t* g_sealed_key_enc_key_10;

uint8_t* g_sealed_key_sign_key_1;
uint8_t* g_sealed_key_sign_key_2;
uint8_t* g_sealed_key_sign_key_3;
uint8_t* g_sealed_key_sign_key_4;
uint8_t* g_sealed_key_sign_key_5;
uint8_t* g_sealed_key_sign_key_6;
uint8_t* g_sealed_key_sign_key_7;
uint8_t* g_sealed_key_sign_key_8;
uint8_t* g_sealed_key_sign_key_9;
uint8_t* g_sealed_key_sign_key_10;

uint8_t* g_sd_auth_code_key;

uint8_t* g_sd_hdr_data_key;
uint8_t* g_sd_hdr_sig_key;

uint8_t* g_open_psid_sig_key;

uint8_t* g_sd_content_key_1;
uint8_t* g_sd_content_key_2;
uint8_t* g_sd_content_key_3;
uint8_t* g_sd_content_key_4;
uint8_t* g_sd_content_key_5;
uint8_t* g_sd_content_key_6;
uint8_t* g_sd_content_key_7;
uint8_t* g_sd_content_key_8;
uint8_t* g_sd_content_key_9;
#endif

int check_rsa_key_filled(const struct rsa_keyset* key, int is_private);

