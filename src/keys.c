#include "keys.h"

struct rsa_keyset g_rsa_keyset_pkg_entry_key_3 = {
	"pkg_entry_key_3",
	/*  N */ NULL,
	/*  E */ NULL,
	/*  D */ NULL,
	/*  P */ NULL,
	/*  Q */ NULL,
	/* DP */ NULL,
	/* DQ */ NULL,
	/* QP */ NULL,
};

#if defined(ENABLE_EKC_KEYGEN)
struct rsa_keyset g_rsa_keyset_pkg_debug_ekpfs_key = {
	"debug_ekpfs_key",
	/*  N */ NULL,
	/*  E */ NULL,
	/*  D */ NULL,
	/*  P */ NULL,
	/*  Q */ NULL,
	/* DP */ NULL,
	/* DQ */ NULL,
	/* QP */ NULL,
};

struct rsa_keyset g_rsa_keyset_pkg_retail_ekpfs_key_0 = {
	"retail_ekpfs_key_0",
	/*  N */ NULL,
	/*  E */ NULL,
	/*  D */ NULL,
	/*  P */ NULL,
	/*  Q */ NULL,
	/* DP */ NULL,
	/* DQ */ NULL,
	/* QP */ NULL,
};

struct rsa_keyset g_rsa_keyset_pkg_retail_ekpfs_key_1 = {
	"retail_ekpfs_key_1",
	/*  N */ NULL,
	/*  E */ NULL,
	/*  D */ NULL,
	/*  P */ NULL,
	/*  Q */ NULL,
	/* DP */ NULL,
	/* DQ */ NULL,
	/* QP */ NULL,
};
#endif

struct rsa_keyset g_rsa_keyset_pkg_fake_ekpfs_key = {
	"fake_ekpfs_key",
	/*  N */ NULL,
	/*  E */ NULL,
	/*  D */ NULL,
	/*  P */ NULL,
	/*  Q */ NULL,
	/* DP */ NULL,
	/* DQ */ NULL,
	/* QP */ NULL,
};

struct rsa_keyset g_rsa_keyset_pfs_sig_key = {
	"pfs_sig_key",
	/*  N */ NULL,
	/*  E */ NULL,
	/*  D */ NULL,
	/*  P */ NULL,
	/*  Q */ NULL,
	/* DP */ NULL,
	/* DQ */ NULL,
	/* QP */ NULL,
};

const uint8_t g_debug_pfs_zero_crypt_seed[0x10] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

#if defined(ENABLE_EKC_KEYGEN)
uint8_t* g_ekpfs_obf_key_1 = NULL;
uint8_t* g_ekpfs_obf_key_2 = NULL;
uint8_t* g_ekpfs_obf_key_3 = NULL;
uint8_t* g_ekpfs_obf_key_4 = NULL;
uint8_t* g_ekpfs_obf_key_5 = NULL;
uint8_t* g_ekpfs_obf_key_6 = NULL;
uint8_t* g_ekpfs_obf_key_7 = NULL;
uint8_t* g_ekpfs_obf_key_8 = NULL;
uint8_t* g_ekpfs_obf_key_9 = NULL;
uint8_t* g_ekpfs_obf_key_10 = NULL;
uint8_t* g_ekpfs_obf_key_11 = NULL;
uint8_t* g_ekpfs_obf_key_12 = NULL;
uint8_t* g_ekpfs_obf_key_13 = NULL;
uint8_t* g_ekpfs_obf_key_14 = NULL;

uint8_t* g_gdgp_ekc_key_0 = NULL;
uint8_t* g_gdgp_ekc_key_1 = NULL;
uint8_t* g_gdgp_ekc_key_2 = NULL;

uint8_t* g_gdgp_content_key_obf_key = NULL;
uint8_t* g_ac_content_key = NULL;
#endif

#if defined(ENABLE_SD_KEYGEN)
uint8_t* g_idps = NULL;
uint8_t* g_open_psid = NULL;

uint8_t* g_sealed_key_enc_key_1 = NULL;
uint8_t* g_sealed_key_enc_key_2 = NULL;
uint8_t* g_sealed_key_enc_key_3 = NULL;
uint8_t* g_sealed_key_enc_key_4 = NULL;
uint8_t* g_sealed_key_enc_key_5 = NULL;
uint8_t* g_sealed_key_enc_key_6 = NULL;
uint8_t* g_sealed_key_enc_key_7 = NULL;
uint8_t* g_sealed_key_enc_key_8 = NULL;
uint8_t* g_sealed_key_enc_key_9 = NULL;
uint8_t* g_sealed_key_enc_key_10 = NULL;

uint8_t* g_sealed_key_sign_key_1 = NULL;
uint8_t* g_sealed_key_sign_key_2 = NULL;
uint8_t* g_sealed_key_sign_key_3 = NULL;
uint8_t* g_sealed_key_sign_key_4 = NULL;
uint8_t* g_sealed_key_sign_key_5 = NULL;
uint8_t* g_sealed_key_sign_key_6 = NULL;
uint8_t* g_sealed_key_sign_key_7 = NULL;
uint8_t* g_sealed_key_sign_key_8 = NULL;
uint8_t* g_sealed_key_sign_key_9 = NULL;
uint8_t* g_sealed_key_sign_key_10 = NULL;

uint8_t* g_sd_auth_code_key = NULL;

uint8_t* g_sd_hdr_data_key = NULL;
uint8_t* g_sd_hdr_sig_key = NULL;

uint8_t* g_open_psid_sig_key = NULL;

uint8_t* g_sd_content_key_1 = NULL;
uint8_t* g_sd_content_key_2 = NULL;
uint8_t* g_sd_content_key_3 = NULL;
uint8_t* g_sd_content_key_4 = NULL;
uint8_t* g_sd_content_key_5 = NULL;
uint8_t* g_sd_content_key_6 = NULL;
uint8_t* g_sd_content_key_7 = NULL;
uint8_t* g_sd_content_key_8 = NULL;
uint8_t* g_sd_content_key_9 = NULL;
#endif

int check_rsa_key_filled(const struct rsa_keyset* key, int is_private) {
	if (is_private) {
		return (
			key->n != NULL && key->e != NULL &&
			(key->d != NULL || key->p != NULL || key->q != NULL)
		);
	} else {
		return (
			key->n != NULL && key->e != NULL
		);
	}
}
