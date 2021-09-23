#pragma once

#include "common.h"

#include <utstring.h>

#define PLAYGO_CONTENT_ID_SIZE 0x30

#define PLAYGO_MAX_IMAGES 2
#define PLAYGO_MAX_DISCS 2
#define PLAYGO_MAX_LAYERS_FOR_DISC1 2
#define PLAYGO_MAX_LAYERS_FOR_DISC2 1
#define PLAYGO_MAX_CHUNKS 1000
#define PLAYGO_MAX_MCHUNKS 8000
#define PLAYGO_MAX_SCENARIOS 32
#define PLAYGO_MAX_LANGUAGES 64

#define PLAYGO_SCENARIO_TYPE_SP 1
#define PLAYGO_SCENARIO_TYPE_MP 2

#define PLAYGO_SCENARIO_TYPE_USER_00 (16 + 1)

#define PLAYGO_ALL_LANGUAGES_MASK UINT64_C(0xFFFFFFFFFFFFFFFF)

struct playgo {
	uint16_t version_major;
	uint16_t version_minor;

	uint32_t file_size;

	uint32_t sdk_version;
	uint16_t attrib;

	uint16_t image_count;
	uint16_t chunk_count;
	uint16_t mchunk_count;
	uint16_t scenario_count;
	uint16_t disc_count;

	uint16_t layer_bmp;
	uint16_t default_scenario_id;

	char content_id[PLAYGO_CONTENT_ID_SIZE + 1];

	struct playgo_scenario_attr_desc* scenario_attrs;
	struct playgo_chunk_attr_desc* chunk_attrs;
	struct playgo_mchunk_attr_desc* mchunk_attrs;
	struct playgo_mchunk_attr_desc* inner_mchunk_attrs;
};

struct playgo_lang_desc {
	unsigned int code;
	const char* name;
	const char* iso1;
	const char* iso2;
};

enum {
	PLAYGO_LANG_JAPANESE = 0,
	PLAYGO_LANG_ENGLISH_US = 1,
	PLAYGO_LANG_FRENCH = 2,
	PLAYGO_LANG_SPANISH = 3,
	PLAYGO_LANG_GERMAN = 4,
	PLAYGO_LANG_ITALIAN = 5,
	PLAYGO_LANG_DUTCH = 6,
	PLAYGO_LANG_PORTUGUESE_PT = 7,
	PLAYGO_LANG_RUSSIAN = 8,
	PLAYGO_LANG_KOREAN = 9,
	PLAYGO_LANG_CHINESE_TRADITIONAL = 10,
	PLAYGO_LANG_CHINESE_SIMPLIFIED = 11,
	PLAYGO_LANG_FINNISH = 12,
	PLAYGO_LANG_SWEDISH = 13,
	PLAYGO_LANG_DANISH = 14,
	PLAYGO_LANG_NORWEGIAN = 15,
	PLAYGO_LANG_POLISH = 16,
	PLAYGO_LANG_PORTUGUESE_BR = 17,
	PLAYGO_LANG_ENGLISH_UK = 18,
	PLAYGO_LANG_TURKISH = 19,
	PLAYGO_LANG_SPANISH_LA = 20,
	PLAYGO_LANG_ARABIC = 21,
	PLAYGO_LANG_FRENCH_CA = 22,

	PLAYGO_LANG_USER_00 = 48,
	PLAYGO_LANG_USER_01 = 49,
	PLAYGO_LANG_USER_02 = 50,
	PLAYGO_LANG_USER_03 = 51,
	PLAYGO_LANG_USER_04 = 52,
	PLAYGO_LANG_USER_05 = 53,
	PLAYGO_LANG_USER_06 = 54,
	PLAYGO_LANG_USER_07 = 55,
	PLAYGO_LANG_USER_08 = 56,
	PLAYGO_LANG_USER_09 = 57,
	PLAYGO_LANG_USER_10 = 58,
	PLAYGO_LANG_USER_11 = 59,
	PLAYGO_LANG_USER_12 = 60,
	PLAYGO_LANG_USER_13 = 61,
	PLAYGO_LANG_USER_14 = 62,
};

enum {
	PLAYGO_LOCUS_NOT_DOWNLOADED = 0,
	PLAYGO_LOCUS_LOCAL_SLOW = 2,
	PLAYGO_LOCUS_LOCAL_FAST = 3,
};

enum {
	PLAYGO_INSTALL_SPEED_SUSPENDED = 0,
	PLAYGO_INSTALL_SPEED_TRICKLE = 1,
	PLAYGO_INSTALL_SPEED_FULL = 2,
};

struct playgo_scenario_attr_desc {
	unsigned int type;
	unsigned int initial_chunk_count;
	unsigned int chunk_count;
	char* label;
	uint16_t* chunks;
};

struct playgo_chunk_attr_desc {
	unsigned int flag;
	unsigned int disc_no;
	unsigned int layer_no;
	unsigned int image_no;
	unsigned int req_locus;
	unsigned int mchunk_count;
	uint64_t language_mask;
	char* label;
	uint16_t* mchunks;
};

struct playgo_mchunk_attr_desc {
	uint64_t offset;
	uint64_t size;
	unsigned int image_no;
};

struct playgo* playgo_alloc(void);
void playgo_free(struct playgo* plgo);

int playgo_load_from_memory(struct playgo* plgo, const void* data, size_t data_size);

int playgo_get_chunks(struct playgo* plgo, uint64_t offset, uint64_t size, uint16_t** chunks, size_t* nchunks);

int playgo_get_languages(struct playgo* plgo, UT_string* supported_langs_str, UT_string* def_lang_str, int* use_all_langs);
int playgo_get_chunk_languages(struct playgo* plgo, size_t index, UT_string* langs_str);

void playgo_dump(struct playgo* plgo);

const struct playgo_lang_desc* playgo_get_lang_by_code(unsigned int code);
