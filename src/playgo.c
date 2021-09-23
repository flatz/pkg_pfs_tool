#include "playgo.h"
#include "util.h"

#include <utarray.h>

#define PLAYGO_MAGIC "plgo"

#define PLAYGO_HEADER_SIZE 0x100
#define PLAYGO_SCENARIO_ATTRIBUTE_ENTRY_SIZE 0x20
#define PLAYGO_CHUNK_ATTRIBUTE_ENTRY_SIZE 0x20
#define PLAYGO_MCHUNK_ATTRIBUTE_ENTRY_SIZE 0x10

static const struct playgo_lang_desc s_languages[] = {
	{ PLAYGO_LANG_JAPANESE, "Japanese", "ja", NULL },
	{ PLAYGO_LANG_ENGLISH_US, "English", "en-US", "en" },
	{ PLAYGO_LANG_FRENCH, "French", "fr", NULL },
	{ PLAYGO_LANG_SPANISH, "Spanish", "es-ES", "es" },
	{ PLAYGO_LANG_GERMAN, "German", "de", NULL },
	{ PLAYGO_LANG_ITALIAN, "Italian", "it", NULL },
	{ PLAYGO_LANG_DUTCH, "Dutch", "nl", NULL },
	{ PLAYGO_LANG_PORTUGUESE_PT, "Portuguese", "pt-PT", "pt" },
	{ PLAYGO_LANG_RUSSIAN, "Russian", "ru", NULL },
	{ PLAYGO_LANG_KOREAN, "Korean", "ko", NULL },
	{ PLAYGO_LANG_CHINESE_TRADITIONAL, "Trad.Chinese", "zh-Hant", NULL },
	{ PLAYGO_LANG_CHINESE_SIMPLIFIED, "Simp.Chinese", "zh-Hans", NULL },
	{ PLAYGO_LANG_FINNISH, "Finnish", "fi", NULL },
	{ PLAYGO_LANG_SWEDISH, "Swedish", "sv", NULL },
	{ PLAYGO_LANG_DANISH, "Danish", "da", NULL },
	{ PLAYGO_LANG_NORWEGIAN, "Norwegian", "no", NULL },
	{ PLAYGO_LANG_POLISH, "Polish", "pl", NULL },
	{ PLAYGO_LANG_PORTUGUESE_BR, "Braz.Portuguese", "pt-BR", NULL },
	{ PLAYGO_LANG_ENGLISH_UK, "UK English", "en-GB", NULL },
	{ PLAYGO_LANG_TURKISH, "Turkish", "tr", NULL },
	{ PLAYGO_LANG_SPANISH_LA, "Latin American Spanish", "es-LA", NULL },
	{ PLAYGO_LANG_ARABIC, "Arabic", "ar", NULL },
	{ PLAYGO_LANG_FRENCH_CA, "Canadian French", "fr-CA", NULL },

	{ PLAYGO_LANG_USER_00, "User-defined Language #0", "user00", NULL },
	{ PLAYGO_LANG_USER_01, "User-defined Language #1", "user01", NULL },
	{ PLAYGO_LANG_USER_02, "User-defined Language #2", "user02", NULL },
	{ PLAYGO_LANG_USER_03, "User-defined Language #3", "user03", NULL },
	{ PLAYGO_LANG_USER_04, "User-defined Language #4", "user04", NULL },
	{ PLAYGO_LANG_USER_05, "User-defined Language #5", "user05", NULL },
	{ PLAYGO_LANG_USER_06, "User-defined Language #6", "user06", NULL },
	{ PLAYGO_LANG_USER_07, "User-defined Language #7", "user07", NULL },
	{ PLAYGO_LANG_USER_08, "User-defined Language #8", "user08", NULL },
	{ PLAYGO_LANG_USER_09, "User-defined Language #9", "user09", NULL },
	{ PLAYGO_LANG_USER_10, "User-defined Language #10", "user10", NULL },
	{ PLAYGO_LANG_USER_11, "User-defined Language #11", "user11", NULL },
	{ PLAYGO_LANG_USER_12, "User-defined Language #12", "user12", NULL },
	{ PLAYGO_LANG_USER_13, "User-defined Language #13", "user13", NULL },
	{ PLAYGO_LANG_USER_14, "User-defined Language #14", "user14", NULL },
};

TYPE_BEGIN(struct playgo_scenario_attr_entry, PLAYGO_SCENARIO_ATTRIBUTE_ENTRY_SIZE);
	TYPE_FIELD(uint8_t type, 0x00);
	TYPE_FIELD(uint16_t initial_chunk_count, 0x14);
	TYPE_FIELD(uint16_t chunk_count, 0x16);
	TYPE_FIELD(uint32_t chunks_offset, 0x18);
	TYPE_FIELD(uint32_t label_offset, 0x1C);
TYPE_END();
CT_SIZE_ASSERT(struct playgo_scenario_attr_entry, PLAYGO_SCENARIO_ATTRIBUTE_ENTRY_SIZE);

TYPE_BEGIN(struct playgo_chunk_attr_entry, PLAYGO_CHUNK_ATTRIBUTE_ENTRY_SIZE);
	TYPE_FIELD(uint8_t flag, 0x00);
	TYPE_FIELD(uint8_t image_disc_layer_no, 0x01);
	TYPE_FIELD(uint8_t req_locus, 0x02);
	TYPE_FIELD(uint16_t mchunk_count, 0x0E);
	TYPE_FIELD(uint64_t language_mask, 0x10);
	TYPE_FIELD(uint32_t mchunks_offset, 0x18);
	TYPE_FIELD(uint32_t label_offset, 0x1C);
TYPE_END();
CT_SIZE_ASSERT(struct playgo_chunk_attr_entry, PLAYGO_CHUNK_ATTRIBUTE_ENTRY_SIZE);

union playgo_chunk_loc {
	struct {
		uint64_t offset: 48;
		uint64_t: 8;
		uint64_t image_no: 4;
		uint64_t: 4;
	};
	uint64_t raw;
};

union playgo_chunk_size {
	struct {
		uint64_t size: 48;
		uint64_t: 16;
	};
	uint64_t raw;
};

TYPE_BEGIN(struct playgo_mchunk_attr_entry, PLAYGO_MCHUNK_ATTRIBUTE_ENTRY_SIZE);
	TYPE_FIELD(union playgo_chunk_loc loc, 0x00);
	TYPE_FIELD(union playgo_chunk_size size, 0x08);
TYPE_END();
CT_SIZE_ASSERT(struct playgo_mchunk_attr_entry, PLAYGO_MCHUNK_ATTRIBUTE_ENTRY_SIZE);

TYPE_BEGIN(struct playgo_header, PLAYGO_HEADER_SIZE);
	TYPE_FIELD(char magic[4], 0x00);
	TYPE_FIELD(uint16_t version_major, 0x04);
	TYPE_FIELD(uint16_t version_minor, 0x06);
	TYPE_FIELD(uint16_t image_count, 0x08); /* [0;1] */
	TYPE_FIELD(uint16_t chunk_count, 0x0A); /* [0;1000] */
	TYPE_FIELD(uint16_t mchunk_count, 0x0C); /* [0;8000] */
	TYPE_FIELD(uint16_t scenario_count, 0x0E); /* [0;32] */
	TYPE_FIELD(uint32_t file_size, 0x10);
	TYPE_FIELD(uint16_t default_scenario_id, 0x14);
	TYPE_FIELD(uint16_t attrib, 0x16);
	TYPE_FIELD(uint32_t sdk_version, 0x18);
	TYPE_FIELD(uint16_t disc_count, 0x1C); /* [0;2] (if equals to 0 then disc count = 1) */
	TYPE_FIELD(uint16_t layer_bmp, 0x1E);
	TYPE_FIELD(uint8_t reserved[0x20], 0x20);
	TYPE_FIELD(char content_id[PLAYGO_CONTENT_ID_SIZE], 0x40);

	/* chunk attributes */
	TYPE_FIELD(uint32_t chunk_attrs_offset, 0xC0);
	TYPE_FIELD(uint32_t chunk_attrs_size, 0xC4); /* [0;32000] */

	/* chunk mchunks */
	TYPE_FIELD(uint32_t chunk_mchunks_offset, 0xC8);
	TYPE_FIELD(uint32_t chunk_mchunks_size, 0xCC);

	/* chunk labels */
	TYPE_FIELD(uint32_t chunk_labels_offset, 0xD0);
	TYPE_FIELD(uint32_t chunk_labels_size, 0xD4); /* [0;16000] */

	/* mchunk attributes */
	TYPE_FIELD(uint32_t mchunk_attrs_offset, 0xD8);
	TYPE_FIELD(uint32_t mchunk_attrs_size, 0xDC); /* [0;12800] */

	/* scenario attributes */
	TYPE_FIELD(uint32_t scenario_attrs_offset, 0xE0);
	TYPE_FIELD(uint32_t scenario_attrs_size, 0xE4); /* [0;1024] */

	/* scenarios chunks */
	TYPE_FIELD(uint32_t scenario_chunks_offset, 0xE8);
	TYPE_FIELD(uint32_t scenario_chunks_size, 0xEC);

	/* scenario labels */
	TYPE_FIELD(uint32_t scenario_labels_offset, 0xF0);
	TYPE_FIELD(uint32_t scenario_labels_size, 0xF4);

	/* inner mchunk attributes */
	TYPE_FIELD(uint32_t inner_mchunk_attrs_offset, 0xF8);
	TYPE_FIELD(uint32_t inner_mchunk_attrs_size, 0xFC); /* [0;12800] */
TYPE_END();
CT_SIZE_ASSERT(struct playgo_header, PLAYGO_HEADER_SIZE);

static const UT_icd ut_uint16_icd = { sizeof(uint16_t), NULL, NULL, NULL };

static void playgo_cleanup(struct playgo* plgo);

static int parse_scenario_attr(struct playgo* plgo, size_t index, const struct playgo_scenario_attr_entry* entry, const uint16_t* chunks, size_t chunks_size, const char* labels, size_t labels_size);
static int parse_chunk_attr(struct playgo* plgo, size_t index, const struct playgo_chunk_attr_entry* entry, const uint16_t* mchunks, size_t mchunks_size, const char* labels, size_t labels_size);
static int parse_mchunk_attr(struct playgo* plgo, size_t index, const struct playgo_mchunk_attr_entry* entry, int is_inner);

static inline int has_language(uint64_t language_mask, unsigned int code);

struct playgo* playgo_alloc(void) {
	struct playgo* plgo = NULL;

	plgo = (struct playgo*)malloc(sizeof(*plgo));
	if (!plgo)
		goto error;
	memset(plgo, 0, sizeof(*plgo));

	return plgo;

error:
	if (plgo)
		free(plgo);

	return NULL;
}

void playgo_free(struct playgo* plgo) {
	if (!plgo)
		return;

	playgo_cleanup(plgo);

	free(plgo);
}

int playgo_load_from_memory(struct playgo* plgo, const void* data, size_t data_size) {
	const uint8_t* data_raw;
	struct playgo_header* hdr;
	const struct playgo_scenario_attr_entry* scenario_attrs;
	const uint16_t* scenario_chunks;
	const char* scenario_labels;
	const struct playgo_chunk_attr_entry* chunk_attrs;
	const uint16_t* chunk_mchunks;
	const char* chunk_labels;
	const struct playgo_mchunk_attr_entry* mchunk_attrs;
	const struct playgo_mchunk_attr_entry* inner_mchunk_attrs;
	uint32_t chunk_attrs_offset, chunk_attrs_size;
	uint32_t chunk_mchunks_offset, chunk_mchunks_size;
	uint32_t chunk_labels_offset, chunk_labels_size;
	uint32_t mchunk_attrs_offset, mchunk_attrs_size;
	uint32_t scenario_attrs_offset, scenario_attrs_size;
	uint32_t scenario_chunks_offset, scenario_chunks_size;
	uint32_t scenario_labels_offset, scenario_labels_size;
	uint32_t inner_mchunk_attrs_offset, inner_mchunk_attrs_size;
	size_t i;

	assert(plgo != NULL);
	assert(data != NULL);

	if (data_size < sizeof(*hdr)) {
		warning("Insufficient data.");
		goto error;
	}

	data_raw = (const uint8_t*)data;

	hdr = (struct playgo_header*)data_raw;
	if (memcmp(hdr->magic, PLAYGO_MAGIC, sizeof(hdr->magic)) != 0) {
		warning("Invalid playgo file format.");
		goto error;
	}

	plgo->version_major = LE16(hdr->version_major);
	plgo->version_minor = LE16(hdr->version_minor);

	plgo->file_size = LE32(hdr->file_size);

	plgo->sdk_version = LE32(hdr->sdk_version);
	plgo->attrib = LE16(hdr->attrib);

	plgo->image_count = LE16(hdr->image_count);
	if (plgo->image_count > PLAYGO_MAX_IMAGES) {
		warning("Too much images in playgo file.");
		goto error;
	}
	plgo->chunk_count = LE16(hdr->chunk_count);
	if (plgo->chunk_count > PLAYGO_MAX_CHUNKS) {
		warning("Too much chunks in playgo file.");
		goto error;
	}
	plgo->mchunk_count = LE16(hdr->mchunk_count);
	if (plgo->mchunk_count > PLAYGO_MAX_MCHUNKS) {
		warning("Too much mchunks in playgo file.");
		goto error;
	}
	plgo->scenario_count = LE16(hdr->scenario_count);
	if (plgo->scenario_count > PLAYGO_MAX_SCENARIOS) {
		warning("Too much scenarios in playgo file.");
		goto error;
	}
	plgo->disc_count = LE16(hdr->disc_count);
	if (plgo->disc_count == 0)
		plgo->disc_count = 1;
	if (plgo->disc_count > PLAYGO_MAX_DISCS) {
		warning("Too much discs in playgo file.");
		goto error;
	}
	plgo->layer_bmp = LE16(hdr->layer_bmp);

	plgo->default_scenario_id = LE16(hdr->default_scenario_id);
	if (plgo->default_scenario_id >= plgo->scenario_count) {
		warning("Invalid default scenario id.");
		goto error;
	}

	memcpy(plgo->content_id, hdr->content_id, sizeof(plgo->content_id) - 1);
	plgo->content_id[sizeof(plgo->content_id) - 1] = '\0';

	chunk_attrs_offset = LE32(hdr->chunk_attrs_offset);
	chunk_attrs_size = LE32(hdr->chunk_attrs_size);
	if (chunk_attrs_offset + chunk_attrs_size > plgo->file_size) {
		warning("Invalid chunk attributes offset or size.");
		goto error;
	}

	chunk_mchunks_offset = LE32(hdr->chunk_mchunks_offset);
	chunk_mchunks_size = LE32(hdr->chunk_mchunks_size);
	if (chunk_mchunks_offset + chunk_mchunks_size > plgo->file_size) {
		warning("Invalid chunk mchunks offset or size.");
		goto error;
	}

	chunk_labels_offset = LE32(hdr->chunk_labels_offset);
	chunk_labels_size = LE32(hdr->chunk_labels_size);
	if (chunk_labels_offset + chunk_labels_size > plgo->file_size) {
		warning("Invalid chunk labels offset or size.");
		goto error;
	}

	mchunk_attrs_offset = LE32(hdr->mchunk_attrs_offset);
	mchunk_attrs_size = LE32(hdr->mchunk_attrs_size);
	if (mchunk_attrs_offset + mchunk_attrs_size > plgo->file_size) {
		warning("Invalid mchunk attributes offset or size.");
		goto error;
	}

	scenario_attrs_offset = LE32(hdr->scenario_attrs_offset);
	scenario_attrs_size = LE32(hdr->scenario_attrs_size);
	if (scenario_attrs_offset + scenario_attrs_size > plgo->file_size) {
		warning("Invalid scenario attributes offset or size.");
		goto error;
	}

	scenario_chunks_offset = LE32(hdr->scenario_chunks_offset);
	scenario_chunks_size = LE32(hdr->scenario_chunks_size);
	if (scenario_chunks_offset + scenario_chunks_size > plgo->file_size) {
		warning("Invalid scenario chunks offset or size.");
		goto error;
	}

	scenario_labels_offset = LE32(hdr->scenario_labels_offset);
	scenario_labels_size = LE32(hdr->scenario_labels_size);
	if (scenario_labels_offset + scenario_labels_size > plgo->file_size) {
		warning("Invalid scenario labels offset or size.");
		goto error;
	}

	inner_mchunk_attrs_offset = LE32(hdr->inner_mchunk_attrs_offset);
	inner_mchunk_attrs_size = LE32(hdr->inner_mchunk_attrs_size);
	if (inner_mchunk_attrs_offset + inner_mchunk_attrs_size > plgo->file_size) {
		warning("Invalid inner mchunks offset or size.");
		goto error;
	}

	scenario_attrs = (const struct playgo_scenario_attr_entry*)(data_raw + scenario_attrs_offset);
	scenario_chunks = (const uint16_t*)(data_raw + scenario_chunks_offset);
	scenario_labels = (const char*)(data_raw + scenario_labels_offset);

	chunk_attrs = (const struct playgo_chunk_attr_entry*)(data_raw + chunk_attrs_offset);
	chunk_mchunks = (const uint16_t*)(data_raw + chunk_mchunks_offset);
	chunk_labels = (const char*)(data_raw + chunk_labels_offset);

	mchunk_attrs = (const struct playgo_mchunk_attr_entry*)(data_raw + mchunk_attrs_offset);
	inner_mchunk_attrs = (const struct playgo_mchunk_attr_entry*)(data_raw + inner_mchunk_attrs_offset);

	plgo->scenario_attrs = (struct playgo_scenario_attr_desc*)malloc(sizeof(*plgo->scenario_attrs) * plgo->scenario_count);
	if (!plgo->scenario_attrs) {
		warning("Unable to allocate memory for scenario attributes.");
		goto error;
	}
	memset(plgo->scenario_attrs, 0, sizeof(*plgo->scenario_attrs) * plgo->scenario_count);
	{
		for (i = 0; i < plgo->scenario_count; ++i) {
			if (!parse_scenario_attr(plgo, i, scenario_attrs + i, scenario_chunks, scenario_chunks_size, scenario_labels, scenario_labels_size)) {
				warning("Invalid scenario attribute entry #%" PRIuMAX, (uintmax_t)i);
				goto error;
			}
		}
	}

	plgo->chunk_attrs = (struct playgo_chunk_attr_desc*)malloc(sizeof(*plgo->chunk_attrs) * plgo->chunk_count);
	if (!plgo->chunk_attrs) {
		warning("Unable to allocate memory for chunk attributes.");
		goto error;
	}
	memset(plgo->chunk_attrs, 0, sizeof(*plgo->chunk_attrs) * plgo->chunk_count);
	{
		for (i = 0; i < plgo->chunk_count; ++i) {
			if (!parse_chunk_attr(plgo, i, chunk_attrs + i, chunk_mchunks, chunk_mchunks_size, chunk_labels, chunk_labels_size)) {
				warning("Invalid chunk attribute entry #%" PRIuMAX, (uintmax_t)i);
				goto error;
			}
		}
	}

	plgo->mchunk_attrs = (struct playgo_mchunk_attr_desc*)malloc(sizeof(*plgo->mchunk_attrs) * plgo->mchunk_count);
	if (!plgo->mchunk_attrs) {
		warning("Unable to allocate memory for mchunk attributes.");
		goto error;
	}
	memset(plgo->mchunk_attrs, 0, sizeof(*plgo->mchunk_attrs) * plgo->mchunk_count);
	{
		for (i = 0; i < plgo->mchunk_count; ++i) {
			if (!parse_mchunk_attr(plgo, i, mchunk_attrs + i, 0)) {
				warning("Invalid mchunk attribute entry #%" PRIuMAX, (uintmax_t)i);
				goto error;
			}
		}
	}

	plgo->inner_mchunk_attrs = (struct playgo_mchunk_attr_desc*)malloc(sizeof(*plgo->inner_mchunk_attrs) * plgo->mchunk_count);
	if (!plgo->inner_mchunk_attrs) {
		warning("Unable to allocate memory for inner mchunk attributes.");
		goto error;
	}
	memset(plgo->inner_mchunk_attrs, 0, sizeof(*plgo->inner_mchunk_attrs) * plgo->mchunk_count);
	{
		for (i = 0; i < plgo->mchunk_count; ++i) {
			if (!parse_mchunk_attr(plgo, i, inner_mchunk_attrs + i, 1)) {
				warning("Invalid inner mchunk attribute entry #%" PRIuMAX, (uintmax_t)i);
				goto error;
			}
		}
	}

	return 1;

error:
	playgo_cleanup(plgo);

	return 0;
}

int playgo_get_languages(struct playgo* plgo, UT_string* supported_langs_str, UT_string* def_lang_str, int* use_all_langs) {
	struct playgo_chunk_attr_desc* chunk_attr;
	const struct playgo_lang_desc* lang;
	unsigned int lang_counts[PLAYGO_MAX_LANGUAGES];
	unsigned int has_default_lang, first, count;
	uint32_t i;
	uint64_t j;
	int status = 0;

	assert(plgo != NULL);
	assert(supported_langs_str != NULL);
	assert(def_lang_str != NULL);

	utstring_clear(supported_langs_str);
	utstring_clear(def_lang_str);

	memset(lang_counts, 0, sizeof(lang_counts));

	for (i = 0, has_default_lang = 0, first = 1; i < plgo->chunk_count; ++i) {
		chunk_attr = plgo->chunk_attrs + i;
		if (chunk_attr->language_mask == PLAYGO_ALL_LANGUAGES_MASK)
			has_default_lang = 1;
		else {
			count = popcnt_64(chunk_attr->language_mask);
			if (count >= PLAYGO_LANG_USER_00)
				continue;
			for (j = 0; j < COUNT_OF(s_languages); ++j) {
				lang = s_languages + j;
				if (has_language(chunk_attr->language_mask, lang->code))
					lang_counts[lang->code]++;
			}
		}
	}

	if (has_default_lang) {
		lang = playgo_get_lang_by_code(PLAYGO_LANG_ENGLISH_US);
		assert(lang != NULL);

		utstring_printf(supported_langs_str, "%s%s", first ? "" : " ", lang->iso2 ? lang->iso2 : lang->iso1);
		utstring_printf(def_lang_str, "%s", "en"); // XXX: always use English as default language

		first = 0;
	}

	for (i = 0, count = 0; i < COUNT_OF(lang_counts); ++i) {
		lang = playgo_get_lang_by_code(i);
		if (!lang || lang_counts[i] == 0)
			continue;

		utstring_printf(supported_langs_str, "%s%s", first ? "" : " ", lang->iso2 ? lang->iso2 : lang->iso1);
		++count;

		first = 0;
	}

	if (use_all_langs)
		*use_all_langs = 0;

	if (count == 1 && strcmp(utstring_body(supported_langs_str), "en") == 0) {
		utstring_clear(supported_langs_str);

		if (use_all_langs)
			*use_all_langs = 1;
	}

	status = 1;

error:
	return status;
}

int playgo_get_chunk_languages(struct playgo* plgo, size_t index, UT_string* langs_str) {
	struct playgo_chunk_attr_desc* chunk_attr;
	const struct playgo_lang_desc* lang;
	unsigned int first, count;
	uint64_t i;
	int status = 0;

	assert(plgo != NULL);
	assert(index < plgo->chunk_count);
	assert(langs_str != NULL);

	utstring_clear(langs_str);

	chunk_attr = plgo->chunk_attrs + index;

	if (chunk_attr->language_mask != PLAYGO_ALL_LANGUAGES_MASK) {
		count = popcnt_64(chunk_attr->language_mask);
		if (count < PLAYGO_LANG_USER_00) {
			for (i = 0, first = 1; i < COUNT_OF(s_languages); ++i) {
				lang = s_languages + i;

				if (has_language(chunk_attr->language_mask, lang->code)) {
					utstring_printf(langs_str, "%s%s", first ? "" : " ", lang->iso2 ? lang->iso2 : lang->iso1);

					first = 0;
				}
			}
		}
	}

	status = 1;

error:
	return status;
}

void playgo_dump(struct playgo* plgo) {
	struct playgo_scenario_attr_desc* scenario_attr;
	struct playgo_chunk_attr_desc* chunk_attr;
	struct playgo_mchunk_attr_desc* mchunk_attr;
	char type_str[32];
	char req_locus_str[32];
	uint64_t total_mchunk_size, total_inner_mchunk_size;
	unsigned int idx;
	size_t i, j;

	assert(plgo != NULL);

	info(
		"Playgo:\n"
		"  Version: 0x%04X.0x%04X\n"
		"  File size: 0x%X\n"
		"  Attributes: 0x%04X\n"
		"  Image count: %u\n"
		"  Disc count: %u\n"
		"  Scenario count: %u\n"
		"  Chunk count: %u\n"
		"  Mchunk count: %u\n"
		"  Layer bitmap: 0x%04X\n"
		"  SDK version: 0x%08X\n"
		"  Default scenario id: %u\n"
		"  Content id: %s\n",

		plgo->version_major, plgo->version_minor,
		plgo->file_size,
		plgo->attrib,
		plgo->image_count, plgo->disc_count, plgo->scenario_count, plgo->chunk_count, plgo->mchunk_count,
		plgo->layer_bmp,
		plgo->sdk_version,
		plgo->default_scenario_id,
		plgo->content_id
	);

	if (plgo->scenario_count > 0) {
		info("  Scenarios:");
		for (i = 0; i < plgo->scenario_count; ++i) {
			scenario_attr = plgo->scenario_attrs + i;

			if (scenario_attr->type == PLAYGO_SCENARIO_TYPE_SP)
				strncpy(type_str, "sp", sizeof(type_str));
			else if (scenario_attr->type == PLAYGO_SCENARIO_TYPE_MP)
				strncpy(type_str, "mp", sizeof(type_str));
			else if (scenario_attr->type >= PLAYGO_SCENARIO_TYPE_USER_00)
				snprintf(type_str, sizeof(type_str), "User-defined Scenario #%u", scenario_attr->type - PLAYGO_SCENARIO_TYPE_USER_00 + 1);
			else
				snprintf(type_str, sizeof(type_str), "%u", scenario_attr->type);

			info(
					"    Scenario #%02" PRIuMAX ":\n"
					"      Label: %s\n"
					"      Type: %s\n"
					"      Initial chunk count: %u\n"
					"      Chunk count: %u",

					(uintmax_t)i,
					scenario_attr->label,
					type_str,
					scenario_attr->initial_chunk_count,
					scenario_attr->chunk_count
			);

#if 1
			if (scenario_attr->chunk_count > 0) {
				info("      Chunk list:");
				for (j = 0; j < scenario_attr->chunk_count; ++j)
					info("        %u", scenario_attr->chunks[j]);
			}
#endif

			info("");
		}
	}

	if (plgo->chunk_count > 0) {
		info("  Chunks:");
		for (i = 0; i < plgo->chunk_count; ++i) {
			chunk_attr = plgo->chunk_attrs + i;

			if (chunk_attr->req_locus == PLAYGO_LOCUS_NOT_DOWNLOADED)
				snprintf(req_locus_str, sizeof(req_locus_str), "not downloaded (%u)", chunk_attr->req_locus);
			else if (chunk_attr->req_locus == PLAYGO_LOCUS_LOCAL_SLOW)
				snprintf(req_locus_str, sizeof(req_locus_str), "slow (%u)", chunk_attr->req_locus);
			else if (chunk_attr->req_locus == PLAYGO_LOCUS_LOCAL_FAST)
				snprintf(req_locus_str, sizeof(req_locus_str), "fast (%u)", chunk_attr->req_locus);
			else
				snprintf(req_locus_str, sizeof(req_locus_str), "%u", chunk_attr->req_locus);

			info(
				"    Chunk #%04" PRIuMAX ":\n"
				"      Flag: 0x%02X\n"
				"      Label: %s\n"
				"      Disc: %u\n"
				"      Layer: %u\n"
				"      Image: %u\n"
				"      Req locus: %s\n"
				"      Mchunk count: %u\n"
				"      Language mask: 0x%016" PRIX64,

				(uintmax_t)i,
				chunk_attr->flag,
				chunk_attr->label,
				chunk_attr->disc_no,
				chunk_attr->layer_no,
				chunk_attr->image_no,
				req_locus_str,
				chunk_attr->mchunk_count,
				chunk_attr->language_mask
			);

			for (j = 0, total_mchunk_size = 0, total_inner_mchunk_size = 0; j < chunk_attr->mchunk_count; ++j) {
				idx = chunk_attr->mchunks[j];
				mchunk_attr = plgo->mchunk_attrs + idx;
				total_mchunk_size += mchunk_attr->size;
				mchunk_attr = plgo->inner_mchunk_attrs + idx;
				total_inner_mchunk_size += mchunk_attr->size;
			}

			info("      Total mchunk size: 0x%" PRIX64, total_mchunk_size);
			info("      Total inner mchunk size: 0x%" PRIX64, total_inner_mchunk_size);

#if 1
			if (chunk_attr->mchunk_count > 0) {
				info("      Mchunk list:");
				for (j = 0; j < chunk_attr->mchunk_count; ++j)
					info("        %u", chunk_attr->mchunks[j]);
			}
#endif

			info("");
		}
	}

	if (plgo->mchunk_count > 0) {
		info("  Mchunks:");
		for (i = 0; i < plgo->mchunk_count; ++i) {
			mchunk_attr = plgo->mchunk_attrs + i;

			info(
				"    Mchunk #%04" PRIuMAX ":\n"
				"      Image: %u\n"
				"      Offset: 0x%" PRIX64 "\n"
				"      Size: 0x%" PRIX64,

				(uintmax_t)i,
				mchunk_attr->image_no,
				mchunk_attr->offset,
				mchunk_attr->size
			);

			info("");
		}
	}

	if (plgo->mchunk_count > 0) {
		info("  Inner mchunks:");
		for (i = 0; i < plgo->mchunk_count; ++i) {
			mchunk_attr = plgo->inner_mchunk_attrs + i;

			info(
				"    Inner mchunk #%04" PRIuMAX ":\n"
				"      Offset: 0x%" PRIX64 "\n"
				"      Size: 0x%" PRIX64,

				(uintmax_t)i,
				mchunk_attr->offset,
				mchunk_attr->size
			);

			info("");
		}
	}
}

const struct playgo_lang_desc* playgo_get_lang_by_code(unsigned int code) {
	const struct playgo_lang_desc* lang;
	size_t i;

	for (i = 0; i < COUNT_OF(s_languages); ++i) {
		lang = s_languages + i;

		if (lang->code == code)
			return lang;
	}

	return NULL;
}

int playgo_get_chunks(struct playgo* plgo, uint64_t offset, uint64_t size, uint16_t** chunks, size_t* nchunks) {
	UT_array* list = NULL;
	uint16_t* src_chunks;
	uint16_t* dst_chunks;
	size_t count;
	struct playgo_chunk_attr_desc* chunk_attr;
	struct playgo_mchunk_attr_desc* mchunk_attr;
	uint16_t idx;
	size_t i, j;
	int status = 0;

	assert(plgo != NULL);

	/* TODO: check if size is needed */
	UNUSED(size);

	if (plgo->chunk_count == 0 || plgo->mchunk_count == 0) {
		count = 0;
		goto done;
	}

	utarray_new(list, &ut_uint16_icd);
	if (!list) {
		warning("Unable to allocate memory for chunks.");
		goto error;
	}

	for (i = 0; i < plgo->chunk_count; ++i) {
		chunk_attr = plgo->chunk_attrs + i;

		for (j = 0; j < chunk_attr->mchunk_count; ++j) {
			mchunk_attr = plgo->mchunk_attrs + chunk_attr->mchunks[j];

			if (offset >= mchunk_attr->offset && offset < (mchunk_attr->offset + mchunk_attr->size)) {
				idx = (uint16_t)i;
				utarray_push_back(list, &idx);
			}
		}
	}

done:
	count = list ? utarray_len(list) : 0;

	if (chunks) {
		if (list) {
			src_chunks = (uint16_t*)utarray_front(list);
			if (src_chunks) {
				dst_chunks = (uint16_t*)malloc(sizeof(*dst_chunks) * count);
				if (!dst_chunks) {
					warning("Unable to allocate memory for chunks.");
					goto error;
				}
				memcpy(dst_chunks, src_chunks, sizeof(*dst_chunks) * count);
				*chunks = dst_chunks;
			} else {
				goto no_chunks;
			}
		} else {
no_chunks:
			*chunks = NULL;
			count = 0;
		}
	}

	if (nchunks)
		*nchunks = count;

	status = 1;

error:
	if (list)
		utarray_free(list);

	return status;
}

static void playgo_cleanup(struct playgo* plgo) {
	struct playgo_scenario_attr_desc* scenario_attr;
	struct playgo_chunk_attr_desc* chunk_attr;
	size_t i;

	assert(plgo != NULL);

	if (plgo->scenario_attrs) {
		for (i = 0; i < plgo->scenario_count; ++i) {
			scenario_attr = plgo->scenario_attrs + i;

			if (scenario_attr->chunks) {
				free(scenario_attr->chunks);
				scenario_attr->chunks = NULL;
			}

			if (scenario_attr->label) {
				free(scenario_attr->label);
				scenario_attr->label = NULL;
			}
		}

		free(plgo->scenario_attrs);
		plgo->scenario_attrs = NULL;
	}

	if (plgo->chunk_attrs) {
		for (i = 0; i < plgo->chunk_count; ++i) {
			chunk_attr = plgo->chunk_attrs + i;

			if (chunk_attr->mchunks) {
				free(chunk_attr->mchunks);
				chunk_attr->mchunks = NULL;
			}

			if (chunk_attr->label) {
				free(chunk_attr->label);
				chunk_attr->label = NULL;
			}
		}

		free(plgo->chunk_attrs);
		plgo->chunk_attrs = NULL;
	}

	if (plgo->mchunk_attrs) {
		free(plgo->mchunk_attrs);
		plgo->mchunk_attrs = NULL;
	}

	if (plgo->inner_mchunk_attrs) {
		free(plgo->inner_mchunk_attrs);
		plgo->inner_mchunk_attrs = NULL;
	}

	memset(plgo, 0, sizeof(*plgo));
}

static int parse_scenario_attr(struct playgo* plgo, size_t index, const struct playgo_scenario_attr_entry* entry, const uint16_t* chunks, size_t chunks_size, const char* labels, size_t labels_size) {
	struct playgo_scenario_attr_desc* desc;
	const uint16_t* chunks_src;
	uint16_t* chunks_dst;
	uint32_t chunks_offset;
	uint32_t label_offset;
	size_t i;
	int status = 0;

	assert(plgo != NULL);
	assert(index < plgo->scenario_count);
	assert(entry != NULL);
	assert(labels != NULL);

	chunks_offset = LE32(entry->chunks_offset);
	if (chunks_offset >= chunks_size) {
		warning("Invalid scenario chunks offset.");
		goto error;
	}

	label_offset = LE32(entry->label_offset);
	if (label_offset >= labels_size) {
		warning("Invalid scenario label offset.");
		goto error;
	}

	desc = plgo->scenario_attrs + index;
	{
		desc->type = LE32(entry->type);
		desc->initial_chunk_count = LE16(entry->initial_chunk_count);
		desc->chunk_count = LE16(entry->chunk_count);

		desc->chunks = (uint16_t*)malloc(sizeof(*desc->chunks) * desc->chunk_count);
		if (!desc->chunks) {
			warning("Unable to allocate memory for chunks.");
			goto error;
		}
		memset(desc->chunks, 0, sizeof(*desc->chunks) * desc->chunk_count);
		{
			chunks_src = chunks + chunks_offset / sizeof(*chunks);
			chunks_dst = desc->chunks;
			for (i = 0; i < desc->chunk_count; ++i)
				*chunks_dst++ = LE16(*chunks_src++);
		}

		desc->label = strdup(labels + label_offset);
		if (!desc->label) {
			warning("Unable to allocate memory for scenario label.");
			goto error;
		}
	}

	status = 1;

error:
	return status;
}

static int parse_chunk_attr(struct playgo* plgo, size_t index, const struct playgo_chunk_attr_entry* entry, const uint16_t* mchunks, size_t mchunks_size, const char* labels, size_t labels_size) {
	struct playgo_chunk_attr_desc* desc;
	const uint16_t* mchunks_src;
	uint16_t* mchunks_dst;
	uint32_t mchunks_offset;
	uint32_t label_offset;
	size_t i;
	int status = 0;

	assert(plgo != NULL);
	assert(index < plgo->chunk_count);
	assert(entry != NULL);
	assert(labels != NULL);

#if 0
	if ((entry->info2 & 0x8) != 0)
		goto error;
#endif

	// XXX: EP0082-CUSA01435_00-LIFEISSTRANGE001 have mchunks_offset=mchunks_size=0x2, why?
	mchunks_offset = LE32(entry->mchunks_offset);
	if (mchunks_offset > mchunks_size) {
		warning("Invalid chunk mchunks offset.");
		goto error;
	}

	label_offset = LE32(entry->label_offset);
	if (label_offset >= labels_size) {
		warning("Invalid chunk label offset.");
		goto error;
	}

	desc = plgo->chunk_attrs + index;
	{
		desc->flag = entry->flag;
		desc->image_no = (entry->image_disc_layer_no >> 4) & 0xF;
		desc->disc_no = (entry->image_disc_layer_no >> 2) & 0x3;
		desc->layer_no = entry->image_disc_layer_no & 0x3;
		desc->req_locus = entry->req_locus;

		desc->language_mask = LE64(entry->language_mask);

		desc->mchunk_count = LE16(entry->mchunk_count);
		if (desc->mchunk_count > PLAYGO_MAX_MCHUNKS) {
			warning("Too much mchunks in chunk.");
			goto error;
		}
		desc->mchunks = (uint16_t*)malloc(sizeof(*desc->mchunks) * desc->mchunk_count);
		if (!desc->mchunks) {
			warning("Unable to allocate memory for mchunks.");
			goto error;
		}
		memset(desc->mchunks, 0, sizeof(*desc->mchunks) * desc->mchunk_count);
		{
			mchunks_src = mchunks + mchunks_offset / sizeof(*mchunks);
			mchunks_dst = desc->mchunks;
			for (i = 0; i < desc->mchunk_count; ++i)
				*mchunks_dst++ = LE16(*mchunks_src++);
		}

		desc->label = strdup(labels + label_offset);
		if (!desc->label) {
			warning("Unable to allocate memory for chunk label.");
			goto error;
		}
	}

	status = 1;

error:
	return status;
}

static int parse_mchunk_attr(struct playgo* plgo, size_t index, const struct playgo_mchunk_attr_entry* entry, int is_inner) {
	struct playgo_mchunk_attr_desc* desc;
	union playgo_chunk_loc loc;
	union playgo_chunk_size size;
	int status = 0;

	assert(plgo != NULL);
	assert(index < plgo->mchunk_count);
	assert(entry != NULL);

	desc = is_inner ? (plgo->inner_mchunk_attrs + index) : (plgo->mchunk_attrs + index);
	{
		loc.raw = LE64(entry->loc.raw);
		size.raw = LE64(entry->size.raw);

		desc->image_no = is_inner ? 0 : loc.image_no;
		desc->offset = loc.offset;
		desc->size = size.size;
	}

	status = 1;

error:
	return status;
}

static inline int has_language(uint64_t language_mask, unsigned int code) {
	uint64_t bit;
	uint64_t mask;

	bit = UINT64_C(1) << (PLAYGO_MAX_LANGUAGES - code - 1);
	mask = (language_mask & bit);

	return !!mask;
}
