#include "pkg.h"
#include "mapped_file.h"
#include "crypto.h"
#include "keys.h"
#include "keymgr.h"
#include "util.h"

static int pfs_get_size_cb(void* arg, uint64_t* size);
static int pfs_get_outer_location_cb(void* arg, uint64_t offset, uint64_t* outer_offset);
static int pfs_get_offset_size_cb(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed);
static int pfs_seek_cb(void* arg, uint64_t offset);
static int pfs_read_cb(void* arg, void* data, uint64_t data_size);
static int pfs_write_cb(void* arg, void* data, uint64_t data_size);
static int pfs_can_seek_cb(void* arg, uint64_t offset);
static int pfs_can_read_cb(void* arg, uint64_t data_size);
static int pfs_can_write_cb(void* arg, uint64_t data_size);

static int pfs_inner_get_size_cb(void* arg, uint64_t* size);
static int pfs_inner_get_outer_location_cb(void* arg, uint64_t offset, uint64_t* outer_offset);
static int pfs_inner_get_offset_size_cb(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed);
static int pfs_inner_seek_cb(void* arg, uint64_t offset);
static int pfs_inner_read_cb(void* arg, void* data, uint64_t data_size);
static int pfs_inner_write_cb(void* arg, void* data, uint64_t data_size);
static int pfs_inner_can_seek_cb(void* arg, uint64_t offset);
static int pfs_inner_can_read_cb(void* arg, uint64_t data_size);
static int pfs_inner_can_write_cb(void* arg, uint64_t data_size);

static const struct {
	unsigned int id;
	const char* name;
	int is_extra;
} s_entry_names[] = {
	{ PKG_ENTRY_ID__DIGESTS, ".digests", 1 },
	{ PKG_ENTRY_ID__ENTRY_KEYS, ".entry_keys", 1 },
	{ PKG_ENTRY_ID__IMAGE_KEY, ".image_key", 1 },
	{ PKG_ENTRY_ID__GENERAL_DIGESTS, ".general_digests", 1 },
	{ PKG_ENTRY_ID__METAS, ".metas", 1 },
	{ PKG_ENTRY_ID__ENTRY_NAMES, ".entry_names", 1 },

	{ PKG_ENTRY_ID__LICENSE_DAT, "license.dat", 1 },
	{ PKG_ENTRY_ID__LICENSE_INFO, "license.info", 1 },
	{ PKG_ENTRY_ID__NPTITLE_DAT, "nptitle.dat", 0 },
	{ PKG_ENTRY_ID__NPBIND_DAT, "npbind.dat", 0 },
	{ PKG_ENTRY_ID__SELFINFO_DAT, "selfinfo.dat", 1 },
	{ PKG_ENTRY_ID__IMAGEINFO_DAT, "imageinfo.dat", 1 },
	{ PKG_ENTRY_ID__TARGET_DELTAINFO_DAT, "target-deltainfo.dat", 1 },
	{ PKG_ENTRY_ID__ORIGIN_DELTAINFO_DAT, "origin-deltainfo.dat", 1 },
	{ PKG_ENTRY_ID__PSRESERVED_DAT, "psreserved.dat", 1 },
	{ PKG_ENTRY_ID__PARAM_SFO, "param.sfo", 0 },
	{ PKG_ENTRY_ID__PLAYGO_CHUNK_DAT, "playgo-chunk.dat", 1 },
	{ PKG_ENTRY_ID__PLAYGO_CHUNK_SHA, "playgo-chunk.sha", 1 },
	{ PKG_ENTRY_ID__PLAYGO_MANIFEST_XML, "playgo-manifest.xml", 1 },
	{ PKG_ENTRY_ID__PRONUNCIATION_XML, "pronunciation.xml", 0 },
	{ PKG_ENTRY_ID__PRONUNCIATION_SIG, "pronunciation.sig", 0 },
	{ PKG_ENTRY_ID__PIC1_PNG, "pic1.png", 0 },
	{ PKG_ENTRY_ID__PUBTOOLINFO_DAT, "pubtoolinfo.dat", 1 },
	{ PKG_ENTRY_ID__APP__PLAYGO_CHUNK_DAT, "app/playgo-chunk.dat", 1 },
	{ PKG_ENTRY_ID__APP__PLAYGO_CHUNK_SHA, "app/playgo-chunk.sha", 1 },
	{ PKG_ENTRY_ID__APP__PLAYGO_MANIFEST_XML, "app/playgo-manifest.xml", 1 },
	{ PKG_ENTRY_ID__SHAREPARAM_JSON, "shareparam.json", 0 },
	{ PKG_ENTRY_ID__SHAREOVERLAYIMAGE_PNG, "shareoverlayimage.png", 0 },
	{ PKG_ENTRY_ID__SAVE_DATA_PNG, "save_data.png", 0 },
	{ PKG_ENTRY_ID__SHAREPRIVACYGUARDIMAGE_PNG, "shareprivacyguardimage.png", 0 },
	{ PKG_ENTRY_ID__ICON0_PNG, "icon0.png", 0 },
	{ PKG_ENTRY_ID__ICON0_00_PNG, "icon0_00.png", 0 },
	{ PKG_ENTRY_ID__ICON0_01_PNG, "icon0_01.png", 0 },
	{ PKG_ENTRY_ID__ICON0_02_PNG, "icon0_02.png", 0 },
	{ PKG_ENTRY_ID__ICON0_03_PNG, "icon0_03.png", 0 },
	{ PKG_ENTRY_ID__ICON0_04_PNG, "icon0_04.png", 0 },
	{ PKG_ENTRY_ID__ICON0_05_PNG, "icon0_05.png", 0 },
	{ PKG_ENTRY_ID__ICON0_06_PNG, "icon0_06.png", 0 },
	{ PKG_ENTRY_ID__ICON0_07_PNG, "icon0_07.png", 0 },
	{ PKG_ENTRY_ID__ICON0_08_PNG, "icon0_08.png", 0 },
	{ PKG_ENTRY_ID__ICON0_09_PNG, "icon0_09.png", 0 },
	{ PKG_ENTRY_ID__ICON0_10_PNG, "icon0_10.png", 0 },
	{ PKG_ENTRY_ID__ICON0_11_PNG, "icon0_11.png", 0 },
	{ PKG_ENTRY_ID__ICON0_12_PNG, "icon0_12.png", 0 },
	{ PKG_ENTRY_ID__ICON0_13_PNG, "icon0_13.png", 0 },
	{ PKG_ENTRY_ID__ICON0_14_PNG, "icon0_14.png", 0 },
	{ PKG_ENTRY_ID__ICON0_15_PNG, "icon0_15.png", 0 },
	{ PKG_ENTRY_ID__ICON0_16_PNG, "icon0_16.png", 0 },
	{ PKG_ENTRY_ID__ICON0_17_PNG, "icon0_17.png", 0 },
	{ PKG_ENTRY_ID__ICON0_18_PNG, "icon0_18.png", 0 },
	{ PKG_ENTRY_ID__ICON0_19_PNG, "icon0_19.png", 0 },
	{ PKG_ENTRY_ID__ICON0_20_PNG, "icon0_20.png", 0 },
	{ PKG_ENTRY_ID__ICON0_21_PNG, "icon0_21.png", 0 },
	{ PKG_ENTRY_ID__ICON0_22_PNG, "icon0_22.png", 0 },
	{ PKG_ENTRY_ID__ICON0_23_PNG, "icon0_23.png", 0 },
	{ PKG_ENTRY_ID__ICON0_24_PNG, "icon0_24.png", 0 },
	{ PKG_ENTRY_ID__ICON0_25_PNG, "icon0_25.png", 0 },
	{ PKG_ENTRY_ID__ICON0_26_PNG, "icon0_26.png", 0 },
	{ PKG_ENTRY_ID__ICON0_27_PNG, "icon0_27.png", 0 },
	{ PKG_ENTRY_ID__ICON0_28_PNG, "icon0_28.png", 0 },
	{ PKG_ENTRY_ID__ICON0_29_PNG, "icon0_29.png", 0 },
	{ PKG_ENTRY_ID__ICON0_30_PNG, "icon0_30.png", 0 },
	{ PKG_ENTRY_ID__PIC0_PNG, "pic0.png", 0 },
	{ PKG_ENTRY_ID__SND0_AT9, "snd0.at9", 0 },
	{ PKG_ENTRY_ID__PIC1_00_PNG, "pic1_00.png", 0 },
	{ PKG_ENTRY_ID__PIC1_01_PNG, "pic1_01.png", 0 },
	{ PKG_ENTRY_ID__PIC1_02_PNG, "pic1_02.png", 0 },
	{ PKG_ENTRY_ID__PIC1_03_PNG, "pic1_03.png", 0 },
	{ PKG_ENTRY_ID__PIC1_04_PNG, "pic1_04.png", 0 },
	{ PKG_ENTRY_ID__PIC1_05_PNG, "pic1_05.png", 0 },
	{ PKG_ENTRY_ID__PIC1_06_PNG, "pic1_06.png", 0 },
	{ PKG_ENTRY_ID__PIC1_07_PNG, "pic1_07.png", 0 },
	{ PKG_ENTRY_ID__PIC1_08_PNG, "pic1_08.png", 0 },
	{ PKG_ENTRY_ID__PIC1_09_PNG, "pic1_09.png", 0 },
	{ PKG_ENTRY_ID__PIC1_10_PNG, "pic1_10.png", 0 },
	{ PKG_ENTRY_ID__PIC1_11_PNG, "pic1_11.png", 0 },
	{ PKG_ENTRY_ID__PIC1_12_PNG, "pic1_12.png", 0 },
	{ PKG_ENTRY_ID__PIC1_13_PNG, "pic1_13.png", 0 },
	{ PKG_ENTRY_ID__PIC1_14_PNG, "pic1_14.png", 0 },
	{ PKG_ENTRY_ID__PIC1_15_PNG, "pic1_15.png", 0 },
	{ PKG_ENTRY_ID__PIC1_16_PNG, "pic1_16.png", 0 },
	{ PKG_ENTRY_ID__PIC1_17_PNG, "pic1_17.png", 0 },
	{ PKG_ENTRY_ID__PIC1_18_PNG, "pic1_18.png", 0 },
	{ PKG_ENTRY_ID__PIC1_19_PNG, "pic1_19.png", 0 },
	{ PKG_ENTRY_ID__PIC1_20_PNG, "pic1_20.png", 0 },
	{ PKG_ENTRY_ID__PIC1_21_PNG, "pic1_21.png", 0 },
	{ PKG_ENTRY_ID__PIC1_22_PNG, "pic1_22.png", 0 },
	{ PKG_ENTRY_ID__PIC1_23_PNG, "pic1_23.png", 0 },
	{ PKG_ENTRY_ID__PIC1_24_PNG, "pic1_24.png", 0 },
	{ PKG_ENTRY_ID__PIC1_25_PNG, "pic1_25.png", 0 },
	{ PKG_ENTRY_ID__PIC1_26_PNG, "pic1_26.png", 0 },
	{ PKG_ENTRY_ID__PIC1_27_PNG, "pic1_27.png", 0 },
	{ PKG_ENTRY_ID__PIC1_28_PNG, "pic1_28.png", 0 },
	{ PKG_ENTRY_ID__PIC1_29_PNG, "pic1_29.png", 0 },
	{ PKG_ENTRY_ID__PIC1_30_PNG, "pic1_30.png", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_XML, "changeinfo/changeinfo.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_00_XML, "changeinfo/changeinfo_00.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_01_XML, "changeinfo/changeinfo_01.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_02_XML, "changeinfo/changeinfo_02.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_03_XML, "changeinfo/changeinfo_03.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_04_XML, "changeinfo/changeinfo_04.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_05_XML, "changeinfo/changeinfo_05.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_06_XML, "changeinfo/changeinfo_06.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_07_XML, "changeinfo/changeinfo_07.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_08_XML, "changeinfo/changeinfo_08.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_09_XML, "changeinfo/changeinfo_09.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_10_XML, "changeinfo/changeinfo_10.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_11_XML, "changeinfo/changeinfo_11.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_12_XML, "changeinfo/changeinfo_12.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_13_XML, "changeinfo/changeinfo_13.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_14_XML, "changeinfo/changeinfo_14.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_15_XML, "changeinfo/changeinfo_15.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_16_XML, "changeinfo/changeinfo_16.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_17_XML, "changeinfo/changeinfo_17.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_18_XML, "changeinfo/changeinfo_18.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_19_XML, "changeinfo/changeinfo_19.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_20_XML, "changeinfo/changeinfo_20.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_21_XML, "changeinfo/changeinfo_21.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_22_XML, "changeinfo/changeinfo_22.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_23_XML, "changeinfo/changeinfo_23.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_24_XML, "changeinfo/changeinfo_24.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_25_XML, "changeinfo/changeinfo_25.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_26_XML, "changeinfo/changeinfo_26.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_27_XML, "changeinfo/changeinfo_27.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_28_XML, "changeinfo/changeinfo_28.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_29_XML, "changeinfo/changeinfo_29.xml", 0 },
	{ PKG_ENTRY_ID__CHANGEINFO__CHANGEINFO_30_XML, "changeinfo/changeinfo_30.xml", 0 },
	{ PKG_ENTRY_ID__ICON0_DDS, "icon0.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_00_DDS, "icon0_00.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_01_DDS, "icon0_01.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_02_DDS, "icon0_02.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_03_DDS, "icon0_03.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_04_DDS, "icon0_04.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_05_DDS, "icon0_05.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_06_DDS, "icon0_06.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_07_DDS, "icon0_07.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_08_DDS, "icon0_08.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_09_DDS, "icon0_09.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_10_DDS, "icon0_10.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_11_DDS, "icon0_11.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_12_DDS, "icon0_12.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_13_DDS, "icon0_13.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_14_DDS, "icon0_14.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_15_DDS, "icon0_15.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_16_DDS, "icon0_16.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_17_DDS, "icon0_17.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_18_DDS, "icon0_18.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_19_DDS, "icon0_19.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_20_DDS, "icon0_20.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_21_DDS, "icon0_21.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_22_DDS, "icon0_22.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_23_DDS, "icon0_23.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_24_DDS, "icon0_24.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_25_DDS, "icon0_25.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_26_DDS, "icon0_26.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_27_DDS, "icon0_27.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_28_DDS, "icon0_28.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_29_DDS, "icon0_29.dds", 1 },
	{ PKG_ENTRY_ID__ICON0_30_DDS, "icon0_30.dds", 1 },
	{ PKG_ENTRY_ID__PIC0_DDS, "pic0.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_DDS, "pic1.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_00_DDS, "pic1_00.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_01_DDS, "pic1_01.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_02_DDS, "pic1_02.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_03_DDS, "pic1_03.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_04_DDS, "pic1_04.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_05_DDS, "pic1_05.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_06_DDS, "pic1_06.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_07_DDS, "pic1_07.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_08_DDS, "pic1_08.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_09_DDS, "pic1_09.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_10_DDS, "pic1_10.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_11_DDS, "pic1_11.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_12_DDS, "pic1_12.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_13_DDS, "pic1_13.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_14_DDS, "pic1_14.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_15_DDS, "pic1_15.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_16_DDS, "pic1_16.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_17_DDS, "pic1_17.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_18_DDS, "pic1_18.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_19_DDS, "pic1_19.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_20_DDS, "pic1_20.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_21_DDS, "pic1_21.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_22_DDS, "pic1_22.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_23_DDS, "pic1_23.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_24_DDS, "pic1_24.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_25_DDS, "pic1_25.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_26_DDS, "pic1_26.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_27_DDS, "pic1_27.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_28_DDS, "pic1_28.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_29_DDS, "pic1_29.dds", 1 },
	{ PKG_ENTRY_ID__PIC1_30_DDS, "pic1_30.dds", 1 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY00_TRP, "trophy/trophy00.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY01_TRP, "trophy/trophy01.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY02_TRP, "trophy/trophy02.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY03_TRP, "trophy/trophy03.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY04_TRP, "trophy/trophy04.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY05_TRP, "trophy/trophy05.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY06_TRP, "trophy/trophy06.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY07_TRP, "trophy/trophy07.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY08_TRP, "trophy/trophy08.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY09_TRP, "trophy/trophy09.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY10_TRP, "trophy/trophy10.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY11_TRP, "trophy/trophy11.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY12_TRP, "trophy/trophy12.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY13_TRP, "trophy/trophy13.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY14_TRP, "trophy/trophy14.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY15_TRP, "trophy/trophy15.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY16_TRP, "trophy/trophy16.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY17_TRP, "trophy/trophy17.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY18_TRP, "trophy/trophy18.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY19_TRP, "trophy/trophy19.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY20_TRP, "trophy/trophy20.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY21_TRP, "trophy/trophy21.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY22_TRP, "trophy/trophy22.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY23_TRP, "trophy/trophy23.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY24_TRP, "trophy/trophy24.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY25_TRP, "trophy/trophy25.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY26_TRP, "trophy/trophy26.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY27_TRP, "trophy/trophy27.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY28_TRP, "trophy/trophy28.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY29_TRP, "trophy/trophy29.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY30_TRP, "trophy/trophy30.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY31_TRP, "trophy/trophy31.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY32_TRP, "trophy/trophy32.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY33_TRP, "trophy/trophy33.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY34_TRP, "trophy/trophy34.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY35_TRP, "trophy/trophy35.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY36_TRP, "trophy/trophy36.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY37_TRP, "trophy/trophy37.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY38_TRP, "trophy/trophy38.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY39_TRP, "trophy/trophy39.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY40_TRP, "trophy/trophy40.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY41_TRP, "trophy/trophy41.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY42_TRP, "trophy/trophy42.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY43_TRP, "trophy/trophy43.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY44_TRP, "trophy/trophy44.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY45_TRP, "trophy/trophy45.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY46_TRP, "trophy/trophy46.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY47_TRP, "trophy/trophy47.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY48_TRP, "trophy/trophy48.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY49_TRP, "trophy/trophy49.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY50_TRP, "trophy/trophy50.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY51_TRP, "trophy/trophy51.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY52_TRP, "trophy/trophy52.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY53_TRP, "trophy/trophy53.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY54_TRP, "trophy/trophy54.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY55_TRP, "trophy/trophy55.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY56_TRP, "trophy/trophy56.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY57_TRP, "trophy/trophy57.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY58_TRP, "trophy/trophy58.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY59_TRP, "trophy/trophy59.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY60_TRP, "trophy/trophy60.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY61_TRP, "trophy/trophy61.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY62_TRP, "trophy/trophy62.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY63_TRP, "trophy/trophy63.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY64_TRP, "trophy/trophy64.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY65_TRP, "trophy/trophy65.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY66_TRP, "trophy/trophy66.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY67_TRP, "trophy/trophy67.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY68_TRP, "trophy/trophy68.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY69_TRP, "trophy/trophy69.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY70_TRP, "trophy/trophy70.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY71_TRP, "trophy/trophy71.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY72_TRP, "trophy/trophy72.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY73_TRP, "trophy/trophy73.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY74_TRP, "trophy/trophy74.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY75_TRP, "trophy/trophy75.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY76_TRP, "trophy/trophy76.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY77_TRP, "trophy/trophy77.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY78_TRP, "trophy/trophy78.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY79_TRP, "trophy/trophy79.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY80_TRP, "trophy/trophy80.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY81_TRP, "trophy/trophy81.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY82_TRP, "trophy/trophy82.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY83_TRP, "trophy/trophy83.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY84_TRP, "trophy/trophy84.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY85_TRP, "trophy/trophy85.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY86_TRP, "trophy/trophy86.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY87_TRP, "trophy/trophy87.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY88_TRP, "trophy/trophy88.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY89_TRP, "trophy/trophy89.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY90_TRP, "trophy/trophy90.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY91_TRP, "trophy/trophy91.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY92_TRP, "trophy/trophy92.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY93_TRP, "trophy/trophy93.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY94_TRP, "trophy/trophy94.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY95_TRP, "trophy/trophy95.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY96_TRP, "trophy/trophy96.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY97_TRP, "trophy/trophy97.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY98_TRP, "trophy/trophy98.trp", 0 },
	{ PKG_ENTRY_ID__TROPHY__TROPHY99_TRP, "trophy/trophy99.trp", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__001_PNG, "keymap_rp/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__002_PNG, "keymap_rp/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__003_PNG, "keymap_rp/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__004_PNG, "keymap_rp/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__005_PNG, "keymap_rp/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__006_PNG, "keymap_rp/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__007_PNG, "keymap_rp/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__008_PNG, "keymap_rp/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__009_PNG, "keymap_rp/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__010_PNG, "keymap_rp/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__001_PNG, "keymap_rp/00/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__002_PNG, "keymap_rp/00/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__003_PNG, "keymap_rp/00/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__004_PNG, "keymap_rp/00/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__005_PNG, "keymap_rp/00/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__006_PNG, "keymap_rp/00/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__007_PNG, "keymap_rp/00/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__008_PNG, "keymap_rp/00/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__009_PNG, "keymap_rp/00/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__00__010_PNG, "keymap_rp/00/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__001_PNG, "keymap_rp/01/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__002_PNG, "keymap_rp/01/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__003_PNG, "keymap_rp/01/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__004_PNG, "keymap_rp/01/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__005_PNG, "keymap_rp/01/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__006_PNG, "keymap_rp/01/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__007_PNG, "keymap_rp/01/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__008_PNG, "keymap_rp/01/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__009_PNG, "keymap_rp/01/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__01__010_PNG, "keymap_rp/01/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__001_PNG, "keymap_rp/02/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__002_PNG, "keymap_rp/02/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__003_PNG, "keymap_rp/02/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__004_PNG, "keymap_rp/02/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__005_PNG, "keymap_rp/02/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__006_PNG, "keymap_rp/02/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__007_PNG, "keymap_rp/02/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__008_PNG, "keymap_rp/02/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__009_PNG, "keymap_rp/02/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__02__010_PNG, "keymap_rp/02/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__001_PNG, "keymap_rp/03/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__002_PNG, "keymap_rp/03/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__003_PNG, "keymap_rp/03/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__004_PNG, "keymap_rp/03/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__005_PNG, "keymap_rp/03/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__006_PNG, "keymap_rp/03/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__007_PNG, "keymap_rp/03/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__008_PNG, "keymap_rp/03/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__009_PNG, "keymap_rp/03/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__03__010_PNG, "keymap_rp/03/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__001_PNG, "keymap_rp/04/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__002_PNG, "keymap_rp/04/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__003_PNG, "keymap_rp/04/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__004_PNG, "keymap_rp/04/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__005_PNG, "keymap_rp/04/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__006_PNG, "keymap_rp/04/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__007_PNG, "keymap_rp/04/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__008_PNG, "keymap_rp/04/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__009_PNG, "keymap_rp/04/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__04__010_PNG, "keymap_rp/04/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__001_PNG, "keymap_rp/05/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__002_PNG, "keymap_rp/05/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__003_PNG, "keymap_rp/05/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__004_PNG, "keymap_rp/05/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__005_PNG, "keymap_rp/05/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__006_PNG, "keymap_rp/05/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__007_PNG, "keymap_rp/05/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__008_PNG, "keymap_rp/05/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__009_PNG, "keymap_rp/05/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__05__010_PNG, "keymap_rp/05/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__001_PNG, "keymap_rp/06/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__002_PNG, "keymap_rp/06/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__003_PNG, "keymap_rp/06/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__004_PNG, "keymap_rp/06/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__005_PNG, "keymap_rp/06/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__006_PNG, "keymap_rp/06/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__007_PNG, "keymap_rp/06/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__008_PNG, "keymap_rp/06/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__009_PNG, "keymap_rp/06/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__06__010_PNG, "keymap_rp/06/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__001_PNG, "keymap_rp/07/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__002_PNG, "keymap_rp/07/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__003_PNG, "keymap_rp/07/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__004_PNG, "keymap_rp/07/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__005_PNG, "keymap_rp/07/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__006_PNG, "keymap_rp/07/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__007_PNG, "keymap_rp/07/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__008_PNG, "keymap_rp/07/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__009_PNG, "keymap_rp/07/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__07__010_PNG, "keymap_rp/07/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__001_PNG, "keymap_rp/08/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__002_PNG, "keymap_rp/08/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__003_PNG, "keymap_rp/08/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__004_PNG, "keymap_rp/08/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__005_PNG, "keymap_rp/08/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__006_PNG, "keymap_rp/08/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__007_PNG, "keymap_rp/08/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__008_PNG, "keymap_rp/08/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__009_PNG, "keymap_rp/08/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__08__010_PNG, "keymap_rp/08/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__001_PNG, "keymap_rp/09/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__002_PNG, "keymap_rp/09/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__003_PNG, "keymap_rp/09/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__004_PNG, "keymap_rp/09/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__005_PNG, "keymap_rp/09/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__006_PNG, "keymap_rp/09/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__007_PNG, "keymap_rp/09/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__008_PNG, "keymap_rp/09/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__009_PNG, "keymap_rp/09/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__09__010_PNG, "keymap_rp/09/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__001_PNG, "keymap_rp/10/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__002_PNG, "keymap_rp/10/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__003_PNG, "keymap_rp/10/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__004_PNG, "keymap_rp/10/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__005_PNG, "keymap_rp/10/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__006_PNG, "keymap_rp/10/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__007_PNG, "keymap_rp/10/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__008_PNG, "keymap_rp/10/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__009_PNG, "keymap_rp/10/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__10__010_PNG, "keymap_rp/10/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__001_PNG, "keymap_rp/11/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__002_PNG, "keymap_rp/11/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__003_PNG, "keymap_rp/11/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__004_PNG, "keymap_rp/11/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__005_PNG, "keymap_rp/11/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__006_PNG, "keymap_rp/11/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__007_PNG, "keymap_rp/11/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__008_PNG, "keymap_rp/11/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__009_PNG, "keymap_rp/11/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__11__010_PNG, "keymap_rp/11/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__001_PNG, "keymap_rp/12/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__002_PNG, "keymap_rp/12/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__003_PNG, "keymap_rp/12/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__004_PNG, "keymap_rp/12/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__005_PNG, "keymap_rp/12/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__006_PNG, "keymap_rp/12/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__007_PNG, "keymap_rp/12/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__008_PNG, "keymap_rp/12/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__009_PNG, "keymap_rp/12/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__12__010_PNG, "keymap_rp/12/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__001_PNG, "keymap_rp/13/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__002_PNG, "keymap_rp/13/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__003_PNG, "keymap_rp/13/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__004_PNG, "keymap_rp/13/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__005_PNG, "keymap_rp/13/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__006_PNG, "keymap_rp/13/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__007_PNG, "keymap_rp/13/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__008_PNG, "keymap_rp/13/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__009_PNG, "keymap_rp/13/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__13__010_PNG, "keymap_rp/13/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__001_PNG, "keymap_rp/14/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__002_PNG, "keymap_rp/14/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__003_PNG, "keymap_rp/14/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__004_PNG, "keymap_rp/14/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__005_PNG, "keymap_rp/14/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__006_PNG, "keymap_rp/14/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__007_PNG, "keymap_rp/14/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__008_PNG, "keymap_rp/14/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__009_PNG, "keymap_rp/14/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__14__010_PNG, "keymap_rp/14/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__001_PNG, "keymap_rp/15/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__002_PNG, "keymap_rp/15/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__003_PNG, "keymap_rp/15/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__004_PNG, "keymap_rp/15/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__005_PNG, "keymap_rp/15/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__006_PNG, "keymap_rp/15/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__007_PNG, "keymap_rp/15/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__008_PNG, "keymap_rp/15/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__009_PNG, "keymap_rp/15/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__15__010_PNG, "keymap_rp/15/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__001_PNG, "keymap_rp/16/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__002_PNG, "keymap_rp/16/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__003_PNG, "keymap_rp/16/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__004_PNG, "keymap_rp/16/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__005_PNG, "keymap_rp/16/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__006_PNG, "keymap_rp/16/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__007_PNG, "keymap_rp/16/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__008_PNG, "keymap_rp/16/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__009_PNG, "keymap_rp/16/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__16__010_PNG, "keymap_rp/16/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__001_PNG, "keymap_rp/17/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__002_PNG, "keymap_rp/17/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__003_PNG, "keymap_rp/17/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__004_PNG, "keymap_rp/17/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__005_PNG, "keymap_rp/17/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__006_PNG, "keymap_rp/17/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__007_PNG, "keymap_rp/17/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__008_PNG, "keymap_rp/17/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__009_PNG, "keymap_rp/17/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__17__010_PNG, "keymap_rp/17/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__001_PNG, "keymap_rp/18/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__002_PNG, "keymap_rp/18/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__003_PNG, "keymap_rp/18/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__004_PNG, "keymap_rp/18/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__005_PNG, "keymap_rp/18/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__006_PNG, "keymap_rp/18/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__007_PNG, "keymap_rp/18/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__008_PNG, "keymap_rp/18/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__009_PNG, "keymap_rp/18/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__18__010_PNG, "keymap_rp/18/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__001_PNG, "keymap_rp/19/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__002_PNG, "keymap_rp/19/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__003_PNG, "keymap_rp/19/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__004_PNG, "keymap_rp/19/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__005_PNG, "keymap_rp/19/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__006_PNG, "keymap_rp/19/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__007_PNG, "keymap_rp/19/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__008_PNG, "keymap_rp/19/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__009_PNG, "keymap_rp/19/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__19__010_PNG, "keymap_rp/19/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__001_PNG, "keymap_rp/20/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__002_PNG, "keymap_rp/20/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__003_PNG, "keymap_rp/20/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__004_PNG, "keymap_rp/20/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__005_PNG, "keymap_rp/20/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__006_PNG, "keymap_rp/20/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__007_PNG, "keymap_rp/20/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__008_PNG, "keymap_rp/20/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__009_PNG, "keymap_rp/20/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__20__010_PNG, "keymap_rp/20/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__001_PNG, "keymap_rp/21/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__002_PNG, "keymap_rp/21/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__003_PNG, "keymap_rp/21/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__004_PNG, "keymap_rp/21/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__005_PNG, "keymap_rp/21/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__006_PNG, "keymap_rp/21/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__007_PNG, "keymap_rp/21/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__008_PNG, "keymap_rp/21/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__009_PNG, "keymap_rp/21/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__21__010_PNG, "keymap_rp/21/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__001_PNG, "keymap_rp/22/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__002_PNG, "keymap_rp/22/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__003_PNG, "keymap_rp/22/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__004_PNG, "keymap_rp/22/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__005_PNG, "keymap_rp/22/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__006_PNG, "keymap_rp/22/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__007_PNG, "keymap_rp/22/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__008_PNG, "keymap_rp/22/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__009_PNG, "keymap_rp/22/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__22__010_PNG, "keymap_rp/22/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__001_PNG, "keymap_rp/23/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__002_PNG, "keymap_rp/23/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__003_PNG, "keymap_rp/23/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__004_PNG, "keymap_rp/23/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__005_PNG, "keymap_rp/23/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__006_PNG, "keymap_rp/23/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__007_PNG, "keymap_rp/23/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__008_PNG, "keymap_rp/23/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__009_PNG, "keymap_rp/23/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__23__010_PNG, "keymap_rp/23/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__001_PNG, "keymap_rp/24/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__002_PNG, "keymap_rp/24/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__003_PNG, "keymap_rp/24/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__004_PNG, "keymap_rp/24/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__005_PNG, "keymap_rp/24/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__006_PNG, "keymap_rp/24/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__007_PNG, "keymap_rp/24/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__008_PNG, "keymap_rp/24/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__009_PNG, "keymap_rp/24/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__24__010_PNG, "keymap_rp/24/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__001_PNG, "keymap_rp/25/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__002_PNG, "keymap_rp/25/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__003_PNG, "keymap_rp/25/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__004_PNG, "keymap_rp/25/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__005_PNG, "keymap_rp/25/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__006_PNG, "keymap_rp/25/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__007_PNG, "keymap_rp/25/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__008_PNG, "keymap_rp/25/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__009_PNG, "keymap_rp/25/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__25__010_PNG, "keymap_rp/25/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__001_PNG, "keymap_rp/26/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__002_PNG, "keymap_rp/26/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__003_PNG, "keymap_rp/26/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__004_PNG, "keymap_rp/26/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__005_PNG, "keymap_rp/26/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__006_PNG, "keymap_rp/26/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__007_PNG, "keymap_rp/26/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__008_PNG, "keymap_rp/26/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__009_PNG, "keymap_rp/26/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__26__010_PNG, "keymap_rp/26/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__001_PNG, "keymap_rp/27/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__002_PNG, "keymap_rp/27/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__003_PNG, "keymap_rp/27/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__004_PNG, "keymap_rp/27/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__005_PNG, "keymap_rp/27/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__006_PNG, "keymap_rp/27/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__007_PNG, "keymap_rp/27/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__008_PNG, "keymap_rp/27/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__009_PNG, "keymap_rp/27/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__27__010_PNG, "keymap_rp/27/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__001_PNG, "keymap_rp/28/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__002_PNG, "keymap_rp/28/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__003_PNG, "keymap_rp/28/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__004_PNG, "keymap_rp/28/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__005_PNG, "keymap_rp/28/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__006_PNG, "keymap_rp/28/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__007_PNG, "keymap_rp/28/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__008_PNG, "keymap_rp/28/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__009_PNG, "keymap_rp/28/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__28__010_PNG, "keymap_rp/28/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__001_PNG, "keymap_rp/29/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__002_PNG, "keymap_rp/29/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__003_PNG, "keymap_rp/29/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__004_PNG, "keymap_rp/29/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__005_PNG, "keymap_rp/29/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__006_PNG, "keymap_rp/29/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__007_PNG, "keymap_rp/29/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__008_PNG, "keymap_rp/29/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__009_PNG, "keymap_rp/29/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__29__010_PNG, "keymap_rp/29/010.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__001_PNG, "keymap_rp/30/001.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__002_PNG, "keymap_rp/30/002.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__003_PNG, "keymap_rp/30/003.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__004_PNG, "keymap_rp/30/004.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__005_PNG, "keymap_rp/30/005.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__006_PNG, "keymap_rp/30/006.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__007_PNG, "keymap_rp/30/007.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__008_PNG, "keymap_rp/30/008.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__009_PNG, "keymap_rp/30/009.png", 0 },
	{ PKG_ENTRY_ID__KEYMAP_RP__30__010_PNG, "keymap_rp/30/010.png", 0 },

	{ PKG_ENTRY_ID__PARAM_JSON, "param.json", 0 },
};

struct key_desc {
	const struct rsa_keyset* key;
	int is_private;
	int usable;
};

struct entry_check_cb_args {
	int has_new_enc_algo;
	int has_unsupported_id;
};

#if defined(ENABLE_EKC_KEYGEN)
static inline void get_key_params(struct pkg* pkg, unsigned int* pubkey_ver, unsigned int* key_ver) {
	unsigned int pkv, kv;

	assert(pkg != NULL);

	pkv = kv = 0;
	if (BE32(pkg->hdr->flags) & PKG_FLAGS_KEY_VER_1) {
		pkv |= (1 << 0);
		kv = 1;
	}
	if (BE32(pkg->hdr->content_flags) & PKG_CONTENT_FLAGS_NON_GAME)
		pkv |= (1 << 16);
	if (BE32(pkg->hdr->flags) & PKG_FLAGS_SIGNED_EKPFS)
		pkv |= (1 << 31);
	if (BE64(pkg->hdr->pfs_flags) & (UINT64_C(0xFF) << 16))
		pkv |= (1 << 30); // have key id
	if (BE64(pkg->hdr->pfs_flags) & (UINT64_C(1) << 62))
		pkv |= (1 << 29); // have fw version

	if (pubkey_ver)
		*pubkey_ver = pkv;
	if (key_ver)
		*key_ver = kv;
}

static inline int gen_sc0_key(uint8_t sc0_key[KEYMGR_SC0_KEY_SIZE], uint8_t content_key_seed[KEYMGR_CONTENT_KEY_SIZE]) {
	uint8_t d1[KEYMGR_CONTENT_KEY_SIZE];
	uint8_t d2[KEYMGR_HASH_SIZE];
	int status = 0;

	assert(sc0_key != NULL);
	assert(content_key_seed != NULL);

	if (!g_gdgp_content_key_obf_key)
		goto error;

	memcpy(d1, content_key_seed, sizeof(d1));
	aes_decrypt_cbc_cts(g_gdgp_content_key_obf_key, KEYMGR_AES_KEY_SIZE, NULL, d1, d1, sizeof(d1));
	sha256_buffer(d1, sizeof(d1), d2);
	memcpy(sc0_key, d2, KEYMGR_SC0_KEY_SIZE);

	status = 1;

error:
	return status;
}
#endif

static int setup_keyset_by_image_key(struct keymgr_title_keyset* keyset, struct pkg* pkg, int only_non_existent) {
	const enum pkg_entry_id entry_id = PKG_ENTRY_ID__IMAGE_KEY;
	struct pkg_table_entry* entry;
	struct pkg_entry_keyset entry_keyset;
	uint8_t image_key_enc[KEYMGR_IMAGE_KEY_ENC_SIZE];
	uint8_t image_key[KEYMGR_IMAGE_KEY_ENC_SIZE];
	size_t image_key_size = 0, real_size;
	struct key_desc non_finalized_keys[] = {
#if defined(ENABLE_EKC_KEYGEN)
		{ &g_rsa_keyset_pkg_debug_ekpfs_key, 0, 1 },
#endif
		{ &g_rsa_keyset_pkg_fake_ekpfs_key, 1, 1 },
	};
	struct key_desc finalized_keys[] = {
#if defined(ENABLE_EKC_KEYGEN)
		{ &g_rsa_keyset_pkg_retail_ekpfs_key_0, 0, 0 },
		{ &g_rsa_keyset_pkg_retail_ekpfs_key_1, 0, 0 },
#endif
	};
	struct {
		struct key_desc* descs;
		size_t count;
	} keyset_lists[] = {
		{ non_finalized_keys, COUNT_OF(non_finalized_keys) },
		{ finalized_keys, COUNT_OF(finalized_keys) },
	}, * keyset_list;
#if defined(ENABLE_EKC_KEYGEN)
	const uint8_t* ekpfs_obf_keys[] = {
		g_ekpfs_obf_key_1,
		g_ekpfs_obf_key_2,
		g_ekpfs_obf_key_3,
		g_ekpfs_obf_key_4,
		g_ekpfs_obf_key_5,
		g_ekpfs_obf_key_6,
		g_ekpfs_obf_key_7,
		g_ekpfs_obf_key_8,
	};
#endif
	uint8_t* data;
	uint32_t data_size;
	uint8_t* ekpfs = NULL;
#if defined(ENABLE_EKC_KEYGEN)
	unsigned int pubkey_ver, key_ver;
	uint8_t* ekpfs_digest = NULL;
	uint8_t computed_ekpfs_digest[KEYMGR_HASH_SIZE];
	uint8_t content_key[KEYMGR_CONTENT_KEY_SIZE];
	uint32_t* p_obf_key_id = NULL;
	uint32_t* p_fw_version = NULL;
	uint8_t pubkey_idx;
#endif
	int decrypted = 0;
	size_t i;
	int status = 0;

	assert(keyset != NULL);
	assert(pkg != NULL);

	entry = pkg_find_entry(pkg, entry_id);
	if (!entry) {
		warning("Unable to find image key entry.");
		goto error;
	}

	data = pkg_locate_entry_data(pkg, entry_id, NULL, &data_size);
	if (!data) {
		warning("Unable to get image key data.");
		goto error;
	}
	if (data_size != sizeof(image_key_enc)) {
		warning("Invalid image key data size.");
		goto error;
	}
	memcpy(image_key_enc, data, data_size);

	if (pkg_table_entry_has_new_enc_algo(entry)) {
		warning("Unsupported encryption algorithm for image key entry.");
		goto error;
	}

	if (pkg_table_entry_is_encrypted(entry)) {
		if (!pkg_get_entry_keyset(pkg, entry_id, &entry_keyset)) {
			warning("Unable to get key for image key.");
			goto error;
		}
		aes_decrypt_cbc_cts(entry_keyset.key, sizeof(entry_keyset.key), entry_keyset.iv, image_key_enc, image_key_enc, data_size);
	}

#if defined(ENABLE_EKC_KEYGEN)
	get_key_params(pkg, &pubkey_ver, &key_ver);
#endif

	keyset_list = &keyset_lists[pkg->finalized & 0x1];
#if defined(ENABLE_EKC_KEYGEN)
	if (pkg->finalized) {
		pubkey_idx = (uint8_t)((pubkey_ver >> 16) & 0xFF);
		if (pubkey_idx >= keyset_list->count) {
			warning("Unsupported public key for image key.");
			goto error;
		}
		keyset_list->descs[pubkey_idx].usable = 1;
	}
#endif

	ekpfs = image_key + image_key_size;
	image_key_size += KEYMGR_EKPFS_SIZE;
#if defined(ENABLE_EKC_KEYGEN)
	if (pubkey_ver & (1 << 30)) { // have key id?
		p_obf_key_id = (uint32_t*)(image_key + image_key_size);
		image_key_size += sizeof(*p_obf_key_id);
	}
	if (pubkey_ver & (1 << 29)) { // have fw version?
		p_fw_version = (uint32_t*)(image_key + image_key_size);
		image_key_size += sizeof(*p_fw_version);
	}
	if (pubkey_ver & (1 << 31)) { // have digest?
		ekpfs_digest = image_key + image_key_size;
		image_key_size += sizeof(computed_ekpfs_digest);
	}
#endif
	real_size = image_key_size;

	for (i = 0; i < keyset_list->count; ++i) {
		if (!keyset_list->descs[i].usable)
			continue;

		if (!check_rsa_key_filled(keyset_list->descs[i].key, keyset_list->descs[i].is_private))
			continue;

		memset(image_key, 0, sizeof(image_key));
		real_size = image_key_size;

		if (rsa_pkcsv15_decrypt(keyset_list->descs[i].key, image_key_enc, data_size, image_key, &real_size, keyset_list->descs[i].is_private, 1)) {
			decrypted = 1;
			break;
		}
	}
	if (!decrypted) {
		warning("Unable to decrypt image key.");
		goto error;
	}
	if (real_size != image_key_size) {
		warning("Unexpected image key size.");
		goto error;
	}

#if defined(ENABLE_EKC_KEYGEN)
	if (ekpfs_digest) {
		sha256_buffer(image_key, image_key_size - sizeof(computed_ekpfs_digest), computed_ekpfs_digest);
		if (memcmp(ekpfs_digest, computed_ekpfs_digest, sizeof(computed_ekpfs_digest)) != 0) {
			warning("Invalid EKPFS digest.");
			goto error;
		}
	}

	if (p_obf_key_id  && *p_obf_key_id > 0) {
		if ((*p_obf_key_id - 1) >= COUNT_OF(ekpfs_obf_keys)) {
			warning("Invalid EKPFS obfuscation key id: %u", (unsigned int)*p_obf_key_id);
			goto error;
		}
		if (!ekpfs_obf_keys[*p_obf_key_id - 1]) {
			warning("EKPFS obfuscation key #%u not found.", *p_obf_key_id - 1);
			goto error;
		}
		aes_decrypt_cbc_cts(ekpfs_obf_keys[*p_obf_key_id - 1], KEYMGR_AES_KEY_SIZE, NULL, ekpfs, ekpfs, KEYMGR_EKPFS_SIZE);
	}

	if (p_fw_version)
		info("Firmware version: 0x%08" PRIX32, *p_fw_version);

	if (pkg->finalized) {
		if (BE32(pkg->hdr->content_type) == CONTENT_TYPE_GD) {
			if (key_ver != 1) {
				warning("Invalid key version.");
				goto error;
			}
			if (!keyset->flags.has_content_key_seed) {
				warning("Content key seed not found.");
				goto error;
			}
			if (!g_gdgp_content_key_obf_key) {
				warning("Obfuscation key for GDGP content key not found.");
				goto error;
			}
			memcpy(content_key, keyset->content_key_seed, sizeof(content_key));
			aes_decrypt_cbc_cts(g_gdgp_content_key_obf_key, KEYMGR_AES_KEY_SIZE, NULL, content_key, content_key, sizeof(content_key));
		} else if (BE32(pkg->hdr->content_type) == CONTENT_TYPE_AC) {
			memcpy(content_key, g_ac_content_key, sizeof(content_key));
		} else {
			warning("Unsupported content type.");
			goto error;
		}
		aes_decrypt_cbc_cts(content_key, sizeof(content_key), NULL, ekpfs, ekpfs, KEYMGR_EKPFS_SIZE);
	}
#endif

	if (!only_non_existent || !keyset->flags.has_image_key) {
		memcpy(keyset->image_key, ekpfs, sizeof(keyset->image_key));
		keyset->flags.has_image_key = 1;
	}

#if defined(ENABLE_EKC_KEYGEN)
	// TODO: sc0 key = sha256(content_key)
	if (keymgr_has_content_key_seed(keyset)) {
		if (gen_sc0_key(keyset->sc0_key, keyset->content_key_seed))
			keyset->flags.has_sc0_key = 1;
	}
#endif

	status = 1;

error:
	return status;
}

static int get_pkg_total_size(const char* file_path, uint64_t* size) {
	struct file_map* map = NULL;
	struct pkg_header* hdr;
	int status = 0;

	map = map_file(file_path);
	if (!map)
		goto error;

	hdr = (struct pkg_header*)map->data;

	if (size)
		*size = BE64(hdr->pfs_image_offset) + BE64(hdr->pfs_image_size);

	status = 1;

error:
	if (map)
		unmap_file(map);

	return status;
}

static inline int get_pkg_piece_count(const char* file_path, size_t* count) {
	uint64_t size;
	const uint64_t piece_size = (uint64_t)(UINT32_MAX) + 1;

	if (!get_pkg_total_size(file_path, &size))
		return 0;

	if (count)
		*count = (size + piece_size - 1) / piece_size;

	return 1;
}

static enum cb_result entry_check_cb(void* arg, struct pkg* pkg, struct pkg_entry_desc* desc) {
	struct entry_check_cb_args* args = (struct entry_check_cb_args*)arg;
	enum cb_result ret = CB_RESULT_CONTINUE;

	assert(args != NULL);
	assert(pkg != NULL);
	assert(desc != NULL);

	UNUSED(pkg);

	if (desc->use_new_algo) {
		if (!(desc->id >= PKG_ENTRY_ID__TROPHY__TROPHY00_TRP && desc->id <= PKG_ENTRY_ID__TROPHY__TROPHY99_TRP)) {
			args->has_unsupported_id = 1;
			//ret = CB_RESULT_STOP;
		}
		args->has_new_enc_algo = 1;
	}

	return ret;
}

struct pkg* pkg_alloc(const char* file_path, pkg_set_pfs_options_cb set_pfs_options_cb, void* set_pfs_options_cb_arg) {
	struct pkg* pkg = NULL;
	struct pfs_options pfs_opts;
	uint8_t content_id_digest[PFS_HASH_SIZE];
	char** file_paths = NULL;
	size_t file_count = 0;
	char piece_file_path[PATH_MAX];
	char piece_file_path_fmt[PATH_MAX];
	struct entry_check_cb_args entry_check_args;
	char* p;
	size_t i;

	assert(file_path != NULL);

	pkg = (struct pkg*)malloc(sizeof(*pkg));
	if (!pkg)
		goto error;
	memset(pkg, 0, sizeof(*pkg));

	strncpy(piece_file_path, file_path, sizeof(piece_file_path));
	p = strrchr(piece_file_path, '%');
	if (p) {
		*p = '\0';
		snprintf(piece_file_path_fmt, sizeof(piece_file_path_fmt), "%s%%u%s", piece_file_path, p + 1);

		snprintf(piece_file_path, sizeof(piece_file_path), piece_file_path_fmt, 0);
		if (!get_pkg_piece_count(piece_file_path, &file_count) || file_count == 0)
			goto error;

		file_paths = (char**)malloc(file_count * sizeof(*file_paths));
		if (!file_paths)
			goto error;
		memset(file_paths, 0, file_count * sizeof(*file_paths));

		for (i = 0; i < file_count; ++i) {
			snprintf(piece_file_path, sizeof(piece_file_path), piece_file_path_fmt, (unsigned int)i);
			file_paths[i] = strdup(piece_file_path);
			if (!file_paths[i])
				goto error;
		}

		pkg->map = map_files((const char* const*)file_paths, file_count);
	} else {
		pkg->map = map_file(file_path);
	}

	if (!pkg->map)
		goto error;

	pkg->hdr = (struct pkg_header*)pkg->map->data;

	pkg->entry_table = (struct pkg_table_entry*)((uint8_t*)pkg->hdr + BE32(pkg->hdr->entry_table_offset));
	pkg->entry_count = BE32(pkg->hdr->entry_count);
	pkg->sc_entry_count = BE16(pkg->hdr->sc_entry_count);
	pkg->finalized = (BE32(pkg->hdr->flags) & PKG_FLAGS_FINALIZED) != 0 ? 1 : 0;

	memset(content_id_digest, 0, sizeof(content_id_digest));
	sha256_buffer(pkg->hdr->content_id, sizeof(pkg->hdr->content_id), content_id_digest);

	pkg->pfs_image_offset = BE64(pkg->hdr->pfs_image_offset);
	pkg->pfs_image_size = BE64(pkg->hdr->pfs_image_size);
	pkg->pfs_signed_size = BE32(pkg->hdr->pfs_signed_size);

	pkg->pfs_offset = 0;
	pkg->inner_pfs_offset = 0;

	pkg->io.arg = pkg;
	pkg->io.get_size = &pfs_get_size_cb;
	pkg->io.get_outer_location = &pfs_get_outer_location_cb;
	pkg->io.get_offset_size = &pfs_get_offset_size_cb;
	pkg->io.seek = &pfs_seek_cb;
	pkg->io.read = &pfs_read_cb;
	pkg->io.write = &pfs_write_cb;
	pkg->io.can_seek = &pfs_can_seek_cb;
	pkg->io.can_read = &pfs_can_read_cb;
	pkg->io.can_write = &pfs_can_write_cb;

	pkg->inner_io.arg = pkg;
	pkg->inner_io.get_size = &pfs_inner_get_size_cb;
	pkg->inner_io.get_outer_location = &pfs_inner_get_outer_location_cb;
	pkg->inner_io.get_offset_size = &pfs_inner_get_offset_size_cb;
	pkg->inner_io.seek = &pfs_inner_seek_cb;
	pkg->inner_io.read = &pfs_inner_read_cb;
	pkg->inner_io.write = &pfs_inner_write_cb;
	pkg->inner_io.can_seek = &pfs_inner_can_seek_cb;
	pkg->inner_io.can_read = &pfs_inner_can_read_cb;
	pkg->inner_io.can_write = &pfs_inner_can_write_cb;

	memset(&pfs_opts, 0, sizeof(pfs_opts));
	pfs_opts.content_id = pkg->hdr->content_id;
	pfs_opts.finalized = pkg->finalized;
	pfs_opts.playgo = 0;
	pfs_opts.case_sensitive = 0;
	pfs_opts.skip_signature_check = pkg->finalized ? 0 : 1;
	pfs_opts.skip_block_hash_check = 0;

	if (set_pfs_options_cb) {
		if (!(*set_pfs_options_cb)(set_pfs_options_cb_arg, pkg, &pfs_opts))
			goto error;
	}

	memset(&entry_check_args, 0, sizeof(entry_check_args));
	pkg_enum_entries(pkg, &entry_check_cb, &entry_check_args, 1);

	if (entry_check_args.has_new_enc_algo) {
		if (entry_check_args.has_unsupported_id) {
			warning("Found unsupported entry which use new encryption algorithm.");
			//goto error;
		}

		if (pfs_opts.skip_keygen == 1) // all commands except of info
			pfs_opts.skip_keygen = 0;
	}

	if (!pfs_opts.keyset && !pfs_opts.skip_keygen) {
		pfs_opts.keyset = keymgr_get_title_keyset(pkg->hdr->content_id);
		if (!pfs_opts.keyset) {
			pfs_opts.keyset = keymgr_alloc_title_keyset(pkg->hdr->content_id, 1);
			if (!pfs_opts.keyset)
				goto error;
			if (!setup_keyset_by_image_key(pfs_opts.keyset, pkg, 0))
				;// FIXME: goto error;
		} else {
			if (!pfs_opts.keyset->flags.has_passcode && !pfs_opts.keyset->flags.has_image_key && !pfs_opts.keyset->flags.has_enc_data_key && !pfs_opts.keyset->flags.has_enc_tweak_key && !pfs_opts.keyset->flags.has_sig_hmac_key) {
				if (!setup_keyset_by_image_key(pfs_opts.keyset, pkg, 1))
					goto error;
			}
		}
	}

	if (set_pfs_options_cb) {
		if (!(*set_pfs_options_cb)(set_pfs_options_cb_arg, pkg, &pfs_opts))
			goto error;
	}

	if (!pfs_opts.keyset && pfs_opts.skip_keygen) {
		pkg->pfs = pkg->inner_pfs = NULL;
		pkg->image_file = NULL;
		goto done;
	}

	if (!pfs_opts.disable_pkg_pfs_usage) {
		pkg->pfs = pfs_alloc(&pkg->io, &pfs_opts, 0);
		if (!pkg->pfs)
			goto error;

		if (!pfs_lookup_path_user(pkg->pfs, PKG_PFS_IMAGE_FILE_NAME, &pkg->image_file_ino))
			goto error;

		pkg->image_file = pfs_get_file(pkg->pfs, pkg->image_file_ino);
		if (!pkg->image_file)
			goto error;

		pfs_opts.skip_signature_check = 1;
		pfs_opts.skip_block_hash_check = 1;

		pkg->inner_pfs = pfs_alloc(&pkg->inner_io, &pfs_opts, 1);
		if (!pkg->inner_pfs)
			goto error;
	}

done:
	if (file_paths) {
		for (i = 0; i < file_count; ++i) {
			if (file_paths[i])
				free(file_paths[i]);
		}

		free(file_paths);
	}

	return pkg;

error:
	if (pkg) {
		if (pkg->inner_pfs)
			pfs_free(pkg->inner_pfs);

		if (pkg->image_file)
			pfs_free_file(pkg->image_file);

		if (pkg->pfs)
			pfs_free(pkg->pfs);

		if (pkg->map)
			unmap_file(pkg->map);

		free(pkg);
	}

	if (file_paths) {
		for (i = 0; i < file_count; ++i) {
			if (file_paths[i])
				free(file_paths[i]);
		}

		free(file_paths);
	}

	return NULL;
}

void pkg_free(struct pkg* pkg) {
	if (!pkg)
		return;

	if (pkg->inner_pfs)
		pfs_free(pkg->inner_pfs);

	if (pkg->image_file)
		pfs_free_file(pkg->image_file);

	if (pkg->pfs)
		pfs_free(pkg->pfs);

	if (pkg->map)
		unmap_file(pkg->map);

	free(pkg);
}

int pkg_get_name_by_id(char* name, size_t max_size, enum pkg_entry_id id, int* is_extra) {
	size_t i;
	int status = 0;

	assert(name != NULL);

	for (i = 0; i < COUNT_OF(s_entry_names); ++i) {
		if (s_entry_names[i].id == (unsigned int)id) {
			strncpy(name, s_entry_names[i].name, max_size);
			if (is_extra)
				*is_extra = s_entry_names[i].is_extra;
			status = 1;
			break;
		}
	}

	return status;
}

struct pkg_table_entry* pkg_find_entry(struct pkg* pkg, enum pkg_entry_id id) {
	struct pkg_table_entry* entry;
	size_t i;

	assert(pkg != NULL);

	for (i = 0; i < pkg->entry_count; ++i) {
		entry = pkg->entry_table + i;
		if (BE32(entry->id) == (uint32_t)id)
			return entry;
	}

	return NULL;
}

size_t pkg_enum_entries(struct pkg* pkg, pkg_enum_entries_cb cb, void* arg, int need_extra) {
	struct pkg_table_entry* entry;
	struct pkg_entry_desc desc;
	size_t count, i;
	enum cb_result cb_result;
	int is_extra = 0;

	assert(pkg != NULL);

	for (i = 0, count = 0; i < pkg->entry_count; ++i) {
		entry = pkg->entry_table + i;

		memset(&desc, 0, sizeof(desc));
		{
			desc.entry = entry;

			desc.id = (enum pkg_entry_id)BE32(entry->id);
			desc.unk1 = BE32(entry->unk1);
			desc.flags1 = BE32(entry->flags1);
			desc.flags2 = BE32(entry->flags2);
			desc.offset = BE32(entry->offset);
			desc.size = BE32(entry->size);

			if (!pkg_get_name_by_id(desc.name, sizeof(desc.name), desc.id, &is_extra)) {
				snprintf(desc.name, sizeof(desc.name), "_unknown_0x%08" PRIX32, (unsigned int)desc.id);
				warning("Unknown package file entry: 0x%08" PRIX32, (unsigned int)desc.id);
			}

			desc.key_index = pkg_table_entry_key_index(entry);
			desc.is_encrypted = pkg_table_entry_is_encrypted(entry);
			desc.use_new_algo = pkg_table_entry_has_new_enc_algo(entry);

			if (!need_extra && is_extra)
				continue;
		}

		++count;

		if (cb) {
			cb_result = (*cb)(arg, pkg, &desc);
			if (cb_result == CB_RESULT_STOP)
				break;
		}
	}

	return count;
}

uint8_t* pkg_locate_entry_data(struct pkg* pkg, enum pkg_entry_id id, uint64_t* offset, uint32_t* size) {
	struct pkg_table_entry* entry;
	uint8_t* data;

	assert(pkg != NULL);

	entry = pkg_find_entry(pkg, id);
	if (!entry)
		return NULL;

	data = pkg->map->data + BE32(entry->offset);
	if (offset)
		*offset = BE32(entry->offset);
	if (size)
		*size = BE32(entry->size);

	return data;
}

static int get_entry_keyset_old(struct pkg* pkg, struct pkg_table_entry* entry, struct pkg_entry_keyset* keyset) {
	const struct rsa_keyset* key;
	unsigned int key_index;
	uint8_t key_buf[PKG_ENTRY_KEYSET_ENC_SIZE];
	size_t key_buf_size = sizeof(key_buf);
	uint8_t* entry_data = NULL;
	size_t entry_data_size;
	uint8_t hash[PKG_HASH_SIZE];
	uint8_t* data;
	int status = 0;

	assert(pkg != NULL);
	assert(entry != NULL);
	assert(keyset != NULL);

	key_index = pkg_table_entry_key_index(entry);

	switch (key_index) {
		case 3: key = &g_rsa_keyset_pkg_entry_key_3; break;
		default:
#if 0
			warning("No RSA key for key index: %u", key_index);
#endif
			goto error;
	}

	if (!check_rsa_key_filled(key, 1)) {
		warning("Package entry keyset '%s' is missing.", key->name);
		goto error;
	}

	data = pkg_locate_entry_data(pkg, PKG_ENTRY_ID__ENTRY_KEYS, NULL, NULL);
	if (!data) {
		warning("Unable to find entry keys blob.");
		goto error;
	}

	data += PKG_CONTENT_ID_HASH_SIZE;
	data += PKG_ENTRY_KEYS_XHASHES_SIZE;
	data += PKG_PASSCODE_KEY_SIZE;
	data += (key_index - 1) * PKG_ENTRY_KEY_SIZE;

	memset(key_buf, 0, sizeof(key_buf));
	if (!rsa_pkcsv15_decrypt(key, data, key_buf_size, key_buf, &key_buf_size, 1, 1)) {
		warning("Unable to decrypt entry keys blob.");
		goto error;
	}
	if (key_buf_size != PKG_ENTRY_KEYSET_SIZE) {
		warning("Invalid entry keys blob.");
		goto error;
	}

	entry_data_size = sizeof(*entry) + key_buf_size;
	entry_data = (uint8_t*)malloc(entry_data_size);
	if (!entry_data) {
		warning("Unable to allocate memory for entry data of size 0x%" PRIXMAX " bytes.", (uintmax_t)entry_data_size);
		goto error;
	}
	memset(entry_data, 0, entry_data_size);

	memcpy(entry_data, entry, sizeof(*entry));
	memcpy(entry_data + sizeof(*entry), key_buf, key_buf_size);

	sha256_buffer(entry_data, entry_data_size, hash);

	memset(keyset, 0, sizeof(*keyset));
	memcpy(keyset->iv, hash, sizeof(keyset->iv));
	memcpy(keyset->key, hash + sizeof(keyset->iv), sizeof(keyset->key));

	status = 1;

error:
	if (entry_data)
		free(entry_data);

	return status;
}

static int get_entry_keyset_new(struct pkg* pkg, struct pkg_table_entry* entry, struct pkg_entry_keyset* keyset) {
	int status = 0;

	assert(pkg != NULL);
	assert(entry != NULL);
	assert(keyset != NULL);

	UNUSED(entry);

	memset(keyset, 0, sizeof(*keyset));

	if (!pkg->pfs || !pkg->pfs->opts) {
		warning("Unable to get Sc0 key because PFS is not available.");
		goto error;
	}

	if (!pkg->pfs->opts->keyset) {
		warning("Unable to get Sc0 key because keyset is not set properly.");
		goto error;
	}

	if (!keymgr_has_sc0_key(pkg->inner_pfs->opts->keyset)) {
		warning("Sc0 key not found.");
		goto error;
	}

	memcpy(keyset->key, pkg->inner_pfs->opts->keyset->sc0_key, sizeof(pkg->inner_pfs->opts->keyset->sc0_key));

	status = 1;

error:
	return status;
}

int pkg_get_entry_keyset(struct pkg* pkg, enum pkg_entry_id id, struct pkg_entry_keyset* keyset) {
	struct pkg_table_entry* entry;
	int status = 0;

	assert(pkg != NULL);
	assert(keyset != NULL);

	entry = pkg_find_entry(pkg, id);
	if (!entry) {
		warning("Unable to find entry 0x%08" PRIX32 ".", (unsigned int)id);
		goto error;
	}

	if (pkg_table_entry_has_new_enc_algo(entry)) {
		status = get_entry_keyset_new(pkg, entry, keyset);
	} else {
		if (!pkg_table_entry_is_encrypted(entry)) {
			warning("Entry 0x%08" PRIX32 " is not encrypted.", (unsigned int)id);
			goto error;
		}
		status = get_entry_keyset_old(pkg, entry, keyset);
	}

error:
	return status;
}

int pkg_unpack_single(struct pkg* pkg, const char* path, const char* output_directory, pfs_unpack_pre_cb pre_cb, void* pre_cb_arg) {
	int status;

	assert(pkg != NULL);
	assert(path != NULL);
	assert(output_directory != NULL);

	status = pfs_unpack_single(pkg->inner_pfs, path, output_directory, pre_cb, pre_cb_arg);

	return status;
}

int pkg_unpack_all(struct pkg* pkg, const char* output_directory, pfs_unpack_pre_cb pre_cb, void* pre_cb_arg) {
	int status;

	assert(pkg != NULL);
	assert(output_directory != NULL);

	status = pfs_unpack_all(pkg->inner_pfs, output_directory, pre_cb, pre_cb_arg);

	return status;
}

static int pfs_get_size_cb(void* arg, uint64_t* size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (size)
		*size = pkg->pfs_image_size;

	return 1;
}

static int pfs_get_outer_location_cb(void* arg, uint64_t offset, uint64_t* outer_offset) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (offset > pkg->pfs_image_size)
		return 0;

	if (outer_offset)
		*outer_offset = pkg->pfs_image_offset + offset;

	return 1;
}

static int pfs_get_offset_size_cb(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (pkg->pfs_offset + data_size > pkg->pfs_image_size)
		return 0;

	if (real_offset)
		*real_offset = pkg->pfs_offset;

	if (size_to_read)
		*size_to_read = data_size;

	if (compressed)
		*compressed = 0;

	return 1;
}

static int pfs_seek_cb(void* arg, uint64_t offset) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (offset > pkg->pfs_image_size)
		return 0;

	pkg->pfs_offset = offset;

	return 1;
}

static int pfs_read_cb(void* arg, void* data, uint64_t data_size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);
	assert(data != NULL);

	if (pkg->pfs_offset + data_size > pkg->pfs_image_size)
		return 0;

	memcpy(data, pkg->map->data + pkg->pfs_image_offset + pkg->pfs_offset, data_size);

	return 1;
}

static int pfs_write_cb(void* arg, void* data, uint64_t data_size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);
	assert(data != NULL);

	if (pkg->pfs_offset + data_size > pkg->pfs_image_size)
		return 0;

	memcpy(pkg->map->data + pkg->pfs_image_offset + pkg->pfs_offset, data, data_size);

	return 1;
}

static int pfs_can_seek_cb(void* arg, uint64_t offset) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (offset > pkg->pfs_image_size)
		return 0;

	return 1;
}

static int pfs_can_read_cb(void* arg, uint64_t data_size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (pkg->pfs_offset + data_size > pkg->pfs_image_size)
		return 0;

	return 1;
}

static int pfs_can_write_cb(void* arg, uint64_t data_size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (pkg->pfs_offset + data_size > pkg->pfs_image_size)
		return 0;

	return 1;
}

static int pfs_inner_get_size_cb(void* arg, uint64_t* size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (size)
		*size = pkg->image_file->file_size;

	return 1;
}

static int pfs_inner_get_outer_location_cb(void* arg, uint64_t offset, uint64_t* outer_offset) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (offset > pkg->image_file->file_size)
		return 0;

	return pfs_file_get_outer_location(pkg->image_file, offset, outer_offset);
}

static int pfs_inner_get_offset_size_cb(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (pkg->inner_pfs_offset + data_size > pkg->image_file->file_size)
		return 0;

	return pfs_file_get_offset_size(pkg->image_file, pkg->inner_pfs_offset, data_size, real_offset, size_to_read, compressed);
}

static int pfs_inner_seek_cb(void* arg, uint64_t offset) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (offset > pkg->image_file->file_size)
		return 0;

	pkg->inner_pfs_offset = offset;

	return 1;
}

static int pfs_inner_read_cb(void* arg, void* data, uint64_t data_size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);
	assert(data != NULL);

	if (pkg->inner_pfs_offset + data_size > pkg->image_file->file_size)
		return 0;

	return pfs_file_read(pkg->image_file, pkg->inner_pfs_offset, data, data_size);
}

static int pfs_inner_write_cb(void* arg, void* data, uint64_t data_size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);
	assert(data != NULL);

	if (pkg->inner_pfs_offset + data_size > pkg->image_file->file_size)
		return 0;

	return pfs_file_write(pkg->image_file, pkg->inner_pfs_offset, data, data_size);
}

static int pfs_inner_can_seek_cb(void* arg, uint64_t offset) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (offset > pkg->image_file->file_size)
		return 0;

	return 1;
}

static int pfs_inner_can_read_cb(void* arg, uint64_t data_size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (pkg->inner_pfs_offset + data_size > pkg->image_file->file_size)
		return 0;

	return 1;
}

static int pfs_inner_can_write_cb(void* arg, uint64_t data_size) {
	struct pkg* pkg = (struct pkg*)arg;

	assert(pkg != NULL);

	if (pkg->inner_pfs_offset + data_size > pkg->image_file->file_size)
		return 0;

	return 1;
}
