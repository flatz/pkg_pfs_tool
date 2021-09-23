#pragma once

#include "keymgr.h"

#define PFS_HEADER_SIZE 0x5A0
#define PFS_HEADER_COVER_SIZE_FOR_ICV 0x380
#define PFS_SD_HEADER_SIZE 0x580
#define PFS_SD_HEADER_COVER_SIZE 0x40
#define PFS_SUPERBLOCK_SIGNATURE_COVER_SIZE 0x3A0
#define PFSC_HEADER_SIZE 0x30
#define PFS_FS_MAGIC U32C(0x1332A0B)
#define PFSC_MAGIC U32C(0x43534650)
#define PFSC_EXT_MAGIC U64C(0xFFFFFFFF96969696)
#define PFSC_WORK_DATA_SIZE (64 * 1024 * 2) // 2 * 64 KB
#define PFSC_ZLIB_WINDOW_BITS 12
#define PFSC_ZLIB_LEVEL 6
#define PFS_DIR_ENTRY_NAME_MAX_SIZE 16384
#define PFS_DIRECT_BLOCK_MAX_COUNT 12
#define PFS_INDIRECT_BLOCK_MAX_COUNT 5
#define PFS_HASH_SIZE 32
#define PFS_SIGNATURE_SIZE 256
#define PFS_DEVICE_BLOCK_SIZE_SHIFT 9 // log2(PFS_DEVICE_BLOCK_SIZE)
#define PFS_DEVICE_BLOCK_SIZE (1 << PFS_DEVICE_BLOCK_SIZE_SHIFT)
#define PFS_ENCDEC_SECTOR_SIZE_SHIFT 12 // log2(PFS_ENCDEC_SECTOR_SIZE)
#define PFS_ENCDEC_SECTOR_SIZE (1 << PFS_ENCDEC_SECTOR_SIZE_SHIFT)
#define PFS_MIN_BLOCK_SIZE 0x1000
#define PFS_MAX_BLOCK_SIZE 0x200000
#define PFS_MIN_DIR_ENTRY_SIZE 0x14
#define PFS_MODE_FORMAT_MASK 0x3
#define PFS_MODE_SIGNED_FLAG 0x1
#define PFS_MODE_ENCRYPTED_FLAG 0x4
#define PFS_MODE_CASE_INSENSITIVE_FLAG 0x8
#define PFS_BLOCK_SIZE_SHIFT 9
#define PFS_INODE_STRUCT_SIZE 0xB8
#define PFS_BLOCK32_STRUCT_SIZE 0x4
#define PFS_BLOCK64_STRUCT_SIZE 0x8
#define PFS_SBLOCK32_STRUCT_SIZE 0x24
#define PFS_SBLOCK64_STRUCT_SIZE 0x28
#define PFS_DINODE32_STRUCT_SIZE 0x48
#define PFS_DINODE64_STRUCT_SIZE 0x90
#define PFS_SDINODE32_STRUCT_SIZE 0x268
#define PFS_SDINODE64_STRUCT_SIZE 0x2B0
#define PFS_DINODE_TOP_STRUCT_SIZE 0x60
#define PFS_DINODE_STRUCT_SIZE 0x310 // PFS_DINODE_TOP_STRUCT_SIZE + max(PFS_DINODE32_STRUCT_SIZE, PFS_DINODE64_STRUCT_SIZE, PFS_SDINODE32_STRUCT_SIZE, PFS_SDINODE64_STRUCT_SIZE)

#if defined(ENABLE_SD_KEYGEN)
#	define SEALED_KEY_MAGIC MAGIC8_BE('p', 'f', 's', 'S', 'K', 'K', 'e', 'y')
#	define SEALED_KEY_STRUCT_SIZE 0x60

#	define SD_AUTH_CODE_MAGIC MAGIC8_BE(0x79, 0x2B, 0x1A, 0xC1, 0xBB, 0x9B, 0x9A, 0x45)
#	define SD_AUTH_CODE_STRUCT_SIZE 0x70
#	define SD_AUTH_CODE_INFO_STRUCT_SIZE 0x50
#	define SD_AUTH_CODE_OFFSET 0x7F90

#	define SD_INFO_DATA_STRUCT_SIZE 0x1E0

#	define SD_SHELLUI_PAID           UINT64_C(0x380000000000000F)
#	define SD_SHELLCORE_PAID         UINT64_C(0x3800000000000010)
#	define SD_NPXS21003_PAID         UINT64_C(0x3800000000000015)
#	define SD_SECURE_UI_PROCESS_PAID UINT64_C(0x3800000000000033)
#endif

#define PFS_MODE_TO_PERMS(mode, mask) (((mode) & PFS_FILE_PERMS_MASK) == (mask))

#define PFS_MODE_TO_TYPE(mode, mask) (((mode) & PFS_FILE_TYPE_MASK) == (mask))
#define PFS_IS_FIFO(mode) PFS_MODE_TO_TYPE((mode), PFS_FILE_TYPE_FIFO)
#define PFS_IS_CHR(mode)  PFS_MODE_TO_TYPE((mode), PFS_FILE_TYPE_CHR)
#define PFS_IS_DIR(mode)  PFS_MODE_TO_TYPE((mode), PFS_FILE_TYPE_DIR)
#define PFS_IS_BLK(mode)  PFS_MODE_TO_TYPE((mode), PFS_FILE_TYPE_BLK)
#define PFS_IS_REG(mode)  PFS_MODE_TO_TYPE((mode), PFS_FILE_TYPE_REG)
#define PFS_IS_LNK(mode)  PFS_MODE_TO_TYPE((mode), PFS_FILE_TYPE_LNK)
#define PFS_IS_SOCK(mode) PFS_MODE_TO_TYPE((mode), PFS_FILE_TYPE_SOCK)
#define PFS_IS_WHT(mode)  PFS_MODE_TO_TYPE((mode), PFS_FILE_TYPE_WHT)

enum pfs_format {
	PFS_FORMAT_32        = 0, // 32-bit inodes
	PFS_FORMAT_32_SIGNED = 1, // 32-bit inodes (signed)
	PFS_FORMAT_64        = 2, // 64-bit inodes
	PFS_FORMAT_64_SIGNED = 3, // 64-bit inodes (signed)
};

enum pfs_entry_type {
	PFS_ENTRY_NONE      = 0,
	PFS_ENTRY_FILE      = 2,
	PFS_ENTRY_DIRECTORY = 3,
	PFS_ENTRY_THIS      = 4,
	PFS_ENTRY_PARENT    = 5,
};

enum pfs_file_perms {
	PFS_FILE_PERMS_MASK = 0007777, // Mask of file permissions
	PFS_FILE_EXEC       = 0000100, // Executable
	PFS_FILE_WRITE      = 0000200, // Writeable
	PFS_FILE_READ       = 0000400, // Readable
	PFS_FILE_SVTX       = 0001000, // Sticky bit
	PFS_FILE_SGID       = 0002000, // Set-gid
	PFS_FILE_SUID       = 0004000, // Set-uid
};

enum pfs_file_type {
	PFS_FILE_TYPE_MASK = 0170000, // Mask of file type
	PFS_FILE_TYPE_FIFO = 0010000, // Named pipe (fifo)
	PFS_FILE_TYPE_CHR  = 0020000, // Character device
	PFS_FILE_TYPE_DIR  = 0040000, // Directory file
	PFS_FILE_TYPE_BLK  = 0060000, // Block device
	PFS_FILE_TYPE_REG  = 0100000, // Regular file
	PFS_FILE_TYPE_LNK  = 0120000, // Symbolic link
	PFS_FILE_TYPE_SOCK = 0140000, // UNIX domain socket
	PFS_FILE_TYPE_WHT  = 0160000, // Whiteout
};

enum pfs_file_flags {
	PFS_FILE_COMPRESSED = (1 << 0), // Compressed file
	PFS_FILE_ENCRYPTED  = (1 << 2), // Encrypted file
	PFS_FILE_BIT4       = (1 << 4), //
};

typedef uint32_t pfs_ino;
typedef int64_t pfs_lbn;
typedef int64_t pfs_daddr;

struct pfs_dir_entry {
	pfs_ino ino;
	uint32_t type; // enum pfs_entry_type
	uint32_t name_size;
	uint32_t entry_size;
	char name[PFS_DIR_ENTRY_NAME_MAX_SIZE];
};

struct pfs_block32 {
	uint32_t block_no;
};

struct pfs_block64 {
	uint64_t block_no;
};

struct pfs_sblock32 {
	uint8_t digest[PFS_HASH_SIZE];
	uint32_t block_no;
};

struct pfs_sblock64 {
	uint8_t digest[PFS_HASH_SIZE];
	uint64_t block_no;
};

struct pfs_block_list {
	uint64_t* blocks;
	uint64_t capacity;
	uint64_t count;
};

CT_SIZE_ASSERT(struct pfs_block32, PFS_BLOCK32_STRUCT_SIZE);
CT_SIZE_ASSERT(struct pfs_block64, PFS_BLOCK64_STRUCT_SIZE);
CT_SIZE_ASSERT(struct pfs_sblock32, PFS_SBLOCK32_STRUCT_SIZE);
CT_SIZE_ASSERT(struct pfs_sblock64, PFS_SBLOCK64_STRUCT_SIZE);

// For compressed blocks (32-bit).
TYPE_BEGIN(struct pfs_dinode32, PFS_DINODE32_STRUCT_SIZE);
	TYPE_FIELD(uint32_t block_count, 0x00);                                             // Bytes actually held
	TYPE_FIELD(struct pfs_block32 direct_blocks[PFS_DIRECT_BLOCK_MAX_COUNT], 0x04);     // Direct disk blocks
	TYPE_FIELD(struct pfs_block32 indirect_blocks[PFS_INDIRECT_BLOCK_MAX_COUNT], 0x34); // Indirect disk blocks
TYPE_END();
CT_SIZE_ASSERT(struct pfs_dinode32, PFS_DINODE32_STRUCT_SIZE);

// For compressed blocks (64-bit).
TYPE_BEGIN(struct pfs_dinode64, PFS_DINODE64_STRUCT_SIZE);
	TYPE_FIELD(uint64_t block_count, 0x00);                                             // Bytes actually held
	TYPE_FIELD(struct pfs_block64 direct_blocks[PFS_DIRECT_BLOCK_MAX_COUNT], 0x08);     // Direct disk blocks
	TYPE_FIELD(struct pfs_block64 indirect_blocks[PFS_INDIRECT_BLOCK_MAX_COUNT], 0x68); // Indirect disk blocks
TYPE_END();
CT_SIZE_ASSERT(struct pfs_dinode64, PFS_DINODE64_STRUCT_SIZE);

// For raw blocks (32-bit).
TYPE_BEGIN(struct pfs_sdinode32, PFS_SDINODE32_STRUCT_SIZE);
	TYPE_FIELD(uint32_t block_count, 0x00);                                               // Bytes actually held
	TYPE_FIELD(struct pfs_sblock32 direct_blocks[PFS_DIRECT_BLOCK_MAX_COUNT], 0x04);      // Direct disk blocks
	TYPE_FIELD(struct pfs_sblock32 indirect_blocks[PFS_INDIRECT_BLOCK_MAX_COUNT], 0x1B4); // Indirect disk blocks
TYPE_END();
CT_SIZE_ASSERT(struct pfs_sdinode32, PFS_SDINODE32_STRUCT_SIZE);

// For raw blocks (64-bit).
TYPE_BEGIN(struct pfs_sdinode64, PFS_SDINODE64_STRUCT_SIZE);
	TYPE_FIELD(uint64_t block_count, 0x00);                                               // Bytes actually held
	TYPE_FIELD(struct pfs_sblock64 direct_blocks[PFS_DIRECT_BLOCK_MAX_COUNT], 0x08);      // Direct disk blocks
	TYPE_FIELD(struct pfs_sblock64 indirect_blocks[PFS_INDIRECT_BLOCK_MAX_COUNT], 0x1E8); // Indirect disk blocks
TYPE_END();
CT_SIZE_ASSERT(struct pfs_sdinode64, PFS_SDINODE64_STRUCT_SIZE);

TYPE_BEGIN(struct pfs_dinode, PFS_DINODE_STRUCT_SIZE);
	TYPE_FIELD(uint16_t mode, 0x00);                                          // IFMT, permissions
	TYPE_FIELD(uint16_t link_count, 0x02);                                    // File link count
	TYPE_FIELD(uint32_t flags, 0x04);                                         // Flags
	TYPE_FIELD(uint64_t size, 0x08);                                          // File byte count
	TYPE_FIELD(uint64_t size_uncompressed, 0x10);                             // Uncompressed size
	TYPE_FIELD(uint64_t last_access_time, 0x18);                              // Last access time
	TYPE_FIELD(uint64_t last_modified_time, 0x20);                            // Last modified time
	TYPE_FIELD(uint64_t last_change_time, 0x28);                              // Last inode change time
	TYPE_FIELD(uint64_t creation_time, 0x30);                                 // Inode creation time
	TYPE_FIELD(uint32_t last_modified_time_ns, 0x38);                         // Last modified time
	TYPE_FIELD(uint32_t last_access_time_ns, 0x3C);                           // Last access time
	TYPE_FIELD(uint32_t last_change_time_ns, 0x40);                           // Last inode change time
	TYPE_FIELD(uint32_t creation_time_ns, 0x44);                              // Inode creation time
	TYPE_FIELD(uint32_t uid, 0x48);                                           // File owner
	TYPE_FIELD(uint32_t gid, 0x4C);                                           // File group
	TYPE_FIELD(uint64_t spare[2], 0x50);

	TYPE_FIELD(union {
		struct pfs_dinode32 di32;
		struct pfs_dinode64 di64;
		struct pfs_sdinode32 sdi32;
		struct pfs_sdinode64 sdi64;
	}, 0x60);
TYPE_END();
CT_SIZE_ASSERT(struct pfs_dinode, PFS_DINODE_STRUCT_SIZE);

#if defined(ENABLE_SD_KEYGEN)
TYPE_BEGIN(struct sd_info_data, SD_INFO_DATA_STRUCT_SIZE);
	TYPE_FIELD(uint8_t nonce[0x10], 0x00);
	TYPE_FIELD(uint8_t open_psid_digest[KEYMGR_OPEN_PSID_SIZE], 0x10);
	TYPE_FIELD(uint64_t game_paid, 0x20);
	TYPE_FIELD(uint64_t shellui_paid, 0x30);
	TYPE_FIELD(uint8_t partial_idps[4], 0x38);
TYPE_END();
#endif

struct pfs_header {
	uint64_t version;                                          // 0x000: FS format version
	uint64_t magic;                                            // 0x008: FS magic
	uint32_t id[2];                                            // 0x010: Unique filesystem id
	uint8_t fmode;                                             // 0x018
	uint8_t clean;                                             // 0x019
	uint8_t read_only;                                         // 0x01A: Read only flag
	uint8_t rsv;                                               // 0x01B
	uint16_t mode;                                             // 0x01C: Mode (encrypted, signed, etc)
	uint32_t basic_block_size;                                 // 0x020: Size of basic blocks
	uint32_t nbackup;                                          // 0x024
	uint64_t nblock;                                           // 0x028
	uint64_t dinode_count;                                     // 0x030: Number of dinodes in the dinode blocks
	uint64_t data_block_count;                                 // 0x038: Total number of data blocks
	uint64_t dinode_block_count;                               // 0x040: Total number of dinode blocks
	uint64_t super_root_dir_ino;                               // 0x048: Inode of super root directory
	struct pfs_dinode super_root_dinode;                       // 0x050: Super root directory dinode
	uint32_t unk1;                                             // 0x360
	uint32_t unk2;                                             // 0x364
	uint32_t unk3;                                             // 0x368
	uint32_t sd_key_ver;                                       // 0x36C: Key version for SD
	uint8_t crypt_seed[0x10];                                  // 0x370: Seed for encdec keys
	uint8_t header_hash[PFS_HASH_SIZE];                        // 0x380: Header hash
	union {
		struct { /* gd/ac */
			uint8_t super_block_signature[PFS_SIGNATURE_SIZE]; // 0x3A0: Super block RSA signature
			uint8_t unk4[0x100];                               // 0x4A0
		};

#if defined(ENABLE_SD_KEYGEN)
		struct { /* sd */
			struct sd_info_data info_data;                     // 0x3A0: Info data
			uint8_t bottom_signature[PFS_HASH_SIZE];           // 0x580: HMAC digest over PFS header
		};
#endif
	};
};
CT_SIZE_ASSERT(struct pfs_header, PFS_HEADER_SIZE);

struct PACKED pfsc_ext_header {
	uint64_t magic;
	uint64_t compressed_size;
	uint64_t uncompressed_size;
	uint32_t unk1;
};
CT_SIZE_ASSERT(struct pfsc_ext_header, 0x1C);

struct pfsc_header {
	uint32_t magic;              // 0x00: Magic
	uint32_t unk1;               // 0x04:
	uint32_t unk2;               // 0x08:
	uint32_t block_size;         // 0x0C: The original data will be partitioned into blocks of this size and compressed (bytes)
	uint32_t alignment;          // 0x10: The alignment of the compressed data start position (bytes)
	uint32_t unk3;               // 0x14:
	uint64_t block_table_offset; // 0x18: Offset from the file start to the block_table
	uint64_t block_data_offset;  // 0x20: Offset from the file start to the block data
	uint64_t rounded_file_size;  // 0x28: File size before compression but after rounding up to a multiple of block_size (bytes)
};
CT_SIZE_ASSERT(struct pfsc_header, PFSC_HEADER_SIZE);

// The flat_path_table is a simple mapping of filename hashes to inode number to increase the lookup speed for files.
// All hashes are sorted in ascending order.
struct pfs_flat_path_table_entry {
	uint32_t filename_hash;
	pfs_ino ino;
};

enum pfs_flags {
	PFS_FLAGS_PLAYGO         = (1 << 0),
	PFS_FLAGS_CASE_SENSITIVE = (1 << 1),
};

#if defined(ENABLE_SD_KEYGEN)
TYPE_BEGIN(struct sealed_key, SEALED_KEY_STRUCT_SIZE);
	TYPE_FIELD(uint64_t magic, 0x00);
	TYPE_FIELD(uint16_t version, 0x08);
	TYPE_FIELD(uint8_t iv[0x10], 0x10);
	TYPE_FIELD(uint8_t data[KEYMGR_MKEY_SIZE], 0x20);
	TYPE_FIELD(uint8_t hash[KEYMGR_HASH_SIZE], 0x40);
TYPE_END();
CT_SIZE_ASSERT(struct sealed_key, SEALED_KEY_STRUCT_SIZE);

TYPE_BEGIN(struct sd_auth_code_info, SD_AUTH_CODE_INFO_STRUCT_SIZE);
	TYPE_FIELD(uint8_t pfs_hdr_hash1[0x20], 0x00);
	TYPE_FIELD(uint8_t pfs_hdr_hash2[0x20], 0x20);
	TYPE_FIELD(uint64_t copy_ctr, 0x40);
	TYPE_FIELD(uint64_t pad2, 0x48);
TYPE_END();
CT_SIZE_ASSERT(struct sd_auth_code_info, SD_AUTH_CODE_INFO_STRUCT_SIZE);

TYPE_BEGIN(struct sd_auth_code, SD_AUTH_CODE_STRUCT_SIZE);
	TYPE_FIELD(uint64_t magic, 0x00);
	TYPE_FIELD(uint32_t version_major, 0x08);
	TYPE_FIELD(uint32_t version_minor, 0x0C);
	TYPE_FIELD(uint8_t iv[0x10], 0x10);
	TYPE_FIELD(union {
		struct sd_auth_code_info info;
		uint8_t data[SD_AUTH_CODE_INFO_STRUCT_SIZE];
	}, 0x20);
TYPE_END();
CT_SIZE_ASSERT(struct sd_auth_code, SD_AUTH_CODE_STRUCT_SIZE);
#endif

struct encdec_device;

struct pfs_io_callbacks {
	void* arg;

	int (*get_size)(void* arg, uint64_t* size);

	int (*get_outer_location)(void* arg, uint64_t offset, uint64_t* outer_offset);
	int (*get_offset_size)(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed);

	int (*seek)(void* arg, uint64_t offset);
	int (*read)(void* arg, void* data, uint64_t data_size);
	int (*write)(void* arg, void* data, uint64_t data_size);

	int (*can_seek)(void* arg, uint64_t offset);
	int (*can_read)(void* arg, uint64_t data_size);
	int (*can_write)(void* arg, uint64_t data_size);
};

struct pfs {
	struct pfs_io_callbacks* io;
	struct pfs_options* opts;

	struct encdec_device* encdec;

	struct pfs_header hdr;

	size_t basic_block_size;
	size_t basic_block_mask;
	size_t basic_block_qmask;
	int basic_block_size_shift;

	size_t dev_block_size;
	size_t dev_block_mask;
	size_t dev_block_qmask;
	int dev_block_size_shift;

	size_t encdec_sector_size;
	size_t encdec_sector_mask;
	size_t encdec_sector_qmask;
	int encdec_sector_size_shift;

	enum pfs_format format;
	int is_inner;
	int is_signed;
	int is_encrypted;
	enum pfs_flags flags;

	size_t dinode_struct_size;
	size_t block_info_struct_size;
	size_t inodes_per_block;
	size_t indirect_ptrs_per_block;
	size_t max_direct_block_count;
	int64_t indirect_ptrs_per_block_for_level[PFS_INDIRECT_BLOCK_MAX_COUNT];

	pfs_ino super_root_dir_ino;
	pfs_ino block_bitmap_ino;
	pfs_ino ino_bitmap_ino;
	pfs_ino user_root_dir_ino;
	pfs_ino block_addr_table_ino;
	pfs_ino flat_path_table_ino;
	pfs_ino collision_resolver_ino;
};

typedef int (*pfs_dump_indirect_block_cb)(void* arg, struct pfs* pfs, uint64_t block_no, uint64_t block_count, uint8_t* block_data);

struct pfs_options {
	char* content_id;
	struct keymgr_title_keyset* keyset;

	int case_sensitive;
	int playgo;
	int finalized;
#if defined(ENABLE_SD_KEYGEN)
	int is_sd;
#endif

	int skip_signature_check;
	int skip_block_hash_check;

	int skip_keygen;
	int disable_pkg_pfs_usage;
	int dump_final_keys;
#if defined(ENABLE_SD_KEYGEN)
	int dump_sd_info;
#endif
};

struct pfs_file_context {
	struct pfs* pfs;
	struct pfs_dinode dinode;
	struct pfs_block_list* block_list;
	uint8_t* tmp_block;
	uint64_t dinode_block_no;
	size_t dinode_offset;
	pfs_ino ino;
	uint64_t file_size;
	uint32_t flags;
	enum pfs_file_perms perms;
	enum pfs_file_type type;
	int ignore;

	struct {
		uint64_t rounded_file_size;
		uint64_t block_table_offset;
		uint64_t block_data_offset;
		uint64_t block_count;
		size_t block_size;
		size_t alignment;
		int block_size_shift;
		uint32_t block_size_mask;
		uint32_t block_size_qmask;
		uint64_t* block_offsets;
		uint8_t* work_data;
		int loaded;
	} cmp;
};

struct pfs* pfs_alloc(struct pfs_io_callbacks* io, const struct pfs_options* opts, int is_inner);
void pfs_free(struct pfs* pfs);

int pfs_io_get_size(struct pfs* pfs, uint64_t* size);

int pfs_io_get_outer_offset(struct pfs* pfs, uint64_t offset, uint64_t* outer_offset);
int pfs_io_get_offset_size(struct pfs* pfs, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed);

int pfs_io_seek(struct pfs* pfs, uint64_t offset);
int pfs_io_read(struct pfs* pfs, void* data, uint64_t data_size);
int pfs_io_write(struct pfs* pfs, void* data, uint64_t data_size);

int pfs_io_can_seek(struct pfs* pfs, uint64_t offset);
int pfs_io_can_read(struct pfs* pfs, uint64_t data_size);
int pfs_io_can_write(struct pfs* pfs, uint64_t data_size);

int pfs_dump_indirect_blocks(struct pfs* pfs, pfs_ino ino, pfs_dump_indirect_block_cb dump_cb, void* dump_cb_arg);

struct pfs_file_context* pfs_get_file_ex(struct pfs* pfs, pfs_ino ino, pfs_dump_indirect_block_cb dump_cb, void* dump_cb_arg);
struct pfs_file_context* pfs_get_file(struct pfs* pfs, pfs_ino ino);
void pfs_free_file(struct pfs_file_context* file);

struct pfs_block_list* pfs_get_block_list(struct pfs* pfs, const struct pfs_dinode* dinode, pfs_dump_indirect_block_cb dump_cb, void* dump_cb_arg);
void pfs_free_block_list(struct pfs* pfs, struct pfs_block_list* block_list);

int pfs_get_idblock_offset(struct pfs* pfs, int64_t block_counter, uint32_t* level_offsets, int* level_count);
int pfs_get_block_no_sino(struct pfs* pfs, const struct pfs_dinode* dinode, uint64_t block_counter, uint64_t* block_no, uint32_t* sino);

int pfs_get_dinode(struct pfs* pfs, pfs_ino ino, struct pfs_dinode* dinode, uint64_t* dinode_block_no, size_t* dinode_offset);
int pfs_put_dinode(struct pfs* pfs, uint64_t dinode_block_no, size_t dinode_offset, struct pfs_dinode* dinode);

int pfs_lookup_path(struct pfs* pfs, const char* path, pfs_ino root_ino, pfs_ino* ino);
int pfs_lookup_path_super(struct pfs* pfs, const char* path, pfs_ino* ino);
int pfs_lookup_path_user(struct pfs* pfs, const char* path, pfs_ino* ino);

int pfs_read_blocks(struct pfs* pfs, uint64_t block_no, void* data, uint64_t block_count);
int pfs_write_blocks(struct pfs* pfs, uint64_t block_no, void* data, uint64_t block_count);

int pfs_file_read_raw(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size);
int pfs_file_write_raw(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size);

int pfs_file_get_outer_location(struct pfs_file_context* file, uint64_t offset, uint64_t* outer_offset);
int pfs_file_get_offset_size(struct pfs_file_context* file, uint64_t offset, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed);

typedef enum cb_result (*pfs_parse_dir_entries_cb)(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* name);
size_t pfs_parse_dir_entries(struct pfs* pfs, const void* data, uint64_t data_size, pfs_parse_dir_entries_cb cb, void* arg);
size_t pfs_count_dir_entries(struct pfs* pfs, const void* data, uint64_t data_size);

int pfs_parse_super_root_directory(struct pfs* pfs);

typedef enum cb_result (*pfs_enum_user_root_directory_cb)(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* path, uint64_t size, uint32_t flags);
int pfs_enum_user_root_directory(struct pfs* pfs, pfs_enum_user_root_directory_cb cb, void* arg);

int pfs_list_user_root_directory(struct pfs* pfs);

#if defined(ENABLE_SD_KEYGEN)
int pfs_get_sd_key_ver(struct pfs* pfs, unsigned int* key_ver);
#endif

int pfs_check_cipher_block(struct pfs* pfs, const struct pfs_dinode* dinode, int type);

void pfs_encrypt(struct pfs* pfs, const void* in, void* out, uint64_t offset, uint64_t data_size);
void pfs_decrypt(struct pfs* pfs, const void* in, void* out, uint64_t offset, uint64_t data_size);

void pfs_sign_buffer(struct pfs* pfs, const void* data, uint64_t data_size, uint8_t hash[PFS_HASH_SIZE]);

void pfs_dump_dinode(struct pfs* pfs, const struct pfs_dinode* dinode, int dump_blocks);

struct pfs_options* pfs_clone_options(const struct pfs_options* opts);
void pfs_free_options(struct pfs_options* opts);

int pfs_is_super_root_dinode(struct pfs* pfs, const struct pfs_dinode* dinode);

static inline uint64_t pfs_offset_in_block(struct pfs* pfs, uint64_t offset) {
	return offset & pfs->basic_block_qmask;
}

static inline uint64_t pfs_block_no_to_offset(struct pfs* pfs, uint64_t block_no) {
	return block_no << pfs->basic_block_size_shift;
}

static inline uint64_t pfs_offset_to_block_no(struct pfs* pfs, uint64_t offset) {
	return offset >> pfs->basic_block_size_shift;
}

static inline uint64_t pfs_block_round_up(struct pfs* pfs, uint64_t size) {
	return (size + pfs->basic_block_qmask) & pfs->basic_block_mask;
}

static inline uint64_t pfs_lbn_to_size(struct pfs* pfs, uint64_t size, uint64_t lbn) {
	if (lbn >= PFS_DIRECT_BLOCK_MAX_COUNT || size >= pfs_block_no_to_offset(pfs, lbn + 1))
		return pfs->basic_block_size;
	else
		return pfs_block_round_up(pfs, pfs_offset_in_block(pfs, size));
}

static inline uint32_t pfs_flat_path_table_hash(const char* filename) {
	uint32_t hash = 0;
	const char* p = filename;
	while (*p != '\0') {
		int c = (*p >= 'a' && *p <= 'z') ? (*p - 32) : *p;
		hash = c + 31 * hash;
	}
	return hash;
}

int pfs_file_read(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size);
int pfs_file_write(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size);

typedef enum cb_result (*pfs_unpack_pre_cb)(void* arg, const char* path, enum pfs_entry_type type, int* needed);

int pfs_unpack_single(struct pfs* pfs, const char* path, const char* output_directory, pfs_unpack_pre_cb pre_cb, void* pre_cb_arg);
int pfs_unpack_all(struct pfs* pfs, const char* output_directory, pfs_unpack_pre_cb pre_cb, void* pre_cb_arg);

int pfs_dump_to_file(struct pfs* pfs, const char* path, pfs_unpack_pre_cb pre_cb, void* pre_cb_arg);

#if defined(ENABLE_SD_KEYGEN)
int pfs_get_sd_content_key(struct pfs* pfs, uint8_t content_key[KEYMGR_CONTENT_KEY_SIZE]);

int pfs_decrypt_sealed_key(const struct sealed_key* key, uint8_t mkey[KEYMGR_MKEY_SIZE]);
int pfs_decrypt_sealed_key_from_file(const char* path, uint8_t mkey[KEYMGR_MKEY_SIZE]);

int pfs_parse_sd_auth_code(struct pfs* pfs, struct sd_auth_code_info* info, int* has_auth_code);
#endif
