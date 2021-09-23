#pragma once

#include "common.h"

#define SELF_MAGIC MAGIC4_BE(0x4F, 0x15, 0x3D, 0x1D)
#define ELF_MAGIC  MAGIC4_BE(0x7F, 'E', 'L', 'F')

#define SELF_VERSION            0
#define SELF_MODE               1
#define SELF_ENDIANNESS         1
#define SELF_ATTRIBUTE          0x12

#define SELF_HEADER_SIZE               0x20
#define SELF_MAX_HEADER_SIZE           0x4000
#define SELF_ENTRY_SIZE                0x20
#define SELF_EXTENDED_INFO_SIZE        0x40
#define SELF_META_BLOCK_SIZE           0x50
#define SELF_META_FOOTER_SIZE          0x150
#define SELF_NPDRM_CONTROL_BLOCK_SIZE  0x30
#define SELF_NPDRM_CONTENT_ID_SIZE     0x13
#define SELF_NPDRM_RANDOM_PAD_SIZE     0xD
#define SELF_SEGMENT_BLOCK_DIGEST_SIZE 0x20
#define SELF_SEGMENT_BLOCK_EXTENT_SIZE 0x8
#define SELF_HASH_SIZE                 0x20
#define SELF_SIGNATURE_SIZE            0x100
#define SELF_DEFAULT_BLOCK_SIZE        0x1000

#define SELF_ZLIB_WINDOW_BITS 12
#define SELF_ZLIB_LEVEL       6

#define ELF_EX_INFO_OFFSET 0x3F00

#define SELF_ENTRY_FLAGS_META_SEGMENT_MASK 0xF0000

#define SELF_PAID_FSELF U64C(0x3100000000000001)
#define SELF_PAID_GAME  U64C(0x3800000000000011)

#define SELF_PTYPE_FAKE           U64C(1)
#define SELF_PTYPE_NPDRM_EXEC     U64C(4)
#define SELF_PTYPE_NPDRM_DYNLIB   U64C(5)
#define SELF_PTYPE_SYSTEM_EXEC    U64C(8)
#define SELF_PTYPE_SYSTEM_DYNLIB  U64C(9) // including Mono binaries
#define SELF_PTYPE_BIOS_KERNEL    U64C(12)
#define SELF_PTYPE_SECURE_MODULE  U64C(14)
#define SELF_PTYPE_SECURE_LOADER  U64C(15)

#define SELF_CONTROL_BLOCK_NPDRM 3

#define ELF64_EHDR_SIZE 0x40
#define ELF64_PHDR_SIZE 0x38
#define ELF64_SHDR_SIZE 0x40

#define ELF_ET_EXEC          0x2
#define ELF_ET_SCE_EXEC      0xFE00
#define ELF_ET_SCE_EXEC_ASLR 0xFE10
#define ELF_ET_SCE_DYNAMIC   0xFE18

#define ELF_PT_LOAD             U32C(1)
#define ELF_PT_DYNAMIC          U32C(2)
#define ELF_PT_INTERP           U32C(3)
#define ELF_PT_TLS              U32C(7)
#define ELF_PT_GNU_EH_FRAME     U32C(0x6474E550)
#define ELF_PT_GNU_STACK        U32C(0x6474E551)
#define ELF_PT_SCE_RELA         U32C(0x60000000)
#define ELF_PT_SCE_DYNLIBDATA   U32C(0x61000000)
#define ELF_PT_SCE_PROCPARAM    U32C(0x61000001)
#define ELF_PT_SCE_MODULE_PARAM U32C(0x61000002)
#define ELF_PT_SCE_RELRO        U32C(0x61000010)
#define ELF_PT_SCE_COMMENT      U32C(0x6FFFFF00)
#define ELF_PT_SCE_VERSION      U32C(0x6FFFFF01)

#define ELF_PF_EXEC       0x1
#define ELF_PF_WRITE      0x2
#define ELF_PF_READ       0x4
#define ELF_PF_READ_EXEC  (ELF_PF_READ | ELF_PF_EXEC)
#define ELF_PF_READ_WRITE (ELF_PF_READ | ELF_PF_WRITE)

#define ELF64_HALF_LE(x)  LE16(x)
#define ELF64_WORD_LE(x)  LE32(x)
#define ELF64_XWORD_LE(x) LE64(x)
#define ELF64_OFF_LE(x)   LE64(x)
#define ELF64_ADDR_LE(x)  LE64(x)

TYPE_BEGIN(struct self_hdr, SELF_HEADER_SIZE);
	TYPE_FIELD(uint32_t magic, 0x00);
	TYPE_FIELD(uint8_t version, 0x04);
	TYPE_FIELD(uint8_t mode, 0x05);
	TYPE_FIELD(uint8_t endian, 0x06);
	TYPE_FIELD(uint8_t attr, 0x07);
	TYPE_FIELD(uint32_t key_type, 0x08);
	TYPE_FIELD(uint16_t header_size, 0x0C);
	TYPE_FIELD(uint16_t meta_size, 0x0E);
	TYPE_FIELD(uint64_t file_size, 0x10);
	TYPE_FIELD(uint16_t entry_count, 0x18);
	TYPE_FIELD(uint16_t flags, 0x1A);
	TYPE_FIELD(uint8_t pad[4], 0x1C);
TYPE_END();
CT_SIZE_ASSERT(struct self_hdr, SELF_HEADER_SIZE);

#pragma pack(push, 1)

union self_entry_flags {
	uint64_t bitmask;
	struct {
		unsigned int is_ordered: 1; // 0
		unsigned int is_encrypted: 1; // 1
		unsigned int is_signed: 1; // 2
		unsigned int is_compressed: 1; // 3
		unsigned int unk1: 4; // 4
		unsigned int window_bits: 3; // 8
		unsigned int has_blocks: 1; // 11
		unsigned int block_size: 4; // 12
		unsigned int has_digests: 1; // 16
		unsigned int has_extents: 1; // 17
		unsigned int unk2: 2; // 18
		unsigned int segment_idx: 16; // 20
	};
};

#pragma pack(pop)

TYPE_BEGIN(struct self_entry, SELF_ENTRY_SIZE);
	TYPE_FIELD(union self_entry_flags flags, 0x00);
	TYPE_FIELD(uint64_t offset, 0x08);
	TYPE_FIELD(uint64_t compressed_size, 0x10);
	TYPE_FIELD(uint64_t uncompressed_size, 0x18);
TYPE_END();
CT_SIZE_ASSERT(struct self_entry, SELF_ENTRY_SIZE);

TYPE_BEGIN(struct self_extended_info, SELF_EXTENDED_INFO_SIZE);
	TYPE_FIELD(uint64_t paid, 0x00);
	TYPE_FIELD(uint64_t ptype, 0x08);
	TYPE_FIELD(uint64_t app_version, 0x10);
	TYPE_FIELD(uint64_t fw_version, 0x18);
	TYPE_FIELD(uint8_t file_hash[SELF_HASH_SIZE], 0x20);
TYPE_END();
CT_SIZE_ASSERT(struct self_extended_info, SELF_EXTENDED_INFO_SIZE);

TYPE_BEGIN(struct self_meta_block, SELF_META_BLOCK_SIZE); // TODO: figure out layout
TYPE_END();
CT_SIZE_ASSERT(struct self_meta_block, SELF_META_BLOCK_SIZE);

TYPE_BEGIN(struct self_meta_footer, SELF_META_FOOTER_SIZE); // TODO: figure out layout
	TYPE_FIELD(uint32_t unk1, 0x30);
	TYPE_FIELD(uint8_t signature[SELF_SIGNATURE_SIZE], 0x50);
TYPE_END();
CT_SIZE_ASSERT(struct self_meta_footer, SELF_META_FOOTER_SIZE);

TYPE_BEGIN(struct self_npdrm_control_block, SELF_NPDRM_CONTROL_BLOCK_SIZE);
	TYPE_FIELD(uint16_t type, 0x00);
	TYPE_FIELD(char content_id[SELF_NPDRM_CONTENT_ID_SIZE], 0x10);
	TYPE_FIELD(uint8_t random_pad[SELF_NPDRM_RANDOM_PAD_SIZE], 0x23);
TYPE_END();
CT_SIZE_ASSERT(struct self_npdrm_control_block, SELF_NPDRM_CONTROL_BLOCK_SIZE);

TYPE_BEGIN(struct self_segment_block_digest, SELF_SEGMENT_BLOCK_DIGEST_SIZE);
	TYPE_FIELD(uint8_t digest[SELF_HASH_SIZE], 0x00);
TYPE_END();
CT_SIZE_ASSERT(struct self_segment_block_digest, SELF_SEGMENT_BLOCK_DIGEST_SIZE);

TYPE_BEGIN(struct self_segment_block_extent, SELF_SEGMENT_BLOCK_EXTENT_SIZE);
	TYPE_FIELD(uint32_t offset, 0x00);
	TYPE_FIELD(uint32_t size, 0x04);
TYPE_END();
CT_SIZE_ASSERT(struct self_segment_block_extent, SELF_SEGMENT_BLOCK_EXTENT_SIZE);

typedef uint16_t elf64_half_t;
typedef uint32_t elf64_word_t;
typedef uint64_t elf64_xword_t;
typedef uint64_t elf64_off_t;
typedef uint64_t elf64_addr_t;

TYPE_BEGIN(struct elf64_ehdr, ELF64_EHDR_SIZE);
	TYPE_FIELD(uint8_t e_ident[16], 0x00);
	TYPE_FIELD(elf64_half_t e_type, 0x10);
	TYPE_FIELD(elf64_half_t e_machine, 0x12);
	TYPE_FIELD(elf64_word_t e_version, 0x14);
	TYPE_FIELD(elf64_addr_t e_entry, 0x18);
	TYPE_FIELD(elf64_off_t e_phoff, 0x20);
	TYPE_FIELD(elf64_off_t e_shoff, 0x28);
	TYPE_FIELD(elf64_word_t e_flags, 0x30);
	TYPE_FIELD(elf64_half_t e_ehsize, 0x34);
	TYPE_FIELD(elf64_half_t e_phentsize, 0x36);
	TYPE_FIELD(elf64_half_t e_phnum, 0x38);
	TYPE_FIELD(elf64_half_t e_shentsize, 0x3A);
	TYPE_FIELD(elf64_half_t e_shnum, 0x3C);
	TYPE_FIELD(elf64_half_t e_shstrndx, 0x3E);
TYPE_END();
CT_SIZE_ASSERT(struct elf64_ehdr, ELF64_EHDR_SIZE);

TYPE_BEGIN(struct elf64_phdr, ELF64_PHDR_SIZE);
	TYPE_FIELD(elf64_word_t p_type, 0x00);
	TYPE_FIELD(elf64_word_t p_flags, 0x04);
	TYPE_FIELD(elf64_off_t p_offset, 0x08);
	TYPE_FIELD(elf64_addr_t p_vaddr, 0x10);
	TYPE_FIELD(elf64_addr_t p_paddr, 0x18);
	TYPE_FIELD(elf64_xword_t p_filesz, 0x20);
	TYPE_FIELD(elf64_xword_t p_memsz, 0x28);
	TYPE_FIELD(elf64_xword_t p_align, 0x30);
TYPE_END();
CT_SIZE_ASSERT(struct elf64_phdr, ELF64_PHDR_SIZE);

TYPE_BEGIN(struct elf64_shdr, ELF64_SHDR_SIZE);
	TYPE_FIELD(elf64_word_t sh_name, 0x00);
	TYPE_FIELD(elf64_word_t sh_type, 0x04);
	TYPE_FIELD(elf64_xword_t sh_flags, 0x08);
	TYPE_FIELD(elf64_addr_t sh_addr, 0x10);
	TYPE_FIELD(elf64_off_t sh_offset, 0x18);
	TYPE_FIELD(elf64_xword_t sh_size, 0x20);
	TYPE_FIELD(elf64_word_t sh_link, 0x28);
	TYPE_FIELD(elf64_word_t sh_info, 0x2C);
	TYPE_FIELD(elf64_xword_t sh_addralign, 0x30);
	TYPE_FIELD(elf64_xword_t sh_entsize, 0x38);
TYPE_END();
CT_SIZE_ASSERT(struct elf64_shdr, ELF64_SHDR_SIZE);

struct elf_extended_info_1 {
	uint8_t data[0x40];
};

struct elf_extended_info_2 {
	uint8_t data[0x80];
};

struct elf_extended_info {
	uint8_t size;

	union {
		struct elf_extended_info_1 info1;
		struct elf_extended_info_2 info2;
	};
};

struct elf {
	uint8_t* data;
	size_t size;

	struct elf64_ehdr* ehdr;
	struct elf64_phdr* phdrs;
	struct elf64_shdr* shdrs;

	struct elf_extended_info* ex_info;

	int is_inner;
};

struct self {
	uint8_t* data;
	size_t size;

	struct self_hdr* hdr;

	struct self_entry* entry_table;
	size_t entry_count;

	struct elf* elf;

	struct self_extended_info* ex_info;
	struct self_npdrm_control_block* npdrm_control_block;
};

struct elf* elf_alloc(void* data, size_t size, int is_inner);
void elf_free(struct elf* elf);

static inline int elf_has_segments(struct elf* elf) {
	assert(elf != NULL);
	return ELF64_HALF_LE(elf->ehdr->e_phentsize) > 0 && ELF64_HALF_LE(elf->ehdr->e_phnum) > 0;
}

static inline int elf_has_sections(struct elf* elf) {
	assert(elf != NULL);
	return ELF64_HALF_LE(elf->ehdr->e_shentsize) > 0 && ELF64_HALF_LE(elf->ehdr->e_shnum) > 0;
}

struct self* self_alloc(void* data, size_t size);
void self_free(struct self* self);

int self_make_fake_signed(struct self* self, struct elf* elf);

static inline int self_entry_window_bits(struct self_entry* entry) {
	union self_entry_flags flags;
	int window_bits;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	window_bits = flags.window_bits;

	return window_bits;
}

static inline size_t self_entry_segment_index(struct self_entry* entry) {
	union self_entry_flags flags;
	size_t segment_idx;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	segment_idx = flags.segment_idx;

	return segment_idx;
}

static inline size_t self_entry_block_size(struct self_entry* entry) {
	union self_entry_flags flags;
	size_t block_size;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	if (flags.has_blocks)
		block_size = U32C(1) << (12 + flags.block_size);
	else
		block_size = SELF_DEFAULT_BLOCK_SIZE;

	return block_size;
}

static inline size_t self_entry_block_count(struct self_entry* entry) {
	size_t block_size;
	size_t block_count;

	assert(entry != NULL);

	block_size = self_entry_block_size(entry);
	block_count = (LE64(entry->uncompressed_size) + block_size - 1) / block_size;

	return block_count;
}

static inline int self_entry_is_encrypted_segment(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return flags.is_encrypted ? 1 : 0;
}

static inline int self_entry_is_signed_segment(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return flags.is_signed ? 1 : 0;
}

static inline int self_entry_is_compressed_segment(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return flags.is_compressed ? 1 : 0;
}

static inline int self_entry_has_blocks(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return flags.has_blocks ? 1 : 0;
}

static inline int self_entry_has_digests(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return flags.has_digests ? 1 : 0;
}

static inline int self_entry_has_extents(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return flags.has_extents ? 1 : 0;
}

static inline int self_entry_is_meta_segment(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return (flags.bitmask & SELF_ENTRY_FLAGS_META_SEGMENT_MASK) != 0;
}

static inline int self_entry_is_block_table_segment(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return (flags.has_digests || flags.has_extents) ? 1 : 0;
}

static inline int self_entry_is_segment_with_blocks(struct self_entry* entry) {
	union self_entry_flags flags;

	assert(entry != NULL);

	flags.bitmask = LE64(entry->flags.bitmask);

	return flags.has_blocks ? 1 : 0;
}

static struct self_entry* self_find_linked_entry(struct self* self, struct self_entry* entry, size_t* entry_index) {
	struct self_entry* linked_entry = NULL;
	size_t segment_idx, cur_segment_idx;
	size_t i;

	assert(self != NULL);
	assert(entry != NULL);

	if (!self_entry_is_segment_with_blocks(entry))
		goto error;

	segment_idx = (size_t)(entry - self->entry_table);

	for (i = 0; i < self->entry_count; ++i) {
		if (i == segment_idx)
			continue;
		cur_segment_idx = self_entry_segment_index(self->entry_table + i);
		if (cur_segment_idx == segment_idx) {
			linked_entry = self->entry_table + i;
			if (entry_index)
				*entry_index = i;
			break;
		}
	}

error:
	return linked_entry;
}
