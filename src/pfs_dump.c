#include "pfs.h"
#include "util.h"

static void pfs_dump_dinode_block(struct pfs* pfs, const struct pfs_dinode* dinode, enum pfs_format format, size_t block_index, int indirect) {
	union {
		const struct pfs_block32* b32;
		const struct pfs_block64* b64;
		const struct pfs_sblock32* sb32;
		const struct pfs_sblock64* sb64;
	} u;
	uint64_t block_no;
	const uint8_t* digest = NULL;
	char digest_str[PFS_HASH_SIZE * 2 + 1];
	size_t i;

	assert(pfs != NULL);
	assert(dinode != NULL);

	UNUSED(pfs);

	if (format == PFS_FORMAT_32) {
		u.b32 = indirect ? &dinode->di32.indirect_blocks[block_index] : &dinode->di32.direct_blocks[block_index];
		block_no = LE32(u.b32->block_no);
	} else if (format == PFS_FORMAT_64) {
		u.b64 = indirect ? &dinode->di64.indirect_blocks[block_index] : &dinode->di64.direct_blocks[block_index];
		block_no = LE64(u.b64->block_no);
	} else if (format == PFS_FORMAT_32_SIGNED) {
		u.sb32 = indirect ? &dinode->sdi32.indirect_blocks[block_index] : &dinode->sdi32.direct_blocks[block_index];
		block_no = LE32(u.sb32->block_no);
		digest = &u.sb32->digest[0];
	} else if (format == PFS_FORMAT_64_SIGNED) {
		u.sb64 = indirect ? &dinode->sdi64.indirect_blocks[block_index] : &dinode->sdi64.direct_blocks[block_index];
		block_no = LE64(u.sb64->block_no);
		digest = &u.sb64->digest[0];
	} else {
		assert(0);
		return;
	}

	info("%s block #%02" PRIuMAX ":", indirect ? "Indirect" : "Direct", (uintmax_t)block_index);
	info("  Block no: %" PRIu64, block_no);

	if (digest) {
		for (i = 0; i < PFS_HASH_SIZE; ++i)
			snprintf(digest_str + i * 2, sizeof(digest_str) - i * 2, "%02X", digest[i]);
		digest_str[PFS_HASH_SIZE * 2] = '\0';

		info("  Digest: %s", digest_str);
	}
}

void pfs_dump_dinode(struct pfs* pfs, const struct pfs_dinode* dinode, int dump_blocks) {
	uint64_t block_count;
	enum pfs_format format = pfs_is_super_root_dinode(pfs, dinode) ? PFS_FORMAT_64_SIGNED : pfs->format; // super root dinode is always s64
	uint16_t mode;
	const char* type_str;
	size_t i;

	assert(pfs != NULL);
	assert(dinode != NULL);

	switch (format) {
		case PFS_FORMAT_32: block_count = LE32(dinode->di32.block_count); break;
		case PFS_FORMAT_64: block_count = LE64(dinode->di64.block_count); break;
		case PFS_FORMAT_32_SIGNED: block_count = LE32(dinode->sdi32.block_count); break;
		case PFS_FORMAT_64_SIGNED: block_count = LE64(dinode->sdi64.block_count); break;
		default:
			assert(0);
			return;
	}

	mode = LE16(dinode->mode);

	if (PFS_IS_REG(mode))
		type_str = "REG";
	else if (PFS_IS_DIR(mode))
		type_str = "DIR";
	else if (PFS_IS_LNK(mode))
		type_str = "LNK";
	else if (PFS_IS_CHR(mode))
		type_str = "CHR";
	else if (PFS_IS_BLK(mode))
		type_str = "BLK";
	else if (PFS_IS_SOCK(mode))
		type_str = "SOCK";
	else if (PFS_IS_FIFO(mode))
		type_str = "FIFO";
	else if (PFS_IS_WHT(mode))
		type_str = "WHT";
	else
		type_str = "<unknown>";

	info("Mode: 0x%04" PRIX16, mode);
	info("Type: %s", type_str);
	info("Link count: %" PRIu16, LE16(dinode->link_count));
	info("Flags: 0x%08" PRIX32, LE32(dinode->flags));
	info("Size: 0x%" PRIX64, LE64(dinode->size));
	info("Block count: %" PRIu64, block_count);

	if (dump_blocks) {
		for (i = 0; i < PFS_DIRECT_BLOCK_MAX_COUNT; ++i)
			pfs_dump_dinode_block(pfs, dinode, format, i, 0);
		for (i = 0; i < PFS_INDIRECT_BLOCK_MAX_COUNT; ++i)
			pfs_dump_dinode_block(pfs, dinode, format, i, 1);
	}
}

