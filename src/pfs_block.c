#include "pfs.h"
#include "util.h"

int pfs_is_super_root_dinode(struct pfs* pfs, const struct pfs_dinode* dinode) {
	assert(pfs != NULL);
	assert(dinode != NULL);

	return memcmp(&pfs->hdr.super_root_dinode, dinode, sizeof(*dinode)) == 0;
}

struct pfs_block_list* pfs_get_block_list(struct pfs* pfs, const struct pfs_dinode* dinode, pfs_dump_indirect_block_cb dump_cb, void* dump_cb_arg) {
	struct pfs_block_list* block_list = NULL;
	uint64_t real_size, processed_size;
	uint64_t needed_block_count, contig_block_count;
	uint64_t block_no;
	union {
		struct pfs_block32* b32;
		struct pfs_block64* b64;
		struct pfs_sblock32* sb32;
		struct pfs_sblock64* sb64;
		uint8_t* block_buf;
	} u0, u1, u2;
	enum pfs_format db_format = pfs_is_super_root_dinode(pfs, dinode) ? PFS_FORMAT_64_SIGNED : pfs->format; // super root dinode is always s64
	enum pfs_format ib_format = pfs->format;
	size_t i, j, k;

	assert(pfs != NULL);
	assert(dinode != NULL);

	u0.block_buf = u1.block_buf = u2.block_buf = NULL;

#define BLOCK_COUNT(type, bits) LE##bits(dinode->type##di##bits.block_count)

#define PROCESS_DIRECT_BLOCKS(type, bits) \
	do { \
		for (i = 0; i < PFS_DIRECT_BLOCK_MAX_COUNT; ++i) { \
			block_list->blocks[block_list->count] = LE##bits(dinode->type##di##bits.direct_blocks[i].block_no); \
			if (block_list->blocks[block_list->count] == 0xFFFFFFFF) { \
				contig_block_count = needed_block_count - i; \
				break; \
			} \
			processed_size += pfs_lbn_to_size(pfs, real_size, block_list->count); \
			++block_list->count; \
			if (processed_size >= real_size) \
				goto success; \
		} \
		if (contig_block_count > 0) { \
			assert(block_list->count > 0); \
			for (i = 0; i < contig_block_count; ++i) { \
				block_list->blocks[block_list->count] = block_list->blocks[block_list->count - 1] + 1; \
				processed_size += pfs_lbn_to_size(pfs, real_size, block_list->count); \
				++block_list->count; \
				if (processed_size >= real_size) \
					goto success; \
			} \
 		} \
	} while (0)

#define PREPARE_INDIRECT_BLOCKS(type, bits, n) \
	do { \
		if (!u##n.block_buf) { \
			u##n.block_buf = (uint8_t*)malloc(pfs->basic_block_size); \
			if (!u##n.block_buf) \
				goto error; \
		} \
		memset(u##n.block_buf, 0, pfs->basic_block_size); \
		block_no = LE##bits(dinode->type##di##bits.indirect_blocks[(n)].block_no); \
		if (!pfs_read_blocks(pfs, block_no, u##n.block_buf, 1)) \
			goto error; \
		if (dump_cb) \
			(*dump_cb)(dump_cb_arg, pfs, block_no, 1, u##n.block_buf); \
	} while (0)

#define PROCESS_INDIRECT_BLOCKS_0(type, bits) \
	do { \
		for (i = 0; i < pfs->indirect_ptrs_per_block; ++i) { \
			block_list->blocks[block_list->count] = LE##bits(u0.type##b##bits[i].block_no); \
			processed_size += pfs_lbn_to_size(pfs, real_size, block_list->count); \
			++block_list->count; \
			if (processed_size >= real_size) \
				goto success; \
		} \
	} while (0)

#define PROCESS_INDIRECT_BLOCKS_1(type, bits) \
	do { \
		for (j = 0; j < pfs->indirect_ptrs_per_block; ++j) { \
			block_no = LE##bits(u1.type##b##bits[j].block_no); \
			if (!pfs_read_blocks(pfs, block_no, u0.block_buf, 1)) \
				goto error; \
			if (dump_cb) \
				(*dump_cb)(dump_cb_arg, pfs, block_no, 1, u0.block_buf); \
			PROCESS_INDIRECT_BLOCKS_0(type, bits); \
		} \
	} while (0)

#define PROCESS_INDIRECT_BLOCKS_2(type, bits) \
	do { \
		for (k = 0; k < pfs->indirect_ptrs_per_block; ++k) { \
			block_no = LE##bits(u2.type##b##bits[k].block_no); \
			if (!pfs_read_blocks(pfs, block_no, u1.block_buf, 1)) \
				goto error; \
			if (dump_cb) \
				(*dump_cb)(dump_cb_arg, pfs, block_no, 1, u1.block_buf); \
			PROCESS_INDIRECT_BLOCKS_1(type, bits); \
		} \
	} while (0)

	real_size = LE64(dinode->size);

	block_list = (struct pfs_block_list*)malloc(sizeof(*block_list));
	if (!block_list)
		goto error;
	memset(block_list, 0, sizeof(*block_list));

	block_list->capacity = real_size / pfs->basic_block_size + 1;
	block_list->count = 0;
	block_list->blocks = (uint64_t*)malloc(block_list->capacity * sizeof(*block_list->blocks));
	if (!block_list->blocks)
		goto error;
	memset(block_list->blocks, 0, block_list->capacity * sizeof(*block_list->blocks));

	contig_block_count = 0;
	processed_size = 0;

	if (db_format == PFS_FORMAT_32) {
		needed_block_count = BLOCK_COUNT(, 32);
		PROCESS_DIRECT_BLOCKS(, 32);
		PREPARE_INDIRECT_BLOCKS(, 32, 0);
	} else if (db_format == PFS_FORMAT_64) {
		needed_block_count = BLOCK_COUNT(, 64);
		PROCESS_DIRECT_BLOCKS(, 64);
		PREPARE_INDIRECT_BLOCKS(, 64, 0);
	} else if (db_format == PFS_FORMAT_32_SIGNED) {
		needed_block_count = BLOCK_COUNT(s, 32);
		PROCESS_DIRECT_BLOCKS(s, 32);
		PREPARE_INDIRECT_BLOCKS(s, 32, 0);
	} else if (db_format == PFS_FORMAT_64_SIGNED) {
		needed_block_count = BLOCK_COUNT(s, 64);
		PROCESS_DIRECT_BLOCKS(s, 64);
		PREPARE_INDIRECT_BLOCKS(s, 64, 0);
	} else {
		assert(0);
		goto error;
	}

	if (ib_format == PFS_FORMAT_32)
		PROCESS_INDIRECT_BLOCKS_0(, 32);
	else if (ib_format == PFS_FORMAT_64)
		PROCESS_INDIRECT_BLOCKS_0(, 64);
	else if (ib_format == PFS_FORMAT_32_SIGNED)
		PROCESS_INDIRECT_BLOCKS_0(s, 32);
	else if (ib_format == PFS_FORMAT_64_SIGNED)
		PROCESS_INDIRECT_BLOCKS_0(s, 64);

	if (db_format == PFS_FORMAT_32)
		PREPARE_INDIRECT_BLOCKS(, 32, 1);
	if (db_format == PFS_FORMAT_64)
		PREPARE_INDIRECT_BLOCKS(, 64, 1);
	if (db_format == PFS_FORMAT_32_SIGNED)
		PREPARE_INDIRECT_BLOCKS(s, 32, 1);
	if (db_format == PFS_FORMAT_64_SIGNED)
		PREPARE_INDIRECT_BLOCKS(s, 64, 1);

	if (ib_format == PFS_FORMAT_32)
		PROCESS_INDIRECT_BLOCKS_1(, 32);
	else if (ib_format == PFS_FORMAT_64)
		PROCESS_INDIRECT_BLOCKS_1(, 64);
	else if (ib_format == PFS_FORMAT_32_SIGNED)
		PROCESS_INDIRECT_BLOCKS_1(s, 32);
	else if (ib_format == PFS_FORMAT_64_SIGNED)
		PROCESS_INDIRECT_BLOCKS_1(s, 64);

	if (db_format == PFS_FORMAT_32)
		PREPARE_INDIRECT_BLOCKS(, 32, 2);
	if (db_format == PFS_FORMAT_64)
		PREPARE_INDIRECT_BLOCKS(, 64, 2);
	if (db_format == PFS_FORMAT_32_SIGNED)
		PREPARE_INDIRECT_BLOCKS(s, 32, 2);
	if (db_format == PFS_FORMAT_64_SIGNED)
		PREPARE_INDIRECT_BLOCKS(s, 64, 2);

	if (ib_format == PFS_FORMAT_32)
		PROCESS_INDIRECT_BLOCKS_2(, 32);
	else if (ib_format == PFS_FORMAT_64)
		PROCESS_INDIRECT_BLOCKS_2(, 64);
	else if (ib_format == PFS_FORMAT_32_SIGNED)
		PROCESS_INDIRECT_BLOCKS_2(s, 32);
	else if (ib_format == PFS_FORMAT_64_SIGNED)
		PROCESS_INDIRECT_BLOCKS_2(s, 64);

#undef BLOCK_COUNT
#undef PROCESS_DIRECT_BLOCKS
#undef PROCESS_INDIRECT_BLOCKS_1
#undef PROCESS_INDIRECT_BLOCKS_2
#undef PROCESS_INDIRECT_BLOCKS_3

success:
	if (needed_block_count > 0) {
		assert(block_list->count == needed_block_count);
	}

done:
	if (u0.block_buf)
		free(u0.block_buf);
	if (u1.block_buf)
		free(u1.block_buf);
	if (u2.block_buf)
		free(u2.block_buf);

	return block_list;

error:
	if (block_list) {
		pfs_free_block_list(pfs, block_list);
		block_list = NULL;
	}

	goto done;
}

void pfs_free_block_list(struct pfs* pfs, struct pfs_block_list* block_list) {
	assert(pfs != NULL);

	UNUSED(pfs);

	if (!block_list)
		return;

	if (block_list->blocks)
		free(block_list->blocks);

	free(block_list);
}

int pfs_get_idblock_offset(struct pfs* pfs, int64_t block_counter, uint32_t* level_offsets, int* level_count) {
	int64_t next_count;
	uint32_t offset;
	uint32_t* level_offset;
	int64_t* indirect_ptrs_per_block;
	int max_level, level;
	int status = 0;

	assert(pfs != NULL);
	assert(level_offsets != NULL);
	assert(level_count != NULL);

	if (block_counter <= PFS_DIRECT_BLOCK_MAX_COUNT) { // not indirect block?
		warning("Not indirect block: %" PRIuMAX, (uintmax_t)block_counter);
		goto error;
	}

	block_counter -= PFS_DIRECT_BLOCK_MAX_COUNT;
	max_level = 0;

	if (block_counter > pfs->indirect_ptrs_per_block_for_level[0]) {
		max_level = 0;
		while (max_level + 1 < PFS_INDIRECT_BLOCK_MAX_COUNT) {
			block_counter -= pfs->indirect_ptrs_per_block_for_level[max_level];
			next_count = pfs->indirect_ptrs_per_block_for_level[max_level + 1];
			++max_level;
			if (block_counter <= next_count)
				break;
		}

		if (max_level > PFS_INDIRECT_BLOCK_MAX_COUNT) {
			warning("No level matches block: %" PRIuMAX, (uintmax_t)block_counter);
			goto error;
		}
	}

	level = max_level;
	level_offset = level_offsets + level;
	indirect_ptrs_per_block = &pfs->indirect_ptrs_per_block_for_level[level];

	do {
		if (block_counter != 0) {
			offset = (uint32_t)((block_counter - 1) % (*indirect_ptrs_per_block));
			*level_offset = offset;
			if (level < max_level) {
				assert(level > 0);
				*level_offset = (uint32_t)(offset / *(indirect_ptrs_per_block - 1));
			}
		} else {
			*level_offset = 0;
		}

		--level;
		--level_offset;
		++indirect_ptrs_per_block;
	} while (level >= 0); // FIXME: check

	*level_count = level + 1;

	status = 1;

error:
	return status;
}

int pfs_get_block_no_sino(struct pfs* pfs, const struct pfs_dinode* dinode, uint64_t block_counter, uint64_t* block_no, uint32_t* sino) { // FIXME
	uint32_t flags;
	uint64_t max_block_count;
	int status = 0;

	assert(pfs != NULL);
	assert(dinode != NULL);
	assert(block_no != NULL);

	flags = LE32(pfs->hdr.super_root_dinode.flags);
	switch (pfs->format) {
		case PFS_FORMAT_32: max_block_count = LE32(pfs->hdr.super_root_dinode.di32.block_count); break;
		case PFS_FORMAT_64: max_block_count = LE64(pfs->hdr.super_root_dinode.di64.block_count); break;
		case PFS_FORMAT_32_SIGNED: max_block_count = LE32(pfs->hdr.super_root_dinode.sdi32.block_count); break;
		case PFS_FORMAT_64_SIGNED: max_block_count = LE64(pfs->hdr.super_root_dinode.sdi64.block_count); break;
		default:
			assert(0);
			goto error;
	}

	if (max_block_count >= block_counter + 1) {
		if ((flags & 0x10) != 0) {
			if (!pfs->is_signed) {
				if (pfs_is_super_root_dinode(pfs, dinode)) { // super root?
					*block_no = LE64(dinode->sdi64.direct_blocks[0].block_no);
				} else if (pfs->format == PFS_FORMAT_64) {
					*block_no = LE64(dinode->di64.direct_blocks[0].block_no);
				} else {
					*block_no = LE64(dinode->di32.direct_blocks[0].block_no);
				}
				*block_no += block_counter;
				goto done;
			}
		}

		if (block_counter + 1 > PFS_DIRECT_BLOCK_MAX_COUNT) {
			uint32_t level_offsets[PFS_INDIRECT_BLOCK_MAX_COUNT];
			int level_count;
			if (!pfs_get_idblock_offset(pfs, block_counter + 1, level_offsets, &level_count)) {
				warning("Unable to get id block offset for %u.", block_counter + 1);
				goto error;
			}

			error("TODO: 0xFFFFFFFF827D5834");
		} else {
			*block_no = LE64(dinode->sdi64.direct_blocks[block_counter].block_no);
			if (sino)
				*sino = 0;
		}
	} else {
		warning("No blocks: %u/%u", block_counter + 1, max_block_count);
		goto error;
	}

done:
	status = 1;

error:
	return status;
}
