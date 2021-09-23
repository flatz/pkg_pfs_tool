#include "pfs.h"

int pfs_get_dinode(struct pfs* pfs, pfs_ino ino, struct pfs_dinode* dinode, uint64_t* out_dinode_block_no, size_t* out_dinode_offset) {
	size_t idx1, idx2;
	uint64_t block_no;
	size_t dinode_offset;
	uint8_t* block = NULL;
	int status = 0;

	assert(pfs != NULL);
	assert(dinode != NULL);

	idx1 = ino / pfs->inodes_per_block;
	idx2 = ino % pfs->inodes_per_block;

	if (!pfs_get_block_no_sino(pfs, &pfs->hdr.super_root_dinode, idx1, &block_no, NULL))
		goto error;

	dinode_offset = idx2 * pfs->dinode_struct_size;

	block = (uint8_t*)malloc(pfs->basic_block_size);
	if (!block)
		goto error;
	memset(block, 0, pfs->basic_block_size);

	if (!pfs_read_blocks(pfs, block_no, block, 1))
		goto error;

	memcpy(dinode, block + dinode_offset, pfs->dinode_struct_size);

	if (out_dinode_block_no)
		*out_dinode_block_no = block_no;
	if (out_dinode_offset)
		*out_dinode_offset = dinode_offset;

	status = 1;

error:
	if (block)
		free(block);

	return status;
}

int pfs_put_dinode(struct pfs* pfs, uint64_t dinode_block_no, size_t dinode_offset, struct pfs_dinode* dinode) {
	uint8_t* block = NULL;
	int status = 0;

	assert(pfs != NULL);
	assert(dinode != NULL);

	block = (uint8_t*)malloc(pfs->basic_block_size);
	if (!block)
		goto error;
	memset(block, 0, pfs->basic_block_size);

	if (!pfs_read_blocks(pfs, dinode_block_no, block, 1))
		goto error;

	memcpy(block + dinode_offset, &dinode, pfs->dinode_struct_size);

	if (!pfs_write_blocks(pfs, dinode_block_no, block, 1))
		goto error;

	status = 1;

error:
	if (block)
		free(block);

	return status;
}
