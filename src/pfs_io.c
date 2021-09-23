#include "pfs.h"
#include "compression.h"
#include "util.h"

static int pfsc_compress(uint8_t* in, size_t* in_size, uint8_t* out, size_t* out_size);
static int pfsc_decompress(uint8_t* in, size_t* in_size, uint8_t* out, size_t* out_size);

int pfs_io_get_size(struct pfs* pfs, uint64_t* size) {
	assert(pfs != NULL);

	return (*pfs->io->get_size)(pfs->io->arg, size);
}

int pfs_io_get_outer_location(struct pfs* pfs, uint64_t offset, uint64_t* outer_offset) {
	assert(pfs != NULL);

	return (*pfs->io->get_outer_location)(pfs->io->arg, offset, outer_offset);
}

int pfs_io_get_offset_size(struct pfs* pfs, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed) {
	assert(pfs != NULL);

	return (*pfs->io->get_offset_size)(pfs->io->arg, data_size, real_offset, size_to_read, compressed);
}

int pfs_io_seek(struct pfs* pfs, uint64_t offset) {
	assert(pfs != NULL);

	return (*pfs->io->seek)(pfs->io->arg, offset);
}

int pfs_io_read(struct pfs* pfs, void* data, uint64_t data_size) {
	assert(pfs != NULL);
	assert(data != NULL);

	return (*pfs->io->read)(pfs->io->arg, data, data_size);
}

int pfs_io_write(struct pfs* pfs, void* data, uint64_t data_size) {
	assert(pfs != NULL);
	assert(data != NULL);

	return (*pfs->io->write)(pfs->io->arg, data, data_size);
}

int pfs_io_can_seek(struct pfs* pfs, uint64_t offset) {
	assert(pfs != NULL);

	return (*pfs->io->seek)(pfs->io->arg, offset);
}

int pfs_io_can_read(struct pfs* pfs, uint64_t data_size) {
	assert(pfs != NULL);

	return (*pfs->io->can_read)(pfs->io->arg, data_size);
}

int pfs_io_can_write(struct pfs* pfs, uint64_t data_size) {
	assert(pfs != NULL);

	return (*pfs->io->can_write)(pfs->io->arg, data_size);
}

static int pfs_file_get_offset_size_raw(struct pfs_file_context* file, uint64_t offset, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed) {
	struct pfs* pfs;
	uint64_t* blocks;
	uint64_t start_block, end_block, block_count;
	uint64_t start_offset, cur_offset, cur_real_offset, first_real_offset;
	uint64_t cur_size, cur_size_real, total_size;
	int cur_compressed, any_compressed;
	uint64_t i;
	int status = 0;

	assert(file != NULL);

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->block_list != NULL);
	blocks = file->block_list->blocks;
	assert(blocks != NULL);

	start_block = pfs_offset_to_block_no(pfs, offset);
	start_offset = pfs_offset_in_block(pfs, offset);
	block_count = pfs_offset_to_block_no(pfs, align_up(data_size, pfs->basic_block_size));
	end_block = start_block + block_count;

	if (block_count > file->block_list->count)
		goto error;

	for (i = start_block, first_real_offset = 0, total_size = 0, any_compressed = 0; i < end_block; ++i) {
		cur_size = pfs_lbn_to_size(pfs, file->file_size, i);
		if (total_size + cur_size > data_size)
			cur_size = data_size - total_size;

		cur_offset = start_offset + pfs_block_no_to_offset(pfs, blocks[i]);
		if (!pfs_io_seek(pfs, cur_offset)) {
			warning("Unable to seek to offset 0x%" PRIX64 ".", cur_offset);
			goto error;
		}
		if (!pfs_io_get_offset_size(pfs, cur_size, &cur_real_offset, &cur_size_real, &cur_compressed)) {
			warning("Unable to read data at 0x%" PRIX64 " of size 0x%" PRIX64 ".", cur_offset, cur_size);
			goto error;
		}
		if (i == start_block)
			first_real_offset = cur_real_offset;

		if (cur_compressed)
			any_compressed = 1;

		total_size += cur_size_real;
	}

	if (real_offset)
		*real_offset = first_real_offset;

	if (size_to_read)
		*size_to_read = total_size;

	if (compressed)
		*compressed = any_compressed;

	status = 1;

error:
	return status;
}

static int pfs_file_get_offset_size_compressed(struct pfs_file_context* file, uint64_t offset, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed) {
	struct pfs* pfs;
	uint64_t* block_offsets;
	uint64_t start_block, end_block;
	uint64_t block_size, block_count, total_block_count;
	uint64_t cur_size, total_size;
	uint64_t i;
	int status = 0;

	assert(file != NULL);

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->cmp.loaded != 0);

	assert(file->cmp.block_offsets != NULL);
	block_offsets = file->cmp.block_offsets;

	start_block = offset >> file->cmp.block_size_shift;
	block_size = file->cmp.block_size;
	block_count = align_up(data_size, block_size) >> file->cmp.block_size_shift;
	total_block_count = file->cmp.block_count;
	end_block = start_block + block_count;

	if (block_count > total_block_count)
		goto error;

	for (i = start_block, total_size = 0; i < end_block; ++i) {
		cur_size = block_offsets[i + 1] - block_offsets[i];
		total_size += cur_size;
	}

	if (real_offset)
		*real_offset = block_count > 0 ? (offset + block_offsets[0]) : offset;

	if (size_to_read)
		*size_to_read = total_size;

	if (compressed)
		*compressed = 1;

	status = 1;

error:
	return status;
}

int pfs_file_get_outer_location(struct pfs_file_context* file, uint64_t offset, uint64_t* outer_offset) {
	struct pfs* pfs;
	uint64_t start_block;
	uint64_t* block_offsets, block_offset;
	int status = 0;

	assert(file != NULL);

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->block_list != NULL);
	assert(file->block_list->count != 0);
	assert(file->block_list->blocks != NULL);

	if (!(file->flags & PFS_FILE_COMPRESSED)) {
		start_block = pfs_offset_to_block_no(pfs, offset);
		block_offset = pfs_block_no_to_offset(pfs, file->block_list->blocks[start_block]);

		if (!pfs_io_get_outer_location(pfs, block_offset, outer_offset)) {
			warning("Unable to get outer location for block with offset 0x%" PRIX64 ".", block_offset);
			goto error;
		}
	} else if (file->flags & PFS_FILE_COMPRESSED) {
		assert(file->cmp.loaded != 0);

		assert(file->cmp.block_offsets != NULL);
		block_offsets = file->cmp.block_offsets;

		start_block = offset >> file->cmp.block_size_shift;
		block_offset = block_offsets[start_block];

		start_block = pfs_offset_to_block_no(pfs, block_offset);
		block_offset = pfs_block_no_to_offset(pfs, file->block_list->blocks[start_block]);

		if (!pfs_io_get_outer_location(pfs, block_offset, outer_offset)) {
			warning("Unable to get outer location for block with offset 0x%" PRIX64 ".", block_offset);
			goto error;
		}
	}

	status = 1;

error:
	return status;
}

int pfs_file_get_offset_size(struct pfs_file_context* file, uint64_t offset, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed) {
	struct pfs* pfs;
	int status = 0;

	UNUSED(pfs);

	assert(file != NULL);

	if (offset + data_size > file->file_size)
		goto error;

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->block_list->count != 0);

	if (!(file->flags & PFS_FILE_COMPRESSED)) {
		if (!pfs_file_get_offset_size_raw(file, offset, data_size, real_offset, size_to_read, compressed))
			goto error;
	} else if (file->flags & PFS_FILE_COMPRESSED) {
		assert(file->cmp.loaded != 0);

		if (!pfs_file_get_offset_size_compressed(file, offset, data_size, real_offset, size_to_read, compressed))
			goto error;
	}

	status = 1;

error:
	return status;
}

int pfs_file_read_raw(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size) {
	struct pfs* pfs;
	uint64_t* blocks;
	uint64_t start_block, end_block, block_count;
	uint64_t start_offset, cur_size, processed_size;
	uint8_t* cur_data;
	uint64_t i;
	unsigned int read_block_count;
	int status = 0;

	assert(file != NULL);
	assert(data != NULL);

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->block_list != NULL);
	blocks = file->block_list->blocks;
	assert(blocks != NULL);

	start_block = pfs_offset_to_block_no(pfs, offset);
	start_offset = pfs_offset_in_block(pfs, offset);
	block_count = pfs_offset_to_block_no(pfs, align_up(data_size, pfs->basic_block_size));
	end_block = start_block + block_count;
	read_block_count = start_offset > 0 ? 2 : 1;
	cur_data = (uint8_t*)data;

	if (block_count > file->block_list->count)
		goto error;

	for (i = start_block, processed_size = 0; i < end_block; ++i) {
		cur_size = pfs_lbn_to_size(pfs, file->file_size, i);
		if (processed_size + cur_size > data_size)
			cur_size = data_size - processed_size;

		if (!pfs_read_blocks(pfs, blocks[i], file->tmp_block, (i + 1) < file->block_list->count ? read_block_count : 1))
			goto error;

		memcpy(cur_data, file->tmp_block + start_offset, cur_size);

		cur_data += cur_size;
		processed_size += cur_size;
	}

	status = 1;

error:
	return status;
}

int pfs_file_write_raw(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size) {
	struct pfs* pfs;
	uint64_t* blocks;
	uint64_t start_block, end_block, block_count;
	uint64_t start_offset, cur_size, processed_size;
	uint8_t* cur_data;
	uint64_t i;
	unsigned int write_block_count;
	int status = 0;

	assert(file != NULL);
	assert(data != NULL);

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->block_list != NULL);
	blocks = file->block_list->blocks;
	assert(blocks != NULL);

	start_block = pfs_offset_to_block_no(pfs, offset);
	start_offset = pfs_offset_in_block(pfs, offset);
	block_count = pfs_offset_to_block_no(pfs, align_up(data_size, pfs->basic_block_size));
	end_block = start_block + block_count;
	write_block_count = start_offset > 0 ? 2 : 1;
	cur_data = (uint8_t*)data;

	if (block_count > file->block_list->count)
		goto error;

	for (i = start_block, processed_size = 0; i < end_block; ++i) {
		cur_size = pfs_lbn_to_size(pfs, file->file_size, i);
		if (processed_size + cur_size > data_size)
			cur_size = data_size - processed_size;

		if (!pfs_write_blocks(pfs, blocks[i], file->tmp_block, (i + 1) < file->block_list->count ? write_block_count : 1))
			goto error;

		memcpy(cur_data, file->tmp_block + start_offset, cur_size);

		cur_data += cur_size;
		processed_size += cur_size;
	}

	status = 1;

error:
	return status;
}

static int pfs_file_read_compressed(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size) {
	struct pfs* pfs;
	uint64_t* block_offsets;
	uint64_t start_block, end_block;
	uint64_t block_size, block_count, total_block_count;
	uint64_t start_offset, total_size, processed_size;
	uint8_t* cur_data;
	uint8_t* work_data_in;
	uint8_t* work_data_out;
	size_t compressed_size, decompressed_size, cur_size;
	uint64_t i;
	int status = 0;

	UNUSED(pfs);

	assert(file != NULL);
	assert(data != NULL);

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->cmp.loaded != 0);

	assert(file->cmp.block_offsets != NULL);
	block_offsets = file->cmp.block_offsets;

	assert(file->cmp.work_data != NULL);
	work_data_in = file->cmp.work_data;
	work_data_out = work_data_in + PFSC_WORK_DATA_SIZE / 2;

	start_block = offset >> file->cmp.block_size_shift;
	block_size = file->cmp.block_size;
	block_count = align_up(data_size, block_size) >> file->cmp.block_size_shift;
	total_block_count = file->cmp.block_count;
	total_size = file->cmp.rounded_file_size;
	end_block = start_block + block_count;
	start_offset = offset & file->cmp.block_size_qmask;
	cur_data = (uint8_t*)data;

	if (block_count > total_block_count)
		goto error;

	for (i = start_block, processed_size = 0; i < end_block; ++i) {
		if (!pfs_file_read_raw(file, block_offsets[i], work_data_in, block_size))
			goto error;

		compressed_size = block_offsets[i + 1] - block_offsets[i];

		if (compressed_size == block_size) {
just_copy:
			cur_size = (i + 1 < end_block) ? (block_size - start_offset) : (data_size - processed_size);
			memcpy(cur_data, work_data_in + start_offset, cur_size);
		} else {
			decompressed_size = (i + 1) < total_block_count ? block_size : (total_size - (total_block_count - 1) * block_size);

			if (decompressed_size < compressed_size)
				goto just_copy;

			if (!pfsc_decompress(work_data_in, &compressed_size, work_data_out, &decompressed_size))
				goto error;

			cur_size = (i + 1 < end_block) ? (decompressed_size - start_offset) : (data_size - processed_size);

			memcpy(cur_data, work_data_out + start_offset, cur_size);
		}

		cur_data += cur_size;
		processed_size += cur_size;
	}

	status = 1;

error:
	return status;
}

static int pfs_file_write_compressed(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size) {
	/* TODO */
	assert(0 && "Unimplemented.");

	UNUSED(file);
	UNUSED(offset);
	UNUSED(data);
	UNUSED(data_size);

	return 0;
}

int pfs_file_read(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size) {
	struct pfs* pfs;
	int status = 0;

	UNUSED(pfs);

	assert(file != NULL);
	assert(data != NULL);

	if (offset + data_size > file->file_size)
		goto error;

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->block_list->count != 0);

	if (!(file->flags & PFS_FILE_COMPRESSED)) {
		if (!pfs_file_read_raw(file, offset, data, data_size))
			goto error;
	} else if (file->flags & PFS_FILE_COMPRESSED) {
		assert(file->cmp.loaded != 0);

		if (!pfs_file_read_compressed(file, offset, data, data_size))
			goto error;
	}

	status = 1;

error:
	return status;
}

int pfs_file_write(struct pfs_file_context* file, uint64_t offset, void* data, uint64_t data_size) {
	struct pfs* pfs;
	int status = 0;

	UNUSED(pfs);

	assert(file != NULL);
	assert(data != NULL);

	if (offset + data_size > file->file_size)
		goto error;

	pfs = file->pfs;
	assert(pfs != NULL);

	assert(file->block_list->count != 0);

	if (!(file->flags & PFS_FILE_COMPRESSED)) {
		if (!pfs_file_write_raw(file, offset, data, data_size))
			goto error;
	} else if (file->flags & PFS_FILE_COMPRESSED) {
		assert(file->cmp.loaded != 0);

		if (!pfs_file_write_compressed(file, offset, data, data_size))
			goto error;
	}

	status = 1;

error:
	return status;
}

int pfs_read_blocks(struct pfs* pfs, uint64_t block_no, void* data, uint64_t block_count) {
	uint64_t offset, data_size;
#ifdef COMPUTE_BLOCK_DIGEST
	uint8_t block_digest[PFS_HASH_SIZE];
#endif
	int status = 0;

	assert(pfs != NULL);
	assert(data != NULL);

	offset = pfs_block_no_to_offset(pfs, block_no);
	data_size = pfs_block_no_to_offset(pfs, block_count);

	if (!pfs_io_seek(pfs, offset)) {
		warning("Unable to seek to offset 0x%" PRIX64 ".", offset);
		goto error;
	}
	if (!pfs_io_read(pfs, data, data_size)) {
		warning("Unable to read data at 0x%" PRIX64 " of size 0x%" PRIXMAX ".", offset, (uintmax_t)data_size);
		goto error;
	}

	if (pfs_check_cipher_block(pfs, NULL, 1)) {
		assert(pfs->is_encrypted != 0);

#ifdef COMPUTE_BLOCK_DIGEST
		/* TODO */
		pfs_sign_buffer(pfs, data, data_size, block_digest);
#endif

		pfs_decrypt(pfs, data, data, offset, data_size);

		// TODO: check icv
	}

	status = 1;

error:
	return status;
}

int pfs_write_blocks(struct pfs* pfs, uint64_t block_no, void* data, uint64_t block_count) {
	uint64_t offset, data_size;
	int status = 0;

	assert(pfs != NULL);
	assert(data != NULL);

	offset = pfs_block_no_to_offset(pfs, block_no);
	data_size = pfs_block_no_to_offset(pfs, block_count);

	if (pfs_check_cipher_block(pfs, NULL, 1)) {
		assert(pfs->is_encrypted != 0);
		pfs_encrypt(pfs, data, data, offset, data_size);

		// TODO: check icv
	}

	if (!pfs_io_seek(pfs, offset)) {
		warning("Unable to seek to offset 0x%" PRIX64 ".", offset);
		goto error;
	}
	if (!pfs_io_write(pfs, data, data_size)) {
		warning("Unable to write data at 0x%" PRIX64 " of size 0x%" PRIXMAX ".", offset, (uintmax_t)data_size);
		goto error;
	}

	status = 1;

error:
	return status;
}

static int pfsc_compress(uint8_t* in, size_t* in_size, uint8_t* out, size_t* out_size) {
	int status = 0;

	status = zlib_compress((const uint8_t*)in, in_size, out, out_size, PFSC_ZLIB_WINDOW_BITS, PFSC_ZLIB_LEVEL);
	if (!status)
		goto error;

error:
	return status;
}

static int pfsc_decompress(uint8_t* in, size_t* in_size, uint8_t* out, size_t* out_size) {
	int status = 0;

	status = zlib_decompress((const uint8_t*)in, in_size, out, out_size, PFSC_ZLIB_WINDOW_BITS);
	if (!status)
		goto error;

error:
	return status;
}
