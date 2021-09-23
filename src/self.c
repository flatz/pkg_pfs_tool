#include "self.h"
#include "compression.h"
#include "crypto.h"
#include "util.h"

struct elf* elf_alloc(void* data, size_t size, int is_inner) {
	struct elf* elf = NULL;
	uint32_t magic = ELF_MAGIC;

	assert(data != NULL);

	if (!has_magic(data, size, &magic, sizeof(magic))) {
		error("Invalid elf magic.");
		goto error;
	}
	if (size < sizeof(*elf->ehdr)) {
		error("Insufficient elf size: 0x%" PRIXMAX, size);
		goto error;
	}

	elf = (struct elf*)malloc(sizeof(*elf));
	if (!elf)
		goto error;
	memset(elf, 0, sizeof(*elf));

	elf->data = (uint8_t*)data;
	elf->size = size;
	elf->is_inner = is_inner;

	elf->ehdr = (struct elf64_ehdr*)elf->data;
	if (ELF64_HALF_LE(elf->ehdr->e_ehsize) != sizeof(*elf->ehdr)) {
		error("Invalid elf header size: 0x%X", ELF64_HALF_LE(elf->ehdr->e_ehsize));
		goto error;
	}
	elf->phdrs = (struct elf64_phdr*)(elf->data + ELF64_OFF_LE(elf->ehdr->e_phoff));
	if (ELF64_HALF_LE(elf->ehdr->e_phentsize) != sizeof(*elf->phdrs)) {
		error("Invalid elf program header entry size: 0x%X", ELF64_HALF_LE(elf->ehdr->e_phentsize));
		goto error;
	}
	elf->shdrs = (struct elf64_shdr*)(elf->data + ELF64_OFF_LE(elf->ehdr->e_shoff));
	if (ELF64_HALF_LE(elf->ehdr->e_shnum) > 0 && ELF64_HALF_LE(elf->ehdr->e_shentsize) != sizeof(*elf->shdrs)) {
		error("Invalid elf section header entry size: 0x%X", ELF64_HALF_LE(elf->ehdr->e_shentsize));
		goto error;
	}

	if (!elf->is_inner) {
		elf->ex_info = (struct elf_extended_info*)(elf->data + ELF_EX_INFO_OFFSET);
		if (elf->ex_info->size != 0 && elf->ex_info->size != sizeof(elf->ex_info->info1) && elf->ex_info->size != sizeof(elf->ex_info->info2)) {
			error("Invalid elf extended info size: 0x%X", elf->ex_info->size);
			goto error;
		}
	} else {
		elf->ex_info = 0;
	}

	return elf;

error:
	if (elf)
		free(elf);

	return NULL;
}

void elf_free(struct elf* elf) {
	if (!elf)
		return;

	free(elf);
}

struct self* self_alloc(void* data, size_t size) {
	struct self* self = NULL;
	uint32_t magic = SELF_MAGIC;
	size_t elf_offset, elf_header_size;

	assert(data != NULL);

	if (!has_magic(data, size, &magic, sizeof(magic))) {
		error("Invalid self magic.");
		goto error;
	}
	if (size < sizeof(*self->hdr)) {
		error("Insufficient self size: 0x%" PRIXMAX, size);
		goto error;
	}

	self = (struct self*)malloc(sizeof(*self));
	if (!self)
		goto error;
	memset(self, 0, sizeof(*self));

	self->data = (uint8_t*)data;
	self->size = size;

	self->hdr = (struct self_hdr*)self->data;
	if (self->hdr->version != SELF_VERSION)
		error("Unsupported self version: 0x%02X", self->hdr->version);
	if (self->hdr->mode != SELF_MODE)
		error("Unsupported self mode: 0x%02X", self->hdr->mode);
	if (self->hdr->endian != SELF_ENDIANNESS)
		error("Unsupported self endianness: 0x%02X", self->hdr->endian);
	if (self->hdr->attr != SELF_ATTRIBUTE)
		error("Unsupported self attribute: 0x%02X", self->hdr->attr);

	self->entry_table = (struct self_entry*)(self->data + sizeof(*self->hdr));
	self->entry_count = LE16(self->hdr->entry_count);

	elf_offset = align_up(sizeof(*self->hdr) + sizeof(*self->entry_table) * self->entry_count, 16);
	self->elf = elf_alloc(self->data + elf_offset, size - elf_offset, 1);
	if (!self->elf) {
		error("Unable to allocate elf object.");
		goto error;
	}
	elf_header_size = MAX(
		(size_t)ELF64_HALF_LE(self->elf->ehdr->e_ehsize),
		(size_t)ELF64_OFF_LE(self->elf->ehdr->e_phoff) + (size_t)ELF64_HALF_LE(self->elf->ehdr->e_phentsize) * ELF64_HALF_LE(self->elf->ehdr->e_phnum)
	);
	elf_header_size = align_up(elf_header_size, 16);

	self->ex_info = (struct self_extended_info*)(self->data + elf_offset + elf_header_size);

	self->npdrm_control_block = (struct self_npdrm_control_block*)((uint8_t*)self->ex_info + sizeof(*self->ex_info));
	if (LE16(self->npdrm_control_block->type) != SELF_CONTROL_BLOCK_NPDRM)
		self->npdrm_control_block = NULL;

	return self;

error:
	if (self) {
		if (self->elf)
			elf_free(self->elf);

		free(self);
	}

	return NULL;
}

void self_free(struct self* self) {
	if (!self)
		return;

	if (self->elf)
		elf_free(self->elf);

	free(self);
}

static int self_make_paid_ptype(struct self* self, struct elf* elf) {
	unsigned int elf_type;
	size_t ex_info_size;
	uint32_t paid_lo;
	int status = 0;

	assert(self != NULL);
	assert(elf != NULL);

	elf_type = ELF64_HALF_LE(elf->ehdr->e_type);
	ex_info_size = elf->ex_info ? elf->ex_info->size : 0;

	if (ex_info_size == 0) {
		if (elf_type == ELF_ET_EXEC || elf_type == ELF_ET_SCE_EXEC || elf_type == ELF_ET_SCE_EXEC_ASLR)
			paid_lo = 0x1;
		else
			paid_lo = 0x2;
	} else if (ex_info_size == 0x40) {
		if (elf_type == ELF_ET_EXEC || elf_type == ELF_ET_SCE_EXEC || elf_type == ELF_ET_SCE_EXEC_ASLR)
			paid_lo = 0x1101;
		else
			paid_lo = 0x1102;
	} else if (ex_info_size == 0x80) {
		if (elf_type == ELF_ET_EXEC || elf_type == ELF_ET_SCE_EXEC || elf_type == ELF_ET_SCE_EXEC_ASLR)
			paid_lo = 0x1001;
		else
			paid_lo = 0x1002;
	} else {
		goto error;
	}

	self->ex_info->paid = LE64((U64C(0x31000000) << 32) | paid_lo);
	self->ex_info->ptype = LE64(SELF_PTYPE_FAKE);

	status = 1;

error:
	return status;
}

int self_make_fake_signed(struct self* self, struct elf* elf) {
	int status = 0;
	struct self_entry* entry;
	struct self_entry* linked_entry;
	struct elf64_phdr* phdr;
	struct elf64_phdr* cur_phdr;
	union self_entry_flags entry_flags;
	uint8_t* elf_segment_data;
	size_t elf_segment_size;
	uint8_t* self_segment_data;
	size_t self_segment_size;
	uint8_t* self_block_table_segment_data;
	size_t self_block_table_segment_size;
	size_t block_size, last_block_size, block_count;
	uint8_t* meta_data;
	size_t meta_data_size;
	struct self_meta_block* meta_blocks;
	struct self_meta_footer* meta_footer;
	uint8_t* in_data;
	size_t in_size, in_size_orig;
	uint8_t* out_data = NULL;
	size_t out_capacity;
	size_t out_size, total_out_size, tmp_out_size;
	size_t extent_offset, extent_size;
	struct self_segment_block_digest* block_digests;
	struct self_segment_block_extent* block_extents;
	int window_bits, cmp_level;
	int has_digests, has_extents;
	size_t phdr_idx = 0;
	size_t i, j;

	assert(self != NULL);
	assert(elf != NULL);

	meta_data = self->data + self->hdr->header_size;
	meta_data_size = LE16(self->hdr->meta_size);
	if (meta_data_size < (sizeof(*meta_blocks) * self->entry_count + sizeof(*meta_footer)))
		error("Invalid meta data size.");

	meta_blocks = (struct self_meta_block*)meta_data;
	memset(meta_blocks, 0, sizeof(*meta_blocks) * self->entry_count);

	meta_footer = (struct self_meta_footer*)(meta_data + sizeof(*meta_blocks) * self->entry_count);
	memset(meta_footer, 0, sizeof(*meta_footer));
	meta_footer->unk1 = LE32(1);
	memset(meta_footer->signature, 0, sizeof(meta_footer->signature));

	if (!self_make_paid_ptype(self, elf))
		error("Unsupported elf type.");

	self->ex_info->fw_version = 0;

	sha256_buffer(elf->data, elf->size, self->ex_info->file_hash);

	if (self->npdrm_control_block) {
		memset(self->npdrm_control_block->content_id, 0, sizeof(self->npdrm_control_block->content_id));
		memset(self->npdrm_control_block->random_pad, 0, sizeof(self->npdrm_control_block->random_pad));
	}

	for (i = 0; i < self->entry_count; ++i) {
		entry = self->entry_table + i;

		entry_flags.bitmask = LE64(entry->flags.bitmask);
		entry_flags.is_encrypted = 0;
		entry_flags.is_signed = 0;
		entry->flags.bitmask = LE64(entry_flags.bitmask);

		if (!self_entry_is_segment_with_blocks(entry))
			continue;

		linked_entry = self_find_linked_entry(self, entry, &j);
		if (!linked_entry)
			error("Unable to find linked entry.");
		if (LE64(linked_entry->compressed_size) != LE64(linked_entry->uncompressed_size))
			error("Invalid block table segment size.");

		phdr = NULL;
		for (phdr = NULL; !phdr && phdr_idx < ELF64_HALF_LE(elf->ehdr->e_phnum); ++phdr_idx) {
			cur_phdr = elf->phdrs + phdr_idx;
			switch (ELF64_WORD_LE(cur_phdr->p_type)) {
				case ELF_PT_LOAD:
				case ELF_PT_SCE_RELRO:
				case ELF_PT_SCE_DYNLIBDATA:
				case ELF_PT_SCE_COMMENT:
					phdr = cur_phdr;
					break;
				default:
					continue;
			}
		}
		if (!phdr)
			error("Unable to find corresponding elf program segment.");

		elf_segment_data = elf->data + ELF64_OFF_LE(phdr->p_offset);
		elf_segment_size = ELF64_XWORD_LE(phdr->p_filesz);

		block_size = self_entry_block_size(entry);
		block_count = elf_segment_size / block_size;
		if (elf_segment_size > block_count * block_size) {
			last_block_size = elf_segment_size - block_count * block_size;
			++block_count;
		} else {
			last_block_size = block_size;
		}

		self_block_table_segment_data = self->data + LE64(linked_entry->offset);
		self_block_table_segment_size = LE64(linked_entry->uncompressed_size);
		self_segment_data = self->data + LE64(entry->offset);
		self_segment_size = LE64(entry->compressed_size);

		has_digests = self_entry_has_digests(linked_entry);
		has_extents = self_entry_has_extents(linked_entry);
		if (has_digests && has_extents) {
			if (self_block_table_segment_size != (SELF_HASH_SIZE + sizeof(*block_extents)) * block_count)
				error("Invalid block table segment size.");
			block_digests = (struct self_segment_block_digest*)self_block_table_segment_data;
			block_extents = (struct self_segment_block_extent*)(block_digests + block_count);
		} else if (has_digests) {
			if (self_block_table_segment_size != SELF_HASH_SIZE * block_count)
				error("Invalid block table segment size.");
			block_digests = (struct self_segment_block_digest*)self_block_table_segment_data;
			block_extents = NULL;
		} else if (has_extents) {
			if (self_block_table_segment_size != sizeof(*block_extents) * block_count)
				error("Invalid block table segment size.");
			block_digests = NULL;
			block_extents = (struct self_segment_block_extent*)self_block_table_segment_data;
		} else {
			block_digests = NULL;
			block_extents = NULL;
		}

		total_out_size = 0;
		if (self_entry_is_compressed_segment(entry)) {
			window_bits = self_entry_window_bits(entry);
			if (window_bits != 4)
				error("Unsupported window bits.");

			window_bits = SELF_ZLIB_WINDOW_BITS;
			cmp_level = SELF_ZLIB_LEVEL;

			for (j = 0; j < block_count; ++j) {
				in_size = (j + 1) < block_count ? block_size : last_block_size;
				in_data = elf_segment_data + j * block_size;

				tmp_out_size = 0;
				if (!zlib_compress_bound(in_size, window_bits, cmp_level, &tmp_out_size))
					goto error;
				tmp_out_size = align_up(tmp_out_size, 16);

				if (out_data) {
					free(out_data);
					out_data = NULL;
				}

				out_capacity = align_up(MAX(tmp_out_size, in_size), 16);
				out_data = (uint8_t*)malloc(out_capacity);
				if (!out_data)
					goto error;
				memset(out_data, 0, out_capacity);

				in_size_orig = in_size;
				out_size = tmp_out_size;

				if (!zlib_compress(in_data, &in_size, out_data, &out_size, window_bits, cmp_level))
					goto error;

				if (in_size != in_size_orig)
					error("Unmatched input size after compression.");

				if (out_size >= in_size) {
					out_size = in_size;
					memset(out_data, 0, out_capacity);
					memcpy(out_data, in_data, out_size);
				}

				if (block_digests)
					sha256_buffer(out_data, out_size, block_digests[j].digest);

				tmp_out_size = out_size;
				out_size = align_up(out_size, 16);

				extent_offset = total_out_size;
				extent_size = out_size;
				if (tmp_out_size & 0xF)
					extent_size += 16 - (tmp_out_size & 0xF);

				if (block_extents) {
					block_extents[j].offset = LE32((uint32_t)extent_offset);
					block_extents[j].size = LE32((uint32_t)extent_size);
				}

				memcpy(self_segment_data + total_out_size, out_data, out_size);

				total_out_size += out_size;
			}
		} else {
			for (j = 0; j < block_count; ++j) {
				in_size = (j + 1) < block_count ? block_size : last_block_size;
				in_data = elf_segment_data + j * block_size;

				out_capacity = align_up(in_size, 16);
				out_data = (uint8_t*)malloc(out_capacity);
				if (!out_data)
					goto error;
				memset(out_data, 0, out_capacity);

				out_size = in_size;
				memcpy(out_data, in_data, out_size);

				if (block_digests)
					sha256_buffer(out_data, out_size, block_digests[j].digest);

				tmp_out_size = out_size;
				//out_size = align_up(out_size, 16);

				extent_offset = total_out_size;
				extent_size = out_size;
				if (tmp_out_size & 0xF)
					extent_size += 16 - (tmp_out_size & 0xF);

				if (block_extents) {
					block_extents[j].offset = LE32((uint32_t)extent_offset);
					block_extents[j].size = LE32((uint32_t)extent_size);
				}

				memcpy(self_segment_data + total_out_size, out_data, out_size);

				total_out_size += out_size;
			}
		}

		if (total_out_size != self_segment_size)
			error("Not matched output segment size.");
	}

	status = 1;

error:
	if (out_data)
		free(out_data);

	return status;
}