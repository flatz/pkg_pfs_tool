#include "sfo.h"
#include "util.h"

#include <utlist.h>

#define SFO_MAGIC "\0PSF"

#define SFO_HEADER_SIZE 0x14
#define SFO_TABLE_ENTRY_SIZE 0x10

TYPE_BEGIN(struct sfo_header, SFO_HEADER_SIZE);
	TYPE_FIELD(char magic[4], 0x00);
	TYPE_FIELD(uint32_t version, 0x04);
	TYPE_FIELD(uint32_t key_table_offset, 0x08);
	TYPE_FIELD(uint32_t value_table_offset, 0x0C);
	TYPE_FIELD(uint32_t entry_count, 0x10);
TYPE_END();
CT_SIZE_ASSERT(struct sfo_header, SFO_HEADER_SIZE);

TYPE_BEGIN(struct sfo_table_entry, SFO_TABLE_ENTRY_SIZE);
	TYPE_FIELD(uint16_t key_offset, 0x00);
	TYPE_FIELD(uint16_t format, 0x02);
	TYPE_FIELD(uint32_t size, 0x04);
	TYPE_FIELD(uint32_t max_size, 0x08);
	TYPE_FIELD(uint32_t value_offset, 0x0C);
TYPE_END();
CT_SIZE_ASSERT(struct sfo_table_entry, SFO_TABLE_ENTRY_SIZE);

struct sfo* sfo_alloc(void) {
	struct sfo* sfo = NULL;

	sfo = (struct sfo*)malloc(sizeof(*sfo));
	if (!sfo)
		goto error;
	memset(sfo, 0, sizeof(*sfo));

	return sfo;

error:
	if (sfo)
		free(sfo);

	return NULL;
}

void sfo_free(struct sfo* sfo) {
	struct sfo_entry* entry;
	struct sfo_entry* tmp;

	if (!sfo)
		return;

	DL_FOREACH_SAFE(sfo->entries, entry, tmp) {
		DL_DELETE(sfo->entries, entry);

		if (entry->key)
			free(entry->key);

		if (entry->value)
			free(entry->value);

		free(entry);
	}

	free(sfo);
}

int sfo_load_from_file(struct sfo* sfo, const char* file_path) {
	struct stat stats;
	uint8_t* data = NULL;
	size_t data_size;
	ssize_t nread;
	int fd = -1;
	int status = 0;
	int ret;

	assert(sfo != NULL);
	assert(file_path != NULL);

	fd = open(file_path, O_RDONLY | O_BINARY);
	if (fd < 0) {
		warning("Unable to open file.");
		goto error;
	}

	ret = fstat(fd, &stats);
	if (ret < 0) {
		warning("Unable to get file information.");
		goto error;
	}
	data_size = (size_t)stats.st_size;

	data = (uint8_t*)malloc(data_size);
	if (!data) {
		warning("Unable to allocate memory of 0x%" PRIuMAX " bytes.", (uintmax_t)data_size);
		goto error;
	}

	nread = read(fd, data, data_size);
	if (nread < 0) {
		warning("Unable to read file.");
		goto error;
	}
	if ((size_t)nread != data_size) {
		warning("Insufficient data read.");
		goto error;
	}

	if (!sfo_load_from_memory(sfo, data, data_size)) {
		warning("Unable to load system file object.");
		goto error;
	}

	status = 1;

error:
	if (data)
		free(data);

	if (fd > 0)
		close(fd);

	return status;
}

int sfo_load_from_memory(struct sfo* sfo, const void* data, size_t data_size) {
	struct sfo_header* hdr;
	struct sfo_table_entry* entry_table;
	struct sfo_table_entry* entry;
	struct sfo_entry* entries = NULL;
	struct sfo_entry* new_entry = NULL;
	const char* key_table;
	const uint8_t* value_table;
	size_t entry_count, i;
	int status = 0;

	assert(sfo != NULL);
	assert(data != NULL);

	if (data_size < sizeof(*hdr)) {
		warning("Insufficient data.");
		goto error;
	}

	hdr = (struct sfo_header*)data;
	if (memcmp(hdr->magic, SFO_MAGIC, sizeof(hdr->magic)) != 0) {
		warning("Invalid system file object format.");
		goto error;
	}

	entry_table = (struct sfo_table_entry*)(data + sizeof(*hdr));
	entry_count = LE32(hdr->entry_count);
	if (data_size < sizeof(*hdr) + entry_count * sizeof(*entry_table)) {
		warning("Insufficient data.");
		goto error;
	}

	key_table = (const char*)data + LE32(hdr->key_table_offset);
	value_table = (const uint8_t*)data + LE32(hdr->value_table_offset);

	for (i = 0; i < entry_count; ++i) {
		entry = entry_table + i;

		new_entry = (struct sfo_entry*)malloc(sizeof(*new_entry));
		if (!new_entry) {
			warning("Unable to allocate memory for entry.");
			goto error;
		}
		memset(new_entry, 0, sizeof(*new_entry));

		new_entry->format = (enum sfo_value_format)LE16(entry->format);

		new_entry->size = LE32(entry->size);
		new_entry->area = LE32(entry->max_size);
		if (new_entry->area < new_entry->size) {
			warning("Unexpected entry sizes.");
			goto error;
		}

		new_entry->key = strdup(key_table + LE16(entry->key_offset));
		if (!new_entry->key) {
			warning("Unable to allocate memory for entry key.");
			goto error;
		}

		new_entry->value = (uint8_t*)malloc(new_entry->area);
		if (!new_entry->value) {
			warning("Unable to allocate memory for entry value.");
			goto error;
		}
		memset(new_entry->value, 0, new_entry->area);
		memcpy(new_entry->value, value_table + LE16(entry->value_offset), new_entry->size);

		DL_APPEND(entries, new_entry);
	}
	new_entry = NULL;

	sfo->entries = entries;

	status = 1;

error:
	if (new_entry) {
		if (new_entry->key)
			free(new_entry->key);

		if (new_entry->value)
			free(new_entry->value);

		free(new_entry);
	}

	return status;
}

struct sfo_entry* sfo_find_entry(struct sfo* sfo, const char* key) {
	struct sfo_entry* entry;

	assert(sfo != NULL);
	assert(key != NULL);

	DL_FOREACH(sfo->entries, entry) {
		if (strcmp(entry->key, key) == 0)
			return entry;
	}

	return NULL;
}

void sfo_dump(struct sfo* sfo) {
	struct sfo_entry* entry;
	FILE* fp = stdout;
	size_t index = 0;

	assert(sfo != NULL);

	DL_FOREACH(sfo->entries, entry) {
		fprintf(fp, "%s:\n", entry->key);
		if (entry->value) {
			if (entry->format == SFO_FORMAT_STRING)
				fprintf(fp, "  %s\n", (char*)entry->value);
			else
				fprintf_hex(fp, entry->value, entry->size, 2);
		} else {
			fprintf(fp, "  no value\n");
		}
		++index;
	}
}