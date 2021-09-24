#include "mapped_file.h"

#ifndef _WIN32
#	include <sys/mman.h>
#else
#	include "mingw/mman.h"
#endif

#define MAP_PAGE_ALIGNMENT 0x4000

struct file_map* map_files(const char* const* file_paths, size_t file_count) {
	struct file_map* map = NULL;
	struct stat64 st;
	void* data = MAP_FAILED;
	void* map_base_addr = MAP_FAILED;
	void* map_addr;
	int fd = -1;
	uint64_t file_size = 0;
	uint64_t total_file_size = 0;
	size_t i;

	assert(file_paths != NULL);

	map = (struct file_map*)malloc(sizeof(*map));
	if (!map)
		goto error;
	memset(map, 0, sizeof(*map));

	map->file_count = file_count;

	map->file_paths = (char**)malloc(file_count * sizeof(*map->file_paths));
	if (!map->file_paths)
		goto error;
	memset(map->file_paths, 0, file_count * sizeof(*map->file_paths));

	map->fds = (int*)malloc(file_count * sizeof(*map->fds));
	if (!map->fds)
		goto error;
	memset(map->fds, 0, file_count * sizeof(*map->fds));
	for (i = 0; i < file_count; ++i)
		map->fds[i] = -1;

	map->segments = (struct file_map_segment*)malloc(file_count * sizeof(*map->segments));
	if (!map->segments)
		goto error;
	memset(map->segments, 0, file_count * sizeof(*map->segments));
	for (i = 0; i < file_count; ++i)
		map->segments[i].base = MAP_FAILED;

	for (i = 0; i < file_count; ++i) {
		if (stat64(file_paths[i], &st) < 0)
			goto error;
		if (!S_ISREG(st.st_mode)) {
			errno = EINVAL;
			goto error;
		}

		file_size = (uint64_t)st.st_size;
		if (file_size > SIZE_MAX) {
			errno = EINVAL;
			goto error;
		}
		/*if ((file_size & (MAP_PAGE_ALIGNMENT - 1)) != 0) {
			errno = EINVAL;
			goto error;
		}*/

		map->segments[i].size = file_size;

		total_file_size += file_size;
	}

	file_size = total_file_size;
	data = mmap(NULL, (size_t)file_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (data == MAP_FAILED)
		goto error;
	map_base_addr = data;
	munmap(data, (size_t)file_size);
	data = NULL;

	for (i = 0, map_addr = map_base_addr; i < file_count; ++i) {
		map->file_paths[i] = strdup(file_paths[i]);
		if (!map->file_paths[i])
			goto error;

		fd = open(file_paths[i], O_RDONLY | O_LARGEFILE | O_BINARY);
		if (fd < 0)
			goto error;

		if (fstat64(fd, &st) < 0)
			goto error;
		if (!S_ISREG(st.st_mode)) {
			errno = EINVAL;
			goto error;
		}

		file_size = (uint64_t)st.st_size;
		if (file_size != map->segments[i].size) {
			errno = EINVAL;
			goto error;
		}

		data = mmap(map_addr, (size_t)file_size, PROT_READ, MAP_FIXED | MAP_SHARED, fd, 0);
		if (data == MAP_FAILED)
			goto error;
		if (data != map_addr) {
			errno = EINVAL;
			goto error;
		}

		map->fds[i] = fd;
		map->segments[i].base = data;

 		map_addr = (uint8_t*)map_addr + file_size;

		fd = -1;
		data = MAP_FAILED;
	}

	map->data = (uint8_t*)map_base_addr;
	map->size = total_file_size;
	map->write = 0;
	map->submap = 0;

	return map;

error:
	unmap_file(map);

	if (data != MAP_FAILED)
		munmap(data, (size_t)file_size);

	if (fd > 0)
		close(fd);

	return NULL;
}

struct file_map* map_file(const char* file_path) {
	return map_files(&file_path, 1);
}

struct file_map* map_file_for_write(const char* file_path, uint64_t file_size, int mode) {
	struct file_map* map = NULL;
	int fd = -1;
	void* data = MAP_FAILED;
	size_t file_count = 1;
	size_t i;

	assert(file_path != NULL);

	map = (struct file_map*)malloc(sizeof(*map));
	if (!map)
		goto error;
	memset(map, 0, sizeof(*map));

	map->file_count = file_count;

	map->file_paths = (char**)malloc(file_count * sizeof(*map->file_paths));
	if (!map->file_paths)
		goto error;
	memset(map->file_paths, 0, file_count * sizeof(*map->file_paths));

	map->file_paths[0] = strdup(file_path);
	if (!map->file_paths[0])
		goto error;

	map->fds = (int*)malloc(file_count * sizeof(*map->fds));
	if (!map->fds)
		goto error;
	memset(map->fds, 0, file_count * sizeof(*map->fds));
	for (i = 0; i < file_count; ++i)
		map->fds[i] = -1;

	map->segments = (struct file_map_segment*)malloc(file_count * sizeof(*map->segments));
	if (!map->segments)
		goto error;
	memset(map->segments, 0, file_count * sizeof(*map->segments));
	for (i = 0; i < file_count; ++i)
		map->segments[i].base = MAP_FAILED;

	//map->segments[0].size = file_size * 2; // FIXME: wtf?
	map->segments[0].size = file_size;

	fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE | O_BINARY, mode);
	if (fd < 0)
		goto error;
	if (ftruncate64(fd, (fileoff_t)map->segments[0].size) < 0)
		goto error;

	data = mmap(NULL, (size_t)map->segments[0].size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED)
		goto error;

	map->fds[0] = fd;
	map->segments[0].base = data;
	map->data = (uint8_t*)data;
	map->size = map->segments[0].size;
	map->offset = 0;
	map->write = 1;
	map->submap = 0;

	return map;

error:
	unmap_file(map);

	if (data != MAP_FAILED)
		munmap(data, (size_t)file_size);

	if (fd > 0)
		close(fd);

	return NULL;
}

struct file_map* map_file_sub_region(struct file_map* map, uint64_t offset, uint64_t size) {
	struct file_map* submap = NULL;

	if (!map)
		goto error;

	if (map->offset + offset + size > map->size)
		goto error;

	submap = (struct file_map*)malloc(sizeof(*submap));
	if (!submap)
		goto error;
	memset(submap, 0, sizeof(*submap));

	submap->file_count = map->file_count;
	submap->file_paths = map->file_paths;
	submap->fds = map->fds;
	submap->segments = map->segments;
	submap->data = map->data + offset;
	submap->size = size;
	submap->offset = offset;
	submap->write = map->write;
	submap->submap = 1;

	return submap;

error:
	unmap_file(submap);

	return NULL;
}

void unmap_file(struct file_map* map) {
	size_t i;

	if (!map)
		return;

	if (!map->submap) {
		if (map->segments) {
			for (i = 0; i < map->file_count; ++i) {
				if (map->segments[i].base != MAP_FAILED) {
					if (map->write)
						msync(map->segments[i].base, (size_t)map->segments[i].size, MS_SYNC);
					munmap(map->segments[i].base, (size_t)map->segments[i].size);
				}
			}

			free(map->segments);
		}

		if (map->fds) {
			for (i = 0; i < map->file_count; ++i) {
				if (map->fds[i] > 0)
					close(map->fds[i]);
			}

			free(map->fds);
		}

		if (map->file_paths) {
			for (i = 0; i < map->file_count; ++i) {
				if (map->file_paths[i])
					free(map->file_paths[i]);
			}

			free(map->file_paths);
		}
	}

	free(map);
}
