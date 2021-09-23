#pragma once

#include "common.h"

struct file_map_segment {
	void* base;
	uint64_t size;
};

struct file_map {
	char** file_paths;
	size_t file_count;
	uint64_t offset, size;
	int* fds;
	struct file_map_segment* segments;
	uint8_t* data;
	int write;
	int submap;
};

struct file_map* map_files(const char* const* file_paths, size_t file_count);
struct file_map* map_file(const char* file_path);
struct file_map* map_file_for_write(const char* file_path, uint64_t file_size, int mode);
struct file_map* map_file_sub_region(struct file_map* map, uint64_t offset, uint64_t size);
void unmap_file(struct file_map* map);
