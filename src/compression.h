#pragma once

#include "common.h"

int zlib_decompress(const void* in, size_t* in_size, void* out, size_t* out_size, int window_bits);
int zlib_compress(const void* in, size_t* in_size, void* out, size_t* out_size, int window_bits, int level);

int zlib_compress_bound(size_t in_size, int window_bits, int level, size_t* bound_size);