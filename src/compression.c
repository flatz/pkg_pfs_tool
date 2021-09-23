#include "compression.h"
#include "util.h"

#include <zlib.h>

int zlib_decompress(const void* in, size_t* in_size, void* out, size_t* out_size, int window_bits) {
	z_stream stream;
	int ret;

	assert(in != NULL);
	assert(in_size != NULL);
	assert(out != NULL);
	assert(out_size != NULL);

	if (*in_size > UINT_MAX || *out_size > UINT_MAX)
		return EINVAL;

	memset(&stream, 0, sizeof(stream));

	stream.zalloc = (alloc_func)Z_NULL;
	stream.zfree = (free_func)Z_NULL;
	stream.opaque = (voidpf)Z_NULL;

	stream.next_in = (Bytef*)in;
	stream.avail_in = (uInt)*in_size;
	stream.next_out = (Bytef*)out;
	stream.avail_out = (uInt)*out_size;

	ret = inflateInit2(&stream, window_bits);
	if (ret != Z_OK)
		goto error;

	ret = inflate(&stream, Z_FINISH);
	if (ret != Z_STREAM_END) {
		inflateEnd(&stream);
		if (ret == Z_NEED_DICT || (ret == Z_BUF_ERROR && stream.avail_in == 0))
			ret = Z_DATA_ERROR;
		goto error;
	}

	ret = inflateEnd(&stream);

	*in_size = (size_t)stream.total_in;
	*out_size = (size_t)stream.total_out;

error:
	return ret == Z_OK;
}

int zlib_compress(const void* in, size_t* in_size, void* out, size_t* out_size, int window_bits, int level) {
	z_stream stream;
	int ret;

	assert(in != NULL);
	assert(in_size != NULL);
	assert(out != NULL);
	assert(out_size != NULL);

	if (*in_size > UINT_MAX || *out_size > UINT_MAX)
		return EINVAL;

	memset(&stream, 0, sizeof(stream));

	stream.zalloc = (alloc_func)Z_NULL;
	stream.zfree = (free_func)Z_NULL;
	stream.opaque = (voidpf)Z_NULL;

	stream.next_in = (Bytef*)(const Bytef*)in;
	stream.avail_in = (uInt)*in_size;
	stream.next_out = (Bytef*)out;
	stream.avail_out = (uInt)*out_size;

	ret = deflateInit2(&stream, level, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		goto error;

	ret = deflate(&stream, Z_FINISH);
	if (ret != Z_STREAM_END) {
		deflateEnd(&stream);
		if (ret != Z_OK)
			ret = Z_BUF_ERROR;
		goto error;
	}

	ret = deflateEnd(&stream);

	*in_size = (size_t)stream.total_in;
	*out_size = (size_t)stream.total_out;

error:
	return ret == Z_OK;
}

int zlib_compress_bound(size_t in_size, int window_bits, int level, size_t* bound_size) {
	z_stream stream;
	uLong size;
	int ret;

	if (in_size > UINT_MAX)
		return EINVAL;

	memset(&stream, 0, sizeof(stream));

	stream.zalloc = (alloc_func)Z_NULL;
	stream.zfree = (free_func)Z_NULL;
	stream.opaque = (voidpf)Z_NULL;

	ret = deflateInit2(&stream, level, Z_DEFLATED, window_bits, 9, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		goto error;

	size = deflateBound(&stream, in_size);

	deflateEnd(&stream);

	if (bound_size)
		*bound_size = (size_t)size;

error:
	return ret == Z_OK;
}