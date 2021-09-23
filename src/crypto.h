#pragma once

#include "common.h"

struct rsa_keyset {
	const char* name;
	char* n; // public modulus
	char* e; // public exponent
	char* d; // private exponent
	char* p; // 1st prime factor
	char* q; // 2nd prime factor
	char* dp; // d % (p - 1)
	char* dq; // d % (q - 1)
	char* qp; // 1 / (q % p)
};

struct encdec_device;
typedef uint64_t encdec_sector_no;

int crypto_initialize(void);
void crypto_finalize(void);

int rsa_public(const struct rsa_keyset* keyset, const void* in, void* out);
int rsa_private(const struct rsa_keyset* keyset, const void* in, void* out);

int rsa_pkcsv15_decrypt(const struct rsa_keyset* keyset, const void* in, size_t in_size, void* out, size_t* out_size, int is_private, int is_private_2);

int rsa_pkcsv15_verify_by_hash(const struct rsa_keyset* keyset, uint8_t* hash, size_t hash_size, const void* signature, size_t signature_size);
int rsa_pkcsv15_verify(const struct rsa_keyset* keyset, const void* data, size_t data_size, const void* signature, size_t signature_size);

typedef int (*read_chunk_cb)(void* arg, uint8_t* chunk, size_t chunk_size, size_t* n);

void sha256_buffer(const void* data, size_t data_size, uint8_t hash[32]);
int sha256_buffer_chunked(read_chunk_cb read_cb, void* read_cb_arg, uint8_t* chunk, size_t chunk_size, uint8_t hash[32]);
void hmac_sha256_buffer(const void* key, size_t key_size, const void* data, size_t data_size, uint8_t hash[32]);
int hmac_sha256_buffer_chunked(const void* key, size_t key_size, read_chunk_cb read_cb, void* read_cb_arg, uint8_t* chunk, size_t chunk_size, uint8_t hash[32]);

int aes_encrypt_cbc_cts(const void* key, size_t key_size, void* iv, const void* in_data, void* out_data, size_t data_size);
int aes_decrypt_cbc_cts(const void* key, size_t key_size, void* iv, const void* in_data, void* out_data, size_t data_size);

int aes_decrypt_oex(const void* key, size_t key_size, uint64_t offset, const void* in_data, void* out_data, size_t data_size);

int aes_cmac(const void* key, size_t key_size, const void* data, size_t data_size, uint8_t digest[16]);

struct encdec_device* encdec_device_alloc(const void* tweak_key, size_t tweak_key_size, const void* data_key, size_t data_key_size, size_t sector_size);
void encdec_device_free(struct encdec_device* dev);

encdec_sector_no encdec_device_process(struct encdec_device* dev, const void* in, void* out, encdec_sector_no start_sector, uint64_t data_size, int encrypt);

static inline encdec_sector_no encdec_device_encrypt(struct encdec_device* dev, const void* in, void* out, encdec_sector_no start_sector, uint64_t data_size) {
	return encdec_device_process(dev, in, out, start_sector, data_size, 1);
}

static inline encdec_sector_no encdec_device_decrypt(struct encdec_device* dev, const void* in, void* out, encdec_sector_no start_sector, uint64_t data_size) {
	return encdec_device_process(dev, in, out, start_sector, data_size, 0);
}
