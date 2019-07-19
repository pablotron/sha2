#ifndef SHA2_H_
#define SHA2_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h> // uint32_t, uint8_t
#include <stddef.h> // size_t

#define SHA256_HASH_SIZE 32

typedef struct {
  uint8_t buf[64];
  uint32_t h[8];
  uint64_t num_bytes;
} sha256_t;

void sha256_init(sha256_t * const);
void sha256_push(sha256_t * const restrict, const void * const restrict, const size_t);
void sha256_fini(sha256_t * const restrict, void * const restrict);
void sha256(const void * const restrict, const size_t, void * const restrict);

#define SHA224_HASH_SIZE 28

typedef struct {
  sha256_t ctx;
} sha224_t;

void sha224_init(sha224_t * const);
void sha224_push(sha224_t * const restrict, const void * const restrict, const size_t);
void sha224_fini(sha224_t * const restrict, void * const restrict);
void sha224(const void * const restrict, const size_t, void * const restrict);


#define SHA512_HASH_SIZE 64

typedef struct {
  uint8_t buf[128];
  uint64_t h[8];
  uint64_t num_bytes_lo,
           num_bytes_hi;
} sha512_t;

void sha512_init(sha512_t * const);
void sha512_push(sha512_t * const restrict, const void * restrict, const size_t);
void sha512_fini(sha512_t * const restrict, void * const restrict);
void sha512(const void * const restrict, const size_t, void * const restrict);

#define SHA384_HASH_SIZE 48

typedef struct {
  sha512_t ctx;
} sha384_t;

void sha384_init(sha384_t * const);
void sha384_push(sha384_t * const restrict, const void * const restrict, const size_t);
void sha384_fini(sha384_t * const restrict, void * const restrict);
void sha384(const void * const restrict, const size_t, void * const restrict);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* SHA2_H_ */
