#ifndef SHA2_H_
#define SHA2_H_

#include <stdint.h> // uint32_t, uint8_t
#include <stdlib.h> // size_t

#define SHA256_HASH_SIZE 32

typedef struct {
  uint8_t buf[64];
  size_t buf_len;

  uint32_t h[8];

  uint64_t num_bytes;
} sha256_t;

void sha256_init(sha256_t * const);
void sha256_push(sha256_t * const, const uint8_t *, size_t);
void sha256_fini(sha256_t * const, uint8_t * const);
void sha256(const uint8_t * const, const size_t, uint8_t * const);

#endif /* SHA2_H_ */
