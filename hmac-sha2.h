#ifndef HMAC_SHA2_H_
#define HMAC_SHA2_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h> // uint8_t
#include "sha2.h"

typedef struct {
  uint8_t key[64];
  sha256_t ctx;
} hmac_sha256_t;

void hmac_sha256_init(
  hmac_sha256_t * const ctx,
  const uint8_t * const key,
  const size_t key_len
);

void hmac_sha256_push(
  hmac_sha256_t * const ctx,
  const uint8_t * const buf,
  const size_t buf_len
);

void hmac_sha256_fini(
  hmac_sha256_t * const ctx,
  uint8_t * const out
);

void hmac_sha256(
  const uint8_t * const key,
  const size_t key_len,
  const uint8_t * const buf,
  const size_t buf_len,
  uint8_t * const out
);

_Bool hmac_check(
  const uint8_t * const a,
  const uint8_t * const b,
  const size_t len
);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* HMAC_SHA2_H_ */
