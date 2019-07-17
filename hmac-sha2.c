#include "hmac-sha2.h"
#include <stdbool.h> // bool
#include <string.h> // memcpy()

#define SHA256_PAD(val) { \
  ctx->key[0] ^ (val), ctx->key[1] ^ (val), ctx->key[2] ^ (val), \
  ctx->key[3] ^ (val), ctx->key[4] ^ (val), ctx->key[5] ^ (val), \
  ctx->key[6] ^ (val), ctx->key[7] ^ (val), ctx->key[8] ^ (val), \
  ctx->key[9] ^ (val), ctx->key[10] ^ (val), ctx->key[11] ^ (val), \
  ctx->key[12] ^ (val), ctx->key[13] ^ (val), ctx->key[14] ^ (val), \
  ctx->key[15] ^ (val), ctx->key[16] ^ (val), ctx->key[17] ^ (val), \
  ctx->key[18] ^ (val), ctx->key[19] ^ (val), ctx->key[20] ^ (val), \
  ctx->key[21] ^ (val), ctx->key[22] ^ (val), ctx->key[23] ^ (val), \
  ctx->key[24] ^ (val), ctx->key[25] ^ (val), ctx->key[26] ^ (val), \
  ctx->key[27] ^ (val), ctx->key[28] ^ (val), ctx->key[29] ^ (val), \
  ctx->key[30] ^ (val), ctx->key[31] ^ (val), ctx->key[32] ^ (val), \
  ctx->key[33] ^ (val), ctx->key[34] ^ (val), ctx->key[35] ^ (val), \
  ctx->key[36] ^ (val), ctx->key[37] ^ (val), ctx->key[38] ^ (val), \
  ctx->key[39] ^ (val), ctx->key[40] ^ (val), ctx->key[41] ^ (val), \
  ctx->key[42] ^ (val), ctx->key[43] ^ (val), ctx->key[44] ^ (val), \
  ctx->key[45] ^ (val), ctx->key[46] ^ (val), ctx->key[47] ^ (val), \
  ctx->key[48] ^ (val), ctx->key[49] ^ (val), ctx->key[50] ^ (val), \
  ctx->key[51] ^ (val), ctx->key[52] ^ (val), ctx->key[53] ^ (val), \
  ctx->key[54] ^ (val), ctx->key[55] ^ (val), ctx->key[56] ^ (val), \
  ctx->key[57] ^ (val), ctx->key[58] ^ (val), ctx->key[59] ^ (val), \
  ctx->key[60] ^ (val), ctx->key[61] ^ (val), ctx->key[62] ^ (val), \
  ctx->key[63] ^ (val), \
}

void hmac_sha256_init(
  hmac_sha256_t * const ctx,
  const uint8_t * const key,
  const size_t key_len
) {
  memset(ctx->key, 0, 64);
  if (key_len > 64) {
    uint8_t hash[SHA256_HASH_SIZE];
    sha256(key, key_len, hash);
    memcpy(ctx->key, hash, sizeof(hash));
  } else {
    memcpy(ctx->key, key, key_len);
  }

  sha256_init(&(ctx->ctx));
  const uint8_t ipad[64] = SHA256_PAD(0x36);

  sha256_push(&(ctx->ctx), ipad, sizeof(ipad));
}

void hmac_sha256_push(
  hmac_sha256_t * const ctx,
  const uint8_t * const buf,
  const size_t buf_len
) {
  sha256_push(&(ctx->ctx), buf, buf_len);
}

void hmac_sha256_fini(
  hmac_sha256_t * const ctx,
  uint8_t * const out
) {
  uint8_t hash[SHA256_HASH_SIZE];
  sha256_fini(&(ctx->ctx), hash);

  sha256_t out_ctx;
  sha256_init(&out_ctx); 

  const uint8_t opad[64] = SHA256_PAD(0x5c);
  sha256_push(&out_ctx, opad, sizeof(opad));
  sha256_push(&out_ctx, hash, sizeof(hash));
  sha256_fini(&out_ctx, out);
}

void hmac_sha256(
  const uint8_t * const key,
  const size_t key_len,
  const uint8_t * const buf,
  const size_t buf_len,
  uint8_t * const out
) {
  hmac_sha256_t ctx;
  hmac_sha256_init(&ctx, key, key_len);
  hmac_sha256_push(&ctx, buf, buf_len);
  hmac_sha256_fini(&ctx, out);
}

_Bool hmac_check(
  const uint8_t * const a,
  const uint8_t * const b,
  const size_t len
) {
  uint8_t r = 0;

  for (size_t i = 0; i < len; i++) {
    r |= (a[i] ^ b[i]);
  }

  return !r;
}
