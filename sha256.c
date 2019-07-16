#include "sha256.h"
#include <string.h> // memcpy

// initial hash values
// (first 32 bits of the fractional parts of the square roots of the
// first 8 primes 2..19):
static const uint32_t H[8] = {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
};

// round constants
// (first 32 bits of the fractional parts of the cube roots of the first
// 64 primes 2..311):
static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
  0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
  0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
  0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
  0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// rotate right
// (src: https://blog.regehr.org/archives/1063)
static inline uint32_t
rr(const uint32_t v, const size_t n) {
  return (v << (32 - n)) | (v >> n);
}

void sha256_init(sha256_t * const ctx) {
  ctx->buf_len = 0;
  ctx->num_bytes = 0;
  memcpy(ctx->h, H, sizeof(H));
}

static void
sha256_round(sha256_t * const ctx) {
  for (size_t i = 0; i < 16; i++) {
    ctx->w[i] = (
      (((uint32_t) ctx->buf[4 * i + 0]) << 24) |
      (((uint32_t) ctx->buf[4 * i + 1]) << 16) |
      (((uint32_t) ctx->buf[4 * i + 2]) << 8) |
      ((uint32_t) ctx->buf[4 * i + 3])
    );
  }

  // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
  // for i from 16 to 63
  //   s0 := (w[i-15] rr  7) xor (w[i-15] rr 18) xor (w[i-15] rs  3)
  //   s1 := (w[i- 2] rr 17) xor (w[i- 2] rr 19) xor (w[i- 2] rs 10)
  //   w[i] := w[i-16] + s0 + w[i-7] + s1
  for (size_t i = 16; i < 64; i++) {
    const uint32_t w2 = ctx->w[i - 2],
                   w7 = ctx->w[i - 7],
                   w15 = ctx->w[i - 15],
                   w16 = ctx->w[i - 16],
                   s0 = rr(w15, 7) ^ rr(w15, 18) ^ (w15 >> 3),
                   s1 = rr(w2, 17) ^ rr(w2, 19) ^ (w2 >> 10);
    ctx->w[i] = w16 + s0 + w7 + s1;
  }

  // Initialize working variables to current hash value:
  uint32_t hs[8];
  for (size_t i = 0; i < 8; i++) {
    hs[i] = ctx->h[i];
  }

  // Compression function main loop:
  // for i from 0 to 63
  //   S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
  //   ch := (e and f) xor ((not e) and g)
  //   temp1 := h + S1 + ch + k[i] + w[i]
  //   S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
  //   maj := (a and b) xor (a and c) xor (b and c)
  //   temp2 := S0 + maj
  // 
  //   h := g
  //   g := f
  //   f := e
  //   e := d + temp1
  //   d := c
  //   c := b
  //   b := a
  //   a := temp1 + temp2
  for (size_t i = 0; i < 64; i++) {
    const uint32_t s1 = rr(hs[4], 6) ^ rr(hs[4], 11) ^ rr(hs[4], 25),
                   ch = (hs[4] & hs[5]) ^ (~(hs[4]) & hs[6]),
                   t0 = hs[7] + s1 + ch + K[i] + ctx->w[i],
                   s0 = rr(hs[0], 2) ^ rr(hs[0], 13) ^ rr(hs[0], 22),
                   mj = (hs[0] & hs[1]) ^ (hs[0] & hs[2]) ^ (hs[1] & hs[2]),
                   t1 = s0 + mj;

    hs[7] = hs[6];
    hs[6] = hs[5];
    hs[5] = hs[4];
    hs[4] = hs[3] + t0;
    hs[3] = hs[2];
    hs[2] = hs[1];
    hs[1] = hs[0];
    hs[0] = t0 + t1;
  }

  // Add the compressed chunk to the current hash value
  for (size_t i = 0; i < 8; i++) {
    ctx->h[i] += hs[i];
  }
}

void sha256_push(
  sha256_t * const ctx,
  const uint8_t *src,
  size_t src_len
) {
  ctx->num_bytes += src_len;

  if ((ctx->buf_len + src_len) >= 64) {
    const size_t len = 64 - ctx->buf_len;
    memcpy(ctx->buf + ctx->buf_len, src, len);

    sha256_round(ctx);
    ctx->buf_len = 0;

    src += len;
    src_len -= len;
  } else {
    memcpy(ctx->buf + ctx->buf_len, src, src_len);
    ctx->buf_len += src_len;

    src += src_len;
    src_len = 0;
  }

  while (src_len >= 64) {
    memcpy(ctx->buf, src, 64);

    sha256_round(ctx);
    ctx->buf_len = 0;

    src += 64;
    src_len -= 64;
  }

  if (src_len > 0) {
    memcpy(ctx->buf, src, src_len);
    ctx->buf_len = src_len;
  }
}

static void sha256_push_u64(
  sha256_t * const ctx,
  const uint64_t val
) {
  const uint8_t buf[8] = { 
    ((val >> 56) & 0xff),
    ((val >> 48) & 0xff),
    ((val >> 40) & 0xff),
    ((val >> 32) & 0xff),
    ((val >> 24) & 0xff),
    ((val >> 16) & 0xff),
    ((val >> 8) & 0xff),
    ((val) & 0xff),
  };

  sha256_push(ctx, buf, sizeof(buf));
}

static const uint8_t FOOTER[65] = {
  128, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

void sha256_fini(
  sha256_t * const ctx,
  uint8_t * const out
) {
  const uint64_t num_bytes = ctx->num_bytes;

  {
    // push padding
    const size_t pad_len = (64 - ((num_bytes + 1 + 8) % 64)) % 64;
    sha256_push(ctx, FOOTER, 1 + pad_len);
  }

  // push length
  sha256_push_u64(ctx, num_bytes);

  // extract result
  const uint8_t src[32] = {
    (ctx->h[0] >> 24) & 0xff,
    (ctx->h[0] >> 16) & 0xff,
    (ctx->h[0] >> 8) & 0xff,
    (ctx->h[0]) & 0xff,
    (ctx->h[1] >> 24) & 0xff,
    (ctx->h[1] >> 16) & 0xff,
    (ctx->h[1] >> 8) & 0xff,
    (ctx->h[1]) & 0xff,
    (ctx->h[2] >> 24) & 0xff,
    (ctx->h[2] >> 16) & 0xff,
    (ctx->h[2] >> 8) & 0xff,
    (ctx->h[2]) & 0xff,
    (ctx->h[3] >> 24) & 0xff,
    (ctx->h[3] >> 16) & 0xff,
    (ctx->h[3] >> 8) & 0xff,
    (ctx->h[3]) & 0xff,
    (ctx->h[4] >> 24) & 0xff,
    (ctx->h[4] >> 16) & 0xff,
    (ctx->h[4] >> 8) & 0xff,
    (ctx->h[4]) & 0xff,
    (ctx->h[5] >> 24) & 0xff,
    (ctx->h[5] >> 16) & 0xff,
    (ctx->h[5] >> 8) & 0xff,
    (ctx->h[5]) & 0xff,
    (ctx->h[6] >> 24) & 0xff,
    (ctx->h[6] >> 16) & 0xff,
    (ctx->h[6] >> 8) & 0xff,
    (ctx->h[6]) & 0xff,
    (ctx->h[7] >> 24) & 0xff,
    (ctx->h[7] >> 16) & 0xff,
    (ctx->h[7] >> 8) & 0xff,
    (ctx->h[7]) & 0xff,
  };

  memcpy(out, src, sizeof(src));
}

void sha256(
  const uint8_t * const src,
  const size_t src_len,
  uint8_t * const dst
) {
  sha256_t ctx;
  sha256_init(&ctx);
  sha256_push(&ctx, src, src_len);
  sha256_fini(&ctx, dst);
}
