#include "sha256.h"
#include <string.h> // memcpy

// initial hash values
// (first 32 bits of the fractional parts of the square roots of the
// first 8 primes 2..19):
static const uint32_t H[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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

// WI: decode buffer data as 32-bit words (used for the first 16 words)
#define WI(i) ( \
  (((uint32_t) ctx->buf[4 * (i) + 0]) << 24) | \
  (((uint32_t) ctx->buf[4 * (i) + 1]) << 16) | \
  (((uint32_t) ctx->buf[4 * (i) + 2]) << 8) | \
  ((uint32_t) ctx->buf[4 * (i) + 3]) \
)

// WE: expand first 16 buffer words into remaining 48 words
#define WE(i) do { \
  const uint32_t w2 = w[(i) - 2], \
                 w7 = w[(i) - 7], \
                 w15 = w[(i) - 15], \
                 w16 = w[(i) - 16], \
                 s0 = rr(w15, 7) ^ rr(w15, 18) ^ (w15 >> 3), \
                 s1 = rr(w2, 17) ^ rr(w2, 19) ^ (w2 >> 10); \
  w[i] = w16 + s0 + w7 + s1; \
} while (0)

// WC: compress word
#define WC(i) do { \
  const uint32_t s1 = rr(hs[4], 6) ^ rr(hs[4], 11) ^ rr(hs[4], 25), \
                 ch = (hs[4] & hs[5]) ^ ((~(hs[4])) & hs[6]), \
                 t0 = hs[7] + s1 + ch + K[i] + w[i], \
                 s0 = rr(hs[0], 2) ^ rr(hs[0], 13) ^ rr(hs[0], 22), \
                 mj = (hs[0] & hs[1]) ^ (hs[0] & hs[2]) ^ (hs[1] & hs[2]), \
                 t1 = s0 + mj; \
\
  hs[7] = hs[6]; \
  hs[6] = hs[5]; \
  hs[5] = hs[4]; \
  hs[4] = hs[3] + t0; \
  hs[3] = hs[2]; \
  hs[2] = hs[1]; \
  hs[1] = hs[0]; \
  hs[0] = t0 + t1; \
} while (0)

static void
sha256_block(sha256_t * const ctx) {
  // init first 16 words from buffer
  uint32_t w[64] = {
    WI(0), WI(1), WI(2), WI(3), WI(4), WI(5), WI(6), WI(7),
    WI(8), WI(9), WI(10), WI(11), WI(12), WI(13), WI(14), WI(15),
    0,
  };

  // Extend the first 16 words into the remaining 48 words w[16..63] of
  // the message schedule array
  //
  // for i from 16 to 63
  //   s0 := (w[i-15] rr  7) xor (w[i-15] rr 18) xor (w[i-15] rs  3)
  //   s1 := (w[i- 2] rr 17) xor (w[i- 2] rr 19) xor (w[i- 2] rs 10)
  //   w[i] := w[i-16] + s0 + w[i-7] + s1
  //
  // for (size_t i = 16; i < 64; i++) {
  //   const uint32_t w2 = w[i - 2],
  //                  w7 = w[i - 7],
  //                  w15 = w[i - 15],
  //                  w16 = w[i - 16],
  //                  s0 = rr(w15, 7) ^ rr(w15, 18) ^ (w15 >> 3),
  //                  s1 = rr(w2, 17) ^ rr(w2, 19) ^ (w2 >> 10);
  //   w[i] = w16 + s0 + w7 + s1;
  // }
  //
  // // fully unrolled version:
  // WE(24); WE(25); WE(26); WE(27); WE(28); WE(29); WE(30); WE(31);
  // WE(32); WE(33); WE(34); WE(35); WE(36); WE(37); WE(38); WE(39);
  // WE(40); WE(41); WE(42); WE(43); WE(44); WE(45); WE(46); WE(47);
  // WE(48); WE(49); WE(50); WE(51); WE(52); WE(53); WE(54); WE(55);
  // WE(56); WE(57); WE(58); WE(59); WE(60); WE(61); WE(62); WE(63);
  //
  // partially unrolled:
  // for (size_t we_i = 16; we_i < 64; we_i += 16) {
  //   WE(we_i + 0); WE(we_i + 1); WE(we_i + 2); WE(we_i + 3);
  //   WE(we_i + 4); WE(we_i + 5); WE(we_i + 6); WE(we_i + 7);
  //   WE(we_i + 8); WE(we_i + 9); WE(we_i + 10); WE(we_i + 11);
  //   WE(we_i + 12); WE(we_i + 13); WE(we_i + 14); WE(we_i + 15);
  // }
  for (size_t i = 16; i < 64; i++) {
    WE(i);
  }

  // Initialize working variables to current hash value
  uint32_t hs[8] = {
    ctx->h[0], ctx->h[1], ctx->h[2], ctx->h[3],
    ctx->h[4], ctx->h[5], ctx->h[6], ctx->h[7],
  };

  // Compression function main loop
  //
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
  //
  // for (size_t i = 0; i < 64; i++) {
  //   const uint32_t s1 = rr(hs[4], 6) ^ rr(hs[4], 11) ^ rr(hs[4], 25),
  //                  ch = (hs[4] & hs[5]) ^ ((~(hs[4])) & hs[6]),
  //                  t0 = hs[7] + s1 + ch + K[i] + w[i],
  //                  s0 = rr(hs[0], 2) ^ rr(hs[0], 13) ^ rr(hs[0], 22),
  //                  mj = (hs[0] & hs[1]) ^ (hs[0] & hs[2]) ^ (hs[1] & hs[2]),
  //                  t1 = s0 + mj;

  //   hs[7] = hs[6];
  //   hs[6] = hs[5];
  //   hs[5] = hs[4];
  //   hs[4] = hs[3] + t0;
  //   hs[3] = hs[2];
  //   hs[2] = hs[1];
  //   hs[1] = hs[0];
  //   hs[0] = t0 + t1;
  // }
  //
  // // fully unrolled version:
  // WC(0); WC(1); WC(2); WC(3); WC(4); WC(5); WC(6); WC(7);
  // WC(8); WC(9); WC(10); WC(11); WC(12); WC(13); WC(14); WC(15);
  // WC(16); WC(17); WC(18); WC(19); WC(20); WC(21); WC(22); WC(23);
  // WC(24); WC(25); WC(26); WC(27); WC(28); WC(29); WC(30); WC(31);
  // WC(32); WC(33); WC(34); WC(35); WC(36); WC(37); WC(38); WC(39);
  // WC(40); WC(41); WC(42); WC(43); WC(44); WC(45); WC(46); WC(47);
  // WC(48); WC(49); WC(50); WC(51); WC(52); WC(53); WC(54); WC(55);
  // WC(56); WC(57); WC(58); WC(59); WC(60); WC(61); WC(62); WC(63);
  //
  // partially unrolled:
  for (size_t i = 0; i < 64; i += 16) {
    WC(i + 0); WC(i + 1); WC(i + 2); WC(i + 3);
    WC(i + 4); WC(i + 5); WC(i + 6); WC(i + 7);
    WC(i + 8); WC(i + 9); WC(i + 10); WC(i + 11);
    WC(i + 12); WC(i + 13); WC(i + 14); WC(i + 15);
  }

  // Add the compressed chunk to the current hash value
  ctx->h[0] += hs[0];
  ctx->h[1] += hs[1];
  ctx->h[2] += hs[2];
  ctx->h[3] += hs[3];
  ctx->h[4] += hs[4];
  ctx->h[5] += hs[5];
  ctx->h[6] += hs[6];
  ctx->h[7] += hs[7];
}

#undef WI
#undef WE
#undef WC

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

void sha256_push(
  sha256_t * const ctx,
  const uint8_t * const src,
  const size_t src_len
) {
  const size_t buf_left = 64 - ctx->buf_len;

  if (src_len >= buf_left) {
    // fill remaining buffer
    memcpy(ctx->buf + ctx->buf_len, src, buf_left);
    sha256_block(ctx);
    ctx->buf_len = 0;

    const size_t new_src_len = src_len - buf_left;
    const size_t num_blocks = new_src_len / 64;

    // process chunks
    for (size_t i = 0; i < num_blocks; i++) {
      memcpy(ctx->buf, src + buf_left + (64 * i), 64);
      sha256_block(ctx);
    }

    // copy remaining bytes to buffer
    const size_t new_buf_len = (new_src_len - 64 * num_blocks);
    memcpy(ctx->buf, src + buf_left + (64 * num_blocks), new_buf_len);
    ctx->buf_len = new_buf_len;
  } else {
    memcpy(ctx->buf + ctx->buf_len, src, src_len);
    ctx->buf_len += src_len;
  }

  // update byte count
  ctx->num_bytes += src_len;
}

static void
sha256_push_u64(
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

// end of stream padding
static const uint8_t PADDING[65] = {
  128, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#define WB(ctx, i)  \
    ((ctx)->h[i] >> 24) & 0xff, \
    ((ctx)->h[i] >> 16) & 0xff, \
    ((ctx)->h[i] >> 8) & 0xff,  \
    ((ctx)->h[i]) & 0xff

void sha256_fini(
  sha256_t * const ctx,
  uint8_t * const out
) {
  const uint64_t num_bytes = ctx->num_bytes;
  const size_t pad_len = (65 - ((num_bytes + 1 + 8) % 64));

  // push padding
  sha256_push(ctx, PADDING, pad_len);

  // push length (in bits)
  sha256_push_u64(ctx, num_bytes * 8);

  // extract hash
  const uint8_t hash[32] = {
    WB(ctx, 0), WB(ctx, 1), WB(ctx, 2), WB(ctx, 3),
    WB(ctx, 4), WB(ctx, 5), WB(ctx, 6), WB(ctx, 7),
  };

  memcpy(out, hash, sizeof(hash));
}

#undef WB

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
