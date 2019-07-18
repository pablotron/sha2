#include "sha2.h"
#include <string.h> // memcpy()

// extract bytes from uint32_t
// (used in sha256_fini() and sha224_fini())
#define E4(ctx, i)  \
    ((ctx)->h[i] >> 24) & 0xff, \
    ((ctx)->h[i] >> 16) & 0xff, \
    ((ctx)->h[i] >> 8) & 0xff,  \
    ((ctx)->h[i]) & 0xff

// sha256 initial hash values
// (first 32 bits of the fractional parts of the square roots of the
// first 8 primes 2..19):
static const uint32_t SHA256_INIT[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// sha256 round constants
// (first 32 bits of the fractional parts of the cube roots of the first
// 64 primes 2..311):
static const uint32_t K256[64] = {
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

// rotate right (uint32_t)
// (src: https://blog.regehr.org/archives/1063)
static inline uint32_t
rr32(const uint32_t v, const size_t n) {
  return (v << (32 - n)) | (v >> n);
}

#if 0
#define rr32(v, n) (((v) << (32 - (n))) | ((v) >> (n)))
#endif /* 0 */

// rotate right (uint64_t)
// (src: https://blog.regehr.org/archives/1063)
static inline uint64_t
rr64(const uint64_t v, const size_t n) {
  return (v << (64 - n)) | (v >> n);
}

#if 0
#define rr64(v, n) (((v) << (64 - (n))) | ((v) >> (n)))
#endif /* 0 */

void sha256_init(sha256_t * const ctx) {
  ctx->num_bytes = 0;
  memcpy(ctx->h, SHA256_INIT, sizeof(SHA256_INIT));
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
                 s0 = rr32(w15, 7) ^ rr32(w15, 18) ^ (w15 >> 3), \
                 s1 = rr32(w2, 17) ^ rr32(w2, 19) ^ (w2 >> 10); \
  w[i] = w16 + s0 + w7 + s1; \
} while (0)

// WC: compress word
#define WC(i) do { \
  const uint32_t s1 = rr32(hs[4], 6) ^ rr32(hs[4], 11) ^ rr32(hs[4], 25), \
                 ch = (hs[4] & hs[5]) ^ ((~(hs[4])) & hs[6]), \
                 t0 = hs[7] + s1 + ch + K256[i] + w[i], \
                 s0 = rr32(hs[0], 2) ^ rr32(hs[0], 13) ^ rr32(hs[0], 22), \
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
  //                  s0 = rr32(w15, 7) ^ rr32(w15, 18) ^ (w15 >> 3),
  //                  s1 = rr32(w2, 17) ^ rr32(w2, 19) ^ (w2 >> 10);
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
  //   const uint32_t s1 = rr32(hs[4], 6) ^ rr32(hs[4], 11) ^ rr32(hs[4], 25),
  //                  ch = (hs[4] & hs[5]) ^ ((~(hs[4])) & hs[6]),
  //                  t0 = hs[7] + s1 + ch + K256[i] + w[i],
  //                  s0 = rr32(hs[0], 2) ^ rr32(hs[0], 13) ^ rr32(hs[0], 22),
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

void sha256_push(
  sha256_t * const ctx,
  const uint8_t * const src,
  const size_t src_len
) {
  const size_t buf_len = ctx->num_bytes % 64;
  const size_t buf_left = 64 - buf_len;

  if (src_len >= buf_left) {
    // fill remaining buffer
    memcpy(ctx->buf + buf_len, src, buf_left);
    sha256_block(ctx);

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
  } else {
    memcpy(ctx->buf + buf_len, src, src_len);
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

// sha256 end of stream padding
static const uint8_t SHA256_PADDING[65] = {
  128,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static void
sha256_push_footer(
  sha256_t * const ctx
) {
  const uint64_t num_bytes = ctx->num_bytes;
  const size_t pad_len = (65 - ((num_bytes + 1 + 8) % 64));

  // push padding
  sha256_push(ctx, SHA256_PADDING, pad_len);

  // push length (in bits)
  sha256_push_u64(ctx, num_bytes * 8);
}

void sha256_fini(
  sha256_t * const ctx,
  uint8_t * const out
) {
  // push footer
  sha256_push_footer(ctx);

  // extract hash
  const uint8_t hash[32] = {
    E4(ctx, 0), E4(ctx, 1), E4(ctx, 2), E4(ctx, 3),
    E4(ctx, 4), E4(ctx, 5), E4(ctx, 6), E4(ctx, 7),
  };

  memcpy(out, hash, sizeof(hash));
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

// sha224 initial hash values
// (the second 32 bits of the fractional parts of the square roots of
// the 9th through 16th primes 23..53)
static const uint32_t SHA224_INIT[8] = {
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
  0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

void sha224_init(sha224_t * const ctx) {
  ctx->ctx.num_bytes = 0;
  memcpy(ctx->ctx.h, SHA224_INIT, sizeof(SHA224_INIT));
}

void sha224_push(
  sha224_t * const sha224_ctx,
  const uint8_t * const src,
  const size_t src_len
) {
  sha256_t * const ctx = (sha256_t * const) sha224_ctx;
  sha256_push(ctx, src, src_len);
}

void sha224_fini(
  sha224_t * const sha224_ctx,
  uint8_t * const out
) {
  sha256_t * const ctx = (sha256_t * const) sha224_ctx;

  // push footer
  sha256_push_footer(ctx);

  // extract hash
  const uint8_t hash[28] = {
    E4(ctx, 0), E4(ctx, 1), E4(ctx, 2), E4(ctx, 3),
    E4(ctx, 4), E4(ctx, 5), E4(ctx, 6),
  };

  memcpy(out, hash, sizeof(hash));
}

void sha224(
  const uint8_t * const src,
  const size_t src_len,
  uint8_t * const dst
) {
  sha224_t ctx;
  sha224_init(&ctx);
  sha224_push(&ctx, src, src_len);
  sha224_fini(&ctx, dst);
}

// extract bytes from uint64_t
// (used in sha512_fini() and sha384_fini())
#define E8(ctx, i)  \
    ((ctx)->h[i] >> 56) & 0xff, \
    ((ctx)->h[i] >> 48) & 0xff, \
    ((ctx)->h[i] >> 40) & 0xff, \
    ((ctx)->h[i] >> 32) & 0xff, \
    ((ctx)->h[i] >> 24) & 0xff, \
    ((ctx)->h[i] >> 16) & 0xff, \
    ((ctx)->h[i] >> 8) & 0xff,  \
    ((ctx)->h[i]) & 0xff

// sha512 initial hash values
// (first 64 bits of the fractional parts of the square roots of the
// first 8 primes 2..19):
static const uint64_t SHA512_INIT[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
  0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

// sha512 round constants
// (first 64 bits of the fractional parts of the cube roots of the first
// 80 primes [2..409]):
static const uint64_t K512[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
  0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
  0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
  0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
  0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
  0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
  0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
  0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
  0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
  0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
  0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
  0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
  0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
  0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
  0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
  0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
  0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

void sha512_init(sha512_t * const ctx) {
  ctx->num_bytes = 0;
  memcpy(ctx->h, SHA512_INIT, sizeof(SHA512_INIT));
}

// WI64: decode buffer data as 64-bit words (used for the first 16 words)
#define WI64(i) ( \
  (((uint64_t) ctx->buf[8 * (i) + 0]) << 56) | \
  (((uint64_t) ctx->buf[8 * (i) + 1]) << 48) | \
  (((uint64_t) ctx->buf[8 * (i) + 2]) << 40) | \
  (((uint64_t) ctx->buf[8 * (i) + 3]) << 32) | \
  (((uint64_t) ctx->buf[8 * (i) + 4]) << 24) | \
  (((uint64_t) ctx->buf[8 * (i) + 5]) << 16) | \
  (((uint64_t) ctx->buf[8 * (i) + 6]) << 8) | \
  ((uint64_t) ctx->buf[8 * (i) + 7]) \
)

// WE64: expand first 16 buffer words into remaining 64 words
#define WE64(i) do { \
  const uint64_t w2 = w[(i) - 2], \
                 w7 = w[(i) - 7], \
                 w15 = w[(i) - 15], \
                 w16 = w[(i) - 16], \
                 s0 = rr64(w15, 1) ^ rr64(w15, 8) ^ (w15 >> 7), \
                 s1 = rr64(w2, 19) ^ rr64(w2, 61) ^ (w2 >> 6); \
  w[i] = w16 + s0 + w7 + s1; \
} while (0)

// WC64: compress word
#define WC64(i) do { \
  const uint64_t s1 = rr64(hs[4], 14) ^ rr64(hs[4], 18) ^ rr64(hs[4], 41), \
                 ch = (hs[4] & hs[5]) ^ ((~(hs[4])) & hs[6]), \
                 t0 = hs[7] + s1 + ch + K512[i] + w[i], \
                 s0 = rr64(hs[0], 28) ^ rr64(hs[0], 34) ^ rr64(hs[0], 39), \
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
sha512_block(sha512_t * const ctx) {
  // init first 16 words from buffer
  uint64_t w[80] = {
    WI64(0), WI64(1), WI64(2), WI64(3),
    WI64(4), WI64(5), WI64(6), WI64(7),
    WI64(8), WI64(9), WI64(10), WI64(11),
    WI64(12), WI64(13), WI64(14), WI64(15),
    0,
  };

  // Extend the first 16 words into the remaining 64 words w[16..80] of
  // the message schedule array
  for (size_t i = 16; i < 80; i++) {
    WE64(i);
  }

  // Initialize working variables to current hash value
  uint64_t hs[8] = {
    ctx->h[0], ctx->h[1], ctx->h[2], ctx->h[3],
    ctx->h[4], ctx->h[5], ctx->h[6], ctx->h[7],
  };

  // Compression function main loop
  //
  // partially unrolled:
  for (size_t i = 0; i < 80; i += 16) {
    WC64(i + 0); WC64(i + 1); WC64(i + 2); WC64(i + 3);
    WC64(i + 4); WC64(i + 5); WC64(i + 6); WC64(i + 7);
    WC64(i + 8); WC64(i + 9); WC64(i + 10); WC64(i + 11);
    WC64(i + 12); WC64(i + 13); WC64(i + 14); WC64(i + 15);
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

#undef WI64
#undef WE64
#undef WC64

void sha512_push(
  sha512_t * const ctx,
  const uint8_t * const src,
  const size_t src_len
) {
  const size_t buf_len = ctx->num_bytes % 128;
  const size_t buf_left = 128 - buf_len;

  if (src_len >= buf_left) {
    // fill remaining buffer
    memcpy(ctx->buf + buf_len, src, buf_left);
    sha512_block(ctx);

    const size_t new_src_len = src_len - buf_left;
    const size_t num_blocks = new_src_len / 128;

    // process chunks
    for (size_t i = 0; i < num_blocks; i++) {
      memcpy(ctx->buf, src + buf_left + (128 * i), 128);
      sha512_block(ctx);
    }

    // copy remaining bytes to buffer
    const size_t new_buf_len = (new_src_len - 128 * num_blocks);
    memcpy(ctx->buf, src + buf_left + (128 * num_blocks), new_buf_len);
  } else {
    memcpy(ctx->buf + buf_len, src, src_len);
  }

  // update byte count
  ctx->num_bytes += src_len;
}

static void
sha512_push_u128(
  sha512_t * const ctx,
  const uint64_t hi,
  const uint64_t lo
) {
  const uint8_t buf[16] = {
    ((hi >> 56) & 0xff),
    ((hi >> 48) & 0xff),
    ((hi >> 40) & 0xff),
    ((hi >> 32) & 0xff),
    ((hi >> 24) & 0xff),
    ((hi >> 16) & 0xff),
    ((hi >> 8) & 0xff),
    ((hi) & 0xff),
    ((lo >> 56) & 0xff),
    ((lo >> 48) & 0xff),
    ((lo >> 40) & 0xff),
    ((lo >> 32) & 0xff),
    ((lo >> 24) & 0xff),
    ((lo >> 16) & 0xff),
    ((lo >> 8) & 0xff),
    ((lo) & 0xff),
  };

  sha512_push(ctx, buf, sizeof(buf));
}

// sha512 end of stream padding
static const uint8_t SHA512_PADDING[129] = {
  128,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static void
sha512_push_footer(
  sha512_t * const ctx
) {
  const uint64_t num_bytes = ctx->num_bytes;
  const size_t pad_len = (129 - ((num_bytes + 1 + 16) % 128));

  // push padding
  sha512_push(ctx, SHA512_PADDING, pad_len);

  // push length (in bits)
  sha512_push_u128(ctx, 0, num_bytes * 8);
}

void sha512_fini(
  sha512_t * const ctx,
  uint8_t * const out
) {
  // push footer
  sha512_push_footer(ctx);

  // extract hash
  const uint8_t hash[64] = {
    E8(ctx, 0), E8(ctx, 1), E8(ctx, 2), E8(ctx, 3),
    E8(ctx, 4), E8(ctx, 5), E8(ctx, 6), E8(ctx, 7),
  };

  memcpy(out, hash, sizeof(hash));
}

void sha512(
  const uint8_t * const src,
  const size_t src_len,
  uint8_t * const dst
) {
  sha512_t ctx;
  sha512_init(&ctx);
  sha512_push(&ctx, src, src_len);
  sha512_fini(&ctx, dst);
}

// sha384 initial hash values
// (the second 64 bits of the fractional parts of the square roots of
// the 9th through 16th primes 23..53)
static const uint64_t SHA384_INIT[8] = {
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
  0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

void sha384_init(sha384_t * const ctx) {
  ctx->ctx.num_bytes = 0;
  memcpy(ctx->ctx.h, SHA384_INIT, sizeof(SHA384_INIT));
}

void sha384_push(
  sha384_t * const sha384_ctx,
  const uint8_t * const src,
  const size_t src_len
) {
  sha512_t * const ctx = (sha512_t * const) sha384_ctx;
  sha512_push(ctx, src, src_len);
}

void sha384_fini(
  sha384_t * const sha384_ctx,
  uint8_t * const out
) {
  sha512_t * const ctx = (sha512_t * const) sha384_ctx;

  // push footer
  sha512_push_footer(ctx);

  // extract hash
  const uint8_t hash[56] = {
    E8(ctx, 0), E8(ctx, 1), E8(ctx, 2), E8(ctx, 3),
    E8(ctx, 4), E8(ctx, 5), E8(ctx, 6),
  };

  memcpy(out, hash, sizeof(hash));
}

void sha384(
  const uint8_t * const src,
  const size_t src_len,
  uint8_t * const dst
) {
  sha384_t ctx;
  sha384_init(&ctx);
  sha384_push(&ctx, src, src_len);
  sha384_fini(&ctx, dst);
}
