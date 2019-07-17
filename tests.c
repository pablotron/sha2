#include <string.h> // memcmp()
#include "sha2.h"
#include "tests.h"

#define DEF_TEST_FUNC(size) \
  static const size_t NUM_SHA ## size ## _TESTS = \
    (sizeof(SHA ## size ## _TESTS) / sizeof(SHA ## size ## _TESTS[0])); \
  \
  static unsigned int \
  run_sha ## size ## _tests(test_fail_cb_t on_fail) { \
    unsigned int r = 0; \
    uint8_t hash[SHA ## size ## _HASH_SIZE]; \
  \
    for (size_t i = 0; i < NUM_SHA ## size ## _TESTS; i++) { \
      const char * const s = SHA224_TESTS[i].s; \
      sha ## size((const uint8_t *) s, strlen(s), hash); \
      if (memcmp(hash, SHA ## size ## _TESTS[i].h, sizeof(hash))) { \
        on_fail(size, s, hash, SHA ## size ## _TESTS[i].h); \
        r++; \
      } \
    } \
  \
    return r; \
  }

static const struct {
  const char * const s;
  const uint8_t h[SHA256_HASH_SIZE];
} SHA256_TESTS[] = {{
  .s = "",
  .h = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
  },
}, {
  .s = "abc",
  .h = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
  },
}, {
  .s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  .h = {
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
  },
}};

static const struct {
  const char * const s;
  const uint8_t h[SHA224_HASH_SIZE];
} SHA224_TESTS[] = {{
  .s = "",
  .h = {
    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9,
    0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
    0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
    0xc5, 0xb3, 0xe4, 0x2f,
  },
}, {
  .s = "abc",
  .h = {
    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
    0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
    0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
    0xe3, 0x6c, 0x9d, 0xa7,
  },
}, {
  .s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  .h = {
    0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc,
    0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89, 0x01, 0x50,
    0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19,
    0x52, 0x52, 0x25, 0x25,
  },
}};

DEF_TEST_FUNC(256)
DEF_TEST_FUNC(224)

unsigned int run_tests(test_fail_cb_t on_fail) {
  unsigned int r = 0;

  r += run_sha256_tests(on_fail);
  r += run_sha224_tests(on_fail);

  return r;
}
