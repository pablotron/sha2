#include <stdio.h> // printf()
#include <string.h> // strlen()
#include "sha256.h"
#include "tests.h"

static uint8_t dst[SHA256_HASH_SIZE];

static void print_hash(const uint8_t * const hash) {
  for (size_t i = 0; i < SHA256_HASH_SIZE; i++) {
    printf("%02x", hash[i]);
  }
}

static void print_row(
  const char * const src,
  const uint8_t * const hash
) {
  printf("\"%s\",", src);
  print_hash(hash);
  printf("\n");
}

static void on_test_fail(
  const char * const src,
  const uint8_t * const got_hash,
  const uint8_t * const expected_hash
) {
  printf("\"%s\",", src);
  print_hash(got_hash);
  printf(",");
  print_hash(expected_hash);
  printf("\n");
}

int main(int argc, char *argv[]) {
  if (argc > 1) {
    // if command-line parameters are given, then hash and print them
    // instead of running the test vectors

    for (int i = 1; i < argc; i++) {
      const char * const src = argv[i];

      sha256((const uint8_t *) src, strlen(src), dst);
      print_row(src, dst);
    }
  } else {
    // no command-line parameters given.  run internal tests
    printf("input,result,expected\n");
    run_tests(on_test_fail);
  }

  return 0;
}
