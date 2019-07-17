#include <stdio.h> // printf()
#include <string.h> // strlen()
#include "sha2.h"
#include "tests.h"

static void print_hash(const uint8_t * const hash) {
  for (size_t i = 0; i < SHA256_HASH_SIZE; i++) {
    printf("%02x", hash[i]);
  }
}

static void on_test_fail(
  const int algo,
  const char * const src,
  const uint8_t * const got_hash,
  const uint8_t * const expected_hash
) {
  printf("sha%d,\"%s\",", algo, src);
  print_hash(got_hash);
  printf(",");
  print_hash(expected_hash);
  printf("\n");
}

int main(int argc, char *argv[]) {
  (void) argc;
  (void) argv;

  // run internal tests
  printf("algo,input,result,expected\n");
  run_tests(on_test_fail);

  return 0;
}
