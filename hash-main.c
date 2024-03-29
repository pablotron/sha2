#include <stdio.h> // printf()
#include <string.h> // strlen()
#include "sha2.h"

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

static uint8_t dst[SHA256_HASH_SIZE];
static uint8_t buf[1 << 21];

int main(int argc, char *argv[]) {
  // if command-line parameters are given, then treat them as a
  // list of files: open each file, hash it, and and print the
  // result instead of running the test vectors

  for (int i = 1; i < argc; i++) {
    sha256_t ctx;
    sha256_init(&ctx);

    FILE *fh = fopen(argv[i], "rb");
    if (!fh) {
      fprintf(stderr, "fopen(\"%s\") failed", argv[i]);
      return 1;
    }

    size_t len = 0;
    while ((len = fread(buf, 1, sizeof(buf), fh)) > 0) {
      sha256_push(&ctx, buf, len);
    }

    fclose(fh);

    sha256_fini(&ctx, dst);
    print_row(argv[i], dst);
  }

  return 0;
}
