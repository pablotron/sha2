#include <stdio.h> // printf()
#include <string.h> // strlen()
#include "sha256.h"

static const char DEFAULT[] = "The quick brown fox jumps over the lazy dog";

int main(int argc, char *argv[]) {
  const char *src = (argc > 1) ? argv[1] : DEFAULT;
  uint8_t dst[SHA256_HASH_SIZE];

  sha256((const uint8_t *) src, strlen(src), dst);

  printf("src = \"%s\"\nhash = \"", src);
  for (size_t i = 0; i < 32; i++) {
    printf("%02x", dst[i]);
  }
  printf("\"\n");

  return 0;
}
