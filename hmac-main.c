#include <string.h> // strlen()
#include <stdio.h> // printf()
#include "hmac-sha2.h"

static void print_hash(const uint8_t * const hash) {
  for (size_t i = 0; i < SHA256_HASH_SIZE; i++) {
    printf("%02x", hash[i]);
  }
}

int main(int argc, char *argv[]) {
  // check args
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [key] [message]\n", argv[0]);
    return -1;
  }

  // calculate hmac
  uint8_t hash[SHA256_HASH_SIZE];
  hmac_sha256(
    (uint8_t *) argv[1], strlen(argv[1]),
    (uint8_t *) argv[2], strlen(argv[2]),
    hash
  );

  // print hash
  print_hash(hash);
  printf("\n");

  return 0;
}
