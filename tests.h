#ifndef TESTS_H_
#define TESTS_H_

#include <stdint.h>

typedef void (*test_fail_cb_t)(
  const int,
  const char * const,
  const uint8_t *,
  const uint8_t *
);

unsigned int run_tests(test_fail_cb_t);

#endif /* TESTS_H_ */
