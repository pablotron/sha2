#ifndef TESTS_H_
#define TESTS_H_

unsigned int run_tests(
  void (*on_fail)(const char * const, const uint8_t *, const uint8_t *)
);

#endif /* TESTS_H_ */
