Self-contained [C11][] [SHA-2][] implementation.

Includes implementations of the following:
* SHA-224
* SHA-256
* SHA-384
* SHA-512
* HMAC-SHA-256
* HMAC-SHA-512

See `tests.c` for usage.

Benchmarks
==========
Benchmarks.

Partially unrolled compression makes this implementation faster than
[coreutils][], but slower than the [assembly-optimized, family-specific
OpenSSL SHA-2 implementation][openssl-asm-sha].

```
> time -p ./sha256 ~/Videos/8x*avi > /dev/null
rleal 9.39
user 9.10
sys 0.29
> time -p sha256sum ~/Videos/8x*avi > /dev/null
real 12.04
user 11.73
sys 0.31
> time -p openssl sha256 ~/Videos/8x*avi > /dev/null
real 6.36
user 6.01
sys 0.32
```

  [sha-2]: https://en.wikipedia.org/wiki/SHA-2 "Secure Hash Algorithm 2"
  [c11]: https://en.wikipedia.org/wiki/C11_(C_standard_revision) "C11 standard of the C programming language"
  [coreutils]: https://www.gnu.org/software/coreutils/ "GNU core utilities"
  [openssl-asm-sha]: https://github.com/openssl/openssl/tree/master/crypto/sha/asm "assembly-optimized OpenSSL SHA-2 implementation."
