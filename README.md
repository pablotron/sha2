My C11 SHA256 implementation.

See `tests.c` for usage.

Benchmarks
==========
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
