CFLAGS=-std=c11 -W -Wall -Wextra -pedantic -O3 -march=native
TEST_OBJS=sha2.o run-tests.o tests.o hmac-sha2.o
TEST_APP=run-tests
HASH_OBJS=sha2.o hash-main.o tests.o hmac-sha2.o
HASH_APP=hash-sha256
HMAC_OBJS=sha2.o hmac-sha2.o hmac-main.o
HMAC_APP=hmac-sha256

.PHONY=all clean

all: $(TEST_APP) $(HMAC_APP) $(HASH_APP)

$(TEST_APP): $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $(TEST_APP) $(TEST_OBJS)

$(HASH_APP): $(HASH_OBJS)
	$(CC) $(CFLAGS) -o $(HASH_APP) $(HASH_OBJS)

$(HMAC_APP): $(HMAC_OBJS)
	$(CC) $(CFLAGS) -o $(HMAC_APP) $(HMAC_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(TEST_OBJS) $(TEST_APP) \
        $(HASH_OBJS) $(HASH_APP) \
        $(HMAC_OBJS) $(HMAC_APP)

test: $(TEST_APP)
	@# ./$(TEST_APP) '' 'foobar'
	@./$(TEST_APP)
