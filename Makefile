CFLAGS=-std=c11 -W -Wall -Wextra -pedantic -O3 -march=native
OBJS=sha2.o main.o tests.o
APP=sha256

.PHONY=all clean

all: $(APP)

$(APP): $(OBJS)
	$(CC) $(CFLAGS) -o $(APP) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS) $(APP)

test: $(APP)
	@# ./$(APP) '' 'foobar'
	@./$(APP)
