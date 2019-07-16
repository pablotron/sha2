CFLAGS=-W -Wall -Wextra -pedantic -O3 -std=c11
OBJS=sha256.o main.o
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
	./$(APP) ''
