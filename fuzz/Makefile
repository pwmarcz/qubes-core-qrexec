override CC = clang
CFLAGS += -g
CFLAGS += -I. -I../libqrexec
CFLAGS += -std=c11 -D_GNU_SOURCE
CFLAGS += -fsanitize=fuzzer,address

fuzzer: fuzzer.o exec.o buffer.o ioall.o
	$(CC) $(CFLAGS) -o $@ $^

fuzzer.o: fuzzer.c
	$(CC) $(CFLAGS) -o $@ -c $^

exec.o: ../libqrexec/exec.c
	$(CC) $(CFLAGS) -o $@ -c $^

buffer.o: ../libqrexec/buffer.c
	$(CC) $(CFLAGS) -o $@ -c $^

ioall.o: ../libqrexec/ioall.c
	$(CC) $(CFLAGS) -o $@ -c $^
