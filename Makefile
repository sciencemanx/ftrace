CC=gcc
CFLAGS=

DEPS=functools.h readelf.h ptrace_helpers.h logging.h

ftrace: ftrace.c functools.h readelf.h ptrace_helpers.h logging.h
	$(CC) -o ftrace ftrace.c -lcapstone

test: test.c
	$(CC) -o test test.c

clean:
	rm ftrace