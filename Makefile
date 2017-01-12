CC=gcc
CFLAGS=

DEPS=functools.h readelf.h ptrace_helpers.h

ftrace: ftrace.c functools.h readelf.h
	$(CC) -o ftrace ftrace.c -lcapstone

clean:
	rm ftrace