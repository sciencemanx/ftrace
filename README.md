# ftrace
> ltrace/strace but for local functions

## Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [Future work](#future-work)
- [Dependencies](#dependencies)
- [Limitations](#limitations)

## Introduction
The basic idea behind the implementation is:

1. Read in ELF file and identify symbols
2. Fork and ptrace target process
3. Add breakpoints to all symbols
4. Catch breakpoints and log function call; additionally, add a temp. breakpoint to return pointer (for decreasing depthing and logging return value)
5. Repeat

Some other fancy stuff happens in the background. For instance, if no header file is provided simple taint analysis is done on functions to determine the number of function arguments.

## Installation

## Usage

> `./ftrace <program> [arg 1] [arg2] ...`

### Optional parameters
- `-C` - adds colored output
- `-H <file>` - header file to use for function logging
- `-R` - display function return values
- `-o <file>` - specifies output file (replaces stderr)
- `-h` - display this message

## Example

### test.c
``` c
#include <stdio.h>
#include <stdlib.h>

int fib(int n) {
	if (n == 0 || n == 1) return 1;
	else return fib(n - 1) + fib(n - 2);
}

int main(int argc, char **argv) {
	int n = atoi(argv[1]);
	printf("%d\n", fib(n));
	return 0;
}
```


```
$ gcc -o test test.c
$ ./ftrace ./test 3
_start()
__libc_csu_init(2, *0x7ffe0cb39158, *0x7ffe0cb39170)
main(2, *0x7ffe0cb39158)
get_n(*0x7ffe0cb3986c)
fib(3)
  fib(2)
    fib(1)
    fib(0)
  fib(1)
3
```


## Future work

## Dependencies 

* [Capstone Version 4.0-alpha3](https://github.com/aquynh/capstone/releases/tag/4.0-alpha3)

## Limitations
- Currently only compatible with 64 bit ELF files.
