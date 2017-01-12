# ftrace
> ltrace/strace but for local functions

## Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)
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

## Future work

## Dependencies 

* [Capstone Version 4.0-alpha3](https://github.com/aquynh/capstone/releases/tag/4.0-alpha3)

## Limitations
- Currently only compatible with 64 bit ELF files.
