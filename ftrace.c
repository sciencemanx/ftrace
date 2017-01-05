#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdbool.h>

#include "readelf.h"

const uint8_t trap_inst = 0xCC; 

void error(char *msg) {
	printf("[!] %s\n", msg);
	exit(1);
}

void usage(char *prog) {
	printf("Usage: %s <program> [arg 1] [arg2] ...\n", prog);
	exit(1);
}

void get_traced(char **argv) {
	if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) == -1) error("traceme failed");
	if (execvp(argv[0], argv) == -1) error("could not execute file");
}

int at_symbol(struct elf *e, void *addr) {
	int i;

	for (i = 0; i < e->n_syms; i++) {
		if (get_sym_addr(e, i) == addr) return i;
	}

	return -1;
}

int trace(pid_t child, struct elf *e) {
	int status;
	struct user_regs_struct regs;
	int sym_i;

	wait(&status);

	while (1) {
		ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
		wait(&status);

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			break;
		}

		ptrace(PTRACE_GETREGS, child, NULL, &regs);

		if ((sym_i = at_symbol(e, (void *) regs.rip)) != -1) {
			printf("%s(%llx, %llx, %llx)\n", 
				get_sym_name(e, sym_i), regs.rdi, regs.rsi, regs.rdx);
		}
	}

	return 0;
}

int main(int argc, char **argv) {
	struct elf *e;
	int fd, i;
	pid_t pid;

	if (argc < 2) usage(argv[0]);

	fd = open(argv[1], O_RDONLY);

	if (fd == -1) error("failed to open file");

	e = readelf(fd);

	if (e == NULL) error("failed to read elf file for symbols");

	pid = fork();

	if (pid == -1) error("failed to fork");

	if (pid == 0) get_traced(argv + 1); // no return

	if (trace(pid, e) == -1) error("failed to trace program");

	return 0;
}