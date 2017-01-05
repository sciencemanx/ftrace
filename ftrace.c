#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <errno.h>

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

int write_data(pid_t child, void *addr, uint8_t *data, int len) {
    int remaining;
    union {
        uint64_t val;
        char bytes[sizeof(uint64_t)];
    } u; // union idea taken from http://www.linuxjournal.com/article/6210

    while (len) {
        if (len < sizeof(uint64_t)) break;

        if (ptrace(PTRACE_POKETEXT, child, addr, data) == -1) return -1;

        len -= sizeof(uint64_t);
        data += sizeof(uint64_t);
        addr += sizeof(uint64_t);
    }

    errno = 0;
    u.val = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
    if (u.val == -1 && errno != 0) return -1;
    // printf("before: %lx\n", u.val);
    memcpy(u.bytes, data, len % sizeof(uint64_t));
    if (ptrace(PTRACE_POKETEXT, child, addr, u.val) == -1) return -1;
    // u.val = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
    // printf("after: %lx\n", u.val);

    return 0;
}

int add_breakpoint(pid_t child, void *addr) {
    uint8_t ins[1] = {trap_inst};

    write_data(child, addr, ins, sizeof(ins));

    return 0;
}

int restore_code(pid_t child, void *addr, int len, struct elf *e) {

    write_data(child, addr, get_code(e, addr), len);

    return 0;
}

int add_breakpoints(pid_t child, struct elf *e) {
    int i;
    Elf64_Sym s;

    for (i = 0; i < e->n_syms; i++) {
        if (sym_in_section(e, i, ".text")) {
            // printf("adding breakpoint to %s\n", get_sym_name(e, i));
            add_breakpoint(child, get_sym_addr(e, i));
        }
    }

    return 0;
}

int trace(pid_t child, struct elf *e) {
    int status;
    struct user_regs_struct regs;
    int sym_i, depth;
    void *sym_addr;

    wait(&status);

    add_breakpoints(child, e);
    ptrace(PTRACE_CONT, child, NULL, NULL);

    while (1) {
        wait(&status);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("traced program exited\n");
            break;
        }

        if (WSTOPSIG(status) == SIGTRAP) {
            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            sym_i = at_symbol(e, (void *) (regs.rip - 1)); // minus 1 because int 3 already executed
            if (sym_i == -1) error("encountered breakpoint at nonsymbol location");
            printf("%s(%llx, %llx, %llx)\n", 
                get_sym_name(e, sym_i), regs.rdi, regs.rsi, regs.rdx);

            sym_addr = get_sym_addr(e, sym_i);

            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
            restore_code(child, sym_addr, 1, e);

            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            wait(&status);

            add_breakpoint(child, sym_addr);

            ptrace(PTRACE_CONT, child, NULL, NULL);
        } else {
            ptrace(PTRACE_CONT, child, NULL, WSTOPSIG(status));
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