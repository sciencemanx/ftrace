#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <errno.h>

#include "readelf.h"
#include "functools.h"
#include "ptrace_helpers.h"

const uint8_t trap_inst = 0xCC; 

const char *blacklist[] = {"", "frame_dummy", "register_tm_clones",
                           "deregister_tm_clones", "__do_global_dtors_aux"};

format_t *func_fmts = NULL;

void error(char *msg) {
    printf("[!] %s\n", msg);
    exit(1);
}

void usage(char *prog) {
    printf("Usage: %s <program> [arg 1] [arg2] ...\n\n"

           "Optional parameters:\n"
           "  -h          - display this message\n\n",
           
           prog);
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

int add_breakpoint(pid_t child, void *addr) {
    uint8_t ins[1] = {trap_inst};

    write_data(child, addr, ins, sizeof(ins));

    return 0;
}

int restore_code(pid_t child, void *addr, int len, struct elf *e) {

    write_data(child, addr, bytes_from_addr_in_section(e, addr, ".text"), len);

    return 0;
}

bool in_blacklist(char *name) {
    int i;

    for (i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        if (!strcmp(name, blacklist[i])) return true;
    }

    return false;
}

int register_functions(pid_t child, struct elf *e) {
    int i;
    char fmt_buf[FMT_LEN];

    for (i = 0; i < e->n_syms; i++) {
        if (sym_in_section(e, i, ".text") && !in_blacklist(get_sym_name(e, i))) {
            // printf("adding breakpoint to %s\n", get_sym_name(e, i));
            add_breakpoint(child, get_sym_addr(e, i));

            memset(fmt_buf, 0, sizeof(fmt_buf));
            basic_func_fmt(e, i, fmt_buf, sizeof(fmt_buf));
            func_fmts = add_format(func_fmts, get_sym_addr(e, i), i, fmt_buf);

            // printf("%s has %d args\n", get_sym_name(e, i), n_func_args(e, i));
        }
    }

    // print_formats(func_fmts);

    return 0;
}

void print_depth(int d) {
    while (d--) {
        printf(" ");
    }
}

int trace(pid_t child, struct elf *e) {
    int status;
    struct user_regs_struct regs;
    int sym_i, depth;
    void *bp_addr, *ret_addr;
    format_t *fmt;
    char fmt_buf[FMT_LEN];

    wait(&status);

    // printf("%lx\n", ptrace(PTRACE_PEEKTEXT, child, 100, NULL));

    register_functions(child, e);
    ptrace(PTRACE_CONT, child, NULL, NULL);

    depth = 0;
    while (1) {
        wait(&status);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            // printf("child exited of signal %d\n", WSTOPSIG(status));
            break;
        }

        if (WSTOPSIG(status) == SIGTRAP) {
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) error("error getting regs");

            bp_addr = bp_addr = (void *) (regs.rip - 1);
            sym_i = at_symbol(e, bp_addr); // minus 1 because int 3 already executed

            if (sym_i == -1) {
                // we are returning from a local function call
                depth -= 1;
            } else {
                // sym_i != -1 therefore we are at a function breakpoint
                print_depth(depth * 2);
                // printf("%s(%lld)\n", 
                //     get_sym_name(e, sym_i), regs.rdi);
                fmt = get_format(func_fmts, bp_addr);

                if (!fmt->fancy) {
                    memset(fmt_buf, 0, sizeof(fmt_buf));
                    fancy_func_fmt(e, fmt->sym_i, fmt_buf, sizeof(fmt_buf), child);
                    update_format(func_fmts, fmt->addr, fmt_buf);
                    fmt->fancy = true;
                }

                printf(fmt->str, regs.rdi, regs.rsi, regs.rdx);
                printf("\n");

                ret_addr = (void *) ptrace(PTRACE_PEEKTEXT, child, regs.rsp, NULL);
                if (addr_in_section(e, ret_addr, ".text")) {
                    // printf("adding bp to return address %p\n", ret_addr);
                    add_breakpoint(child, ret_addr);
                    depth += 1;
                }
            }
            

            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
            // printf("restoring bp %p\n", bp_addr);
            restore_code(child, bp_addr, 1, e);

            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            wait(&status);

            add_breakpoint(child, bp_addr);

            ptrace(PTRACE_CONT, child, NULL, NULL);
        } else {
            // wasn't our breakpoint -- deliver signal to child
            // printf("sending signal %d to child\n", WSTOPSIG(status));
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