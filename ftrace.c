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
#include "logging.h"

const uint8_t trap_inst = 0xCC; 

const char *blacklist[] = {"", "frame_dummy", "register_tm_clones",
                           "deregister_tm_clones", "__do_global_dtors_aux"};

format_t *func_fmts = NULL;

// globals from command line arguments
bool show_ret = false;
char **traced_argv;

pid_t child;

void usage(char *prog) {
    printf("Usage: %s <program> [arg 1] [arg2] ...\n\n"

           "Optional parameters:\n"
           "  -C          - adds colored output\n"
           "  -H <file>   - header file to use for function logging\n"
           "  -R          - display function return values\n"
           "  -o <file>   - specifies output file (replaces stderr)\n"
           "  -h          - display this message\n\n",

           prog);
    exit(1);
}

void traced() {
    if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) == -1) error("traceme failed");
    if (execvp(traced_argv[0], traced_argv) == -1) error("could not execute file");
}

int add_breakpoint(void *addr) {
    uint8_t bp[1] = {trap_inst};
    return write_data(child, addr, bp, sizeof(bp));
}

int restore_code(void *addr, int len, struct elf *e) {
    return write_data(child, addr, bytes_from_addr_in_section(e, addr, ".text"), len);
}

bool in_blacklist(char *name) {
    int i;

    for (i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        if (!strcmp(name, blacklist[i])) return true;
    }

    return false;
}

int register_functions(struct elf *e) {
    int i;
    char fmt_buf[FMT_LEN];

    for (i = 0; i < e->n_syms; i++) {
        if (sym_in_section(e, i, ".text") && !in_blacklist(get_sym_name(e, i))) {
            add_breakpoint(get_sym_addr(e, i));

            memset(fmt_buf, 0, sizeof(fmt_buf));
            basic_func_fmt(e, i, fmt_buf, sizeof(fmt_buf));
            func_fmts = add_format(func_fmts, get_sym_addr(e, i), i, fmt_buf);
        }
    }

    return 0;
}

void print_depth(int d) {
    while (d--) {
        trace_print(" ");
    }
}

void trace(pid_t pid) {
    int status, fd;
    struct user_regs_struct regs;
    int sym_i, depth;
    void *bp_addr, *ret_addr;
    format_t *fmt;
    char fmt_buf[FMT_LEN];
    struct elf *e;

    child = pid;

    fd = open(traced_argv[0], O_RDONLY);
    if (fd == -1) error("failed to open file");

    e = readelf(fd);
    if (e == NULL) error("failed to read elf file for symbols");

    wait(&status);

    register_functions(e);
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

                trace_print(fmt->str, regs.rdi, regs.rsi, regs.rdx);
                trace_print("\n");

                ret_addr = (void *) ptrace(PTRACE_PEEKTEXT, child, regs.rsp, NULL);
                if (addr_in_section(e, ret_addr, ".text")) {
                    // printf("adding bp to return address %p\n", ret_addr);
                    add_breakpoint(ret_addr);
                    depth += 1;
                }
            }
            

            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
            // printf("restoring bp %p\n", bp_addr);
            restore_code(bp_addr, 1, e);

            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            wait(&status);

            add_breakpoint(bp_addr);

            ptrace(PTRACE_CONT, child, NULL, NULL);
        } else {
            // wasn't our breakpoint -- deliver signal to child
            ptrace(PTRACE_CONT, child, NULL, WSTOPSIG(status));
        }
    }
}

int main(int argc, char **argv) {
    pid_t pid;
    char opt;

    if (argc == 1) usage(argv[0]);

    while ((opt = getopt(argc, argv, "+CH:Ro:h")) != -1) {
        switch (opt) {
            case 'C':
                start_color = GREEN;
                end_color = RESET;
                break;
            case 'H':
                // read in header file and set formats accordingly
                error("Option 'H' not yet supported sorry!");
                break;
            case 'R':
                error("Option 'R' not yet supported sorry!");
                break;
            case 'o':
                trace_fd = open(optarg, O_WRONLY | O_CREAT | O_TRUNC);
                if (trace_fd == -1) error("Couldn't open output file %s", optarg);
                break;
            case 'h':
            default:
                usage(argv[0]);
                break;
        }
    }

    traced_argv = argv + optind;

    if (access(traced_argv[0], R_OK | X_OK) == -1) error("Unable to open %s", traced_argv[0]);

    if ((pid = fork()) == -1) error("failed to fork");

    if (pid == 0) traced();
    else trace(pid);
    
    return 0;
}