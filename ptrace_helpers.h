#pragma once

#include <sys/ptrace.h>

int read_data(pid_t pid, void *addr, uint8_t *buf, int len) {
	int remaining;
    union {
        uint64_t val;
        char bytes[sizeof(uint64_t)];
    } u; // union idea taken from http://www.linuxjournal.com/article/6210

    while (len) {
        if (len < sizeof(uint64_t)) break;

        errno = 0;
        u.val = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
        if (u.val == -1 && errno != 0) return -1;
        memcpy(buf, u.bytes, sizeof(uint64_t));

        len -= sizeof(uint64_t);
        buf += sizeof(uint64_t);
        addr += sizeof(uint64_t);
    }

    errno = 0;
    u.val = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if (u.val == -1 && errno != 0) return -1;
    memcpy(buf, u.bytes, len % sizeof(uint64_t));

    return 0;
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