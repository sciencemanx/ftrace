#include <capstone/capstone.h>
#include "readelf.h"

typedef enum reg_state {
	REG_UNDEF,
	REG_WRITTEN,
	REG_READ
} reg_state;

int get_reg_arg_index(x86_reg reg) {
	switch (reg) {
		case X86_REG_RDI:
		case X86_REG_EDI:
			return 0;
		case X86_REG_RSI:
		case X86_REG_ESI:
			return 1;
		case X86_REG_RDX:
		case X86_REG_EDX:
			return 2;
		case X86_REG_RCX:
		case X86_REG_ECX:
			return 3;
		default:
			return -1;
	}
}

int n_args_from_regs(reg_state *arg_regs, int n) {
	int i;

	for (i = 0; i < n; i++) {
		if (arg_regs[i] != REG_READ) return i;
	}

	return i;
}

// gets number of arguments for x86_64 system v abi assuming no passing structs
// by value
int n_func_args(struct elf *e, int sym_i) {
	void *func;
	uint8_t *code;
	size_t size, count, i, n;
	csh handle;
	cs_insn *all_insn, *insn;
	cs_detail *detail;
	cs_regs regs_read, regs_written;
	uint8_t read_count, write_count;
	int reg_i;
	reg_state arg_regs[] = {REG_UNDEF, REG_UNDEF, REG_UNDEF, REG_UNDEF};

	func = get_sym_addr(e, sym_i);
	code = bytes_from_addr_in_section(e, get_sym_addr(e, sym_i), ".text");
	size = get_sym_size(e, sym_i);

	if (size == 0) {
		printf("no size information for %s\n", get_sym_name(e, sym_i));
		return -1;
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		printf("unable to initilize handle\n");
		return -1;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	count = cs_disasm(handle, code, size, (uint64_t) func, 0, &all_insn);

	printf("%s [%p] size: %lx, count: %lx\n", 
		get_sym_name(e, sym_i), func, size, count);

	for (i = 0; i < count; i++) {
		insn = &all_insn[i];
		if (cs_regs_access(handle, insn,
						   regs_read, &read_count,
						   regs_written, &write_count)) return -1;
		// printf("\t%s %s [r: %u, w: %u]\n", insn->mnemonic, insn->op_str, read_count, write_count);
		// if (read_count > 0) printf("\t\tread:\n");
		// for (n = 0; n < read_count; n++) {
		// 	printf("\t\t\t%d\n", get_reg_arg_index(regs_read[n]));
		// }
		for (n = 0; n < read_count; n++) {
			reg_i = get_reg_arg_index(regs_read[n]);
			if (reg_i == -1) continue;
			if (arg_regs[reg_i] != REG_WRITTEN) arg_regs[reg_i] = REG_READ;
		}
		for (n = 0; n < write_count; n++) {
			reg_i = get_reg_arg_index(regs_written[n]);
			if (reg_i == -1) continue;
			if (arg_regs[reg_i] != REG_READ) arg_regs[reg_i] = REG_WRITTEN;
		}
	}

	return n_args_from_regs(arg_regs, 4);
}