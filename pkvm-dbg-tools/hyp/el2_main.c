// SPDX-License-Identifier: GPL-2.0-only

#include <asm/kvm_pkvm_module.h>
#include <nvhe/module_dbg_tools.h>
#include "hyp_debug.h"
#include "dump_regs.h"
#include "config.h"

struct dbg_tool_ops *dops;
const struct pkvm_module_ops *ops;
unsigned long arm64_kvm_hyp_debug_uart_addr;

u64 hyp_dbg(u64 cmd, u64 param1, u64 param2, u64 param3, u64 param4);

static int create_hyp_debug_uart_mapping(void)
{
	phys_addr_t base = KVM_ARM_HYP_DEBUG_UART_ADDR;

	if (ops->create_private_mapping(base, PAGE_SIZE,
					  PAGE_HYP_DEVICE,
					  &arm64_kvm_hyp_debug_uart_addr))
		return -1;

	return 0;
}

int pkvm_driver_hyp_init(const struct pkvm_module_ops *a_ops)
{
	int ret;

	ops = a_ops;;
	dops = ops->get_vendor_ops(PKVM_DBG_TOOLS);
	if (!dops)
		return -ENOTSUPP;
	ret = create_hyp_debug_uart_mapping();
	if (ret)
		return ret;

	hyp_print("Pkvm debugger initiated\n");
	dops->register_hyp_print(&hyp_print);
	debug_dump_csrs();
	return 0;
}

void pkvm_driver_hyp_hvc(struct user_pt_regs *regs)
{
	u64 ret = hyp_dbg(regs->regs[1], regs->regs[2], regs->regs[3],
			  regs->regs[4], regs->regs[5]);

	regs->regs[0] = SMCCC_RET_SUCCESS;
	regs->regs[1] = ret;
}

/* Android kernel has following definition:
 * 	#ifndef CONFIG_KMSAN
 * 	#define memset(p, c, s) __fortify_memset_chk(p, c, s,s\
 *               __struct_size(p), __member_size(p))
 * 	#endif
 * on the file:
 * 	include/linux/fortify-string.h
 *
 * so the line:
 * 	return ops->memset(str, c, n)
 * does not work with it.
 *
 * #undef memset (and #undef memcpy) solves the problem.
 */
#undef memset
void *memset_el2(void *str, int c, size_t n)
{
	return ops->memset(str, c, n);
}
void *memset(void *str, int c, size_t n)
{
	return ops->memset(str, c, n);
}
#undef memcpy
void *memcpy_el2(void *dst, void *src, size_t n)
{
	return ops->memcpy(dst, src, n);
}

