/* SPDX-License-Identifier: * GPL-2.0-only */

#ifndef __MOD_ARM64_KVM_HYP_HYP_DEBUG_H__
#define __MOD_ARM64_KVM_HYP_HYP_DEBUG_H__
#include "config.h"
#include <asm/kvm_host.h>
#include "hyp_calls.h"
#include <nvhe/module_dbg_tools.h>

extern struct shared_buffer *dbg_buffer;
extern struct dbg_tool_ops *dops;
extern const struct pkvm_module_ops *ops;

int hyp_vsnprintf(char *str, size_t size, const char *format, va_list ap);
int hyp_snprint(char *s, size_t slen, const char *format, ...);
int hyp_dbg_print(const char *fmt, ...);
int hyp_print(const char *fmt, ...);
u64 hyp_dbg(u64 cmd, u64 param1, u64 param2, u64 param3, u64 param4);
int update_rb(struct shared_buffer *rb, u8 *buf, int cnt);
void *memcpy_el2(void *dst, void *src, size_t n);
void *memset_el2(void *str, int c, size_t n);

/**
 * Print and count the amount of guest/hypervisor ram visible to the host
 *
 * @param handle guest to query. if 0 do query for hypervisor
 * @param size the size of query
 * @param lock make the pages read only for the guest
   @param cont, set to 1 if printing continues after output buffer is full
 * @return int count of shared pages,  -errno
 */
int count_shared(u32 id, u64 size, bool lock, bool cont);


/**
 * Initialise shared RAM for hyp-debuggergit
 *
 *  @param pfn the start page of shared memory
 *  @param size the size of the sharedf memory
   @param cont, set to 1 if printing continues after output buffer is full
 *  @return int count of shared pages or -errno
 */
u64 print_mappings(u32 id, u64 addr, u64 size, bool cont);
#endif
