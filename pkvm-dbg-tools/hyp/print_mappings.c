// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_host.h>
#include <asm/kvm_pgtable.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include "config.h"

#include "hyp_debug.h"

char *parse_attrs(char *p, uint64_t attrs, uint64_t stage);

struct dbg_map_data {
	u64 vaddr;
	u64 pte;
	u32 level;
};

struct walk_data {
	u32 stage;
	u64 size;
	u64 start_ipa;
	u64 start_phys;
	u64 attr;
	u64 host_attr;
	u32 level;
	u64 total;
};

struct stat_data {
	struct walk_data wdata;
	u32 id;
	u64 addr;
	u64 size;
};

struct stat_data sdata;

static int bit_shift(u32 level)
{
	int shift;

	switch (level) {
	case 0:
		shift = 39;
		break;
	case 1:
		shift = 30;
		break;
	case 2:
		shift = 21;
		break;
	case 3:
		shift = 12;
		break;
	default:
		shift = 0;
	}
	return shift;
}

static void print_header(void)
{
	hyp_dbg_print("Count     IPA             Phys                    page attributes\n");
	hyp_dbg_print("                                                  prv unp type\n");
}

static int print_footer(struct stat_data *data)
{
	int ret = 0;

	ret = hyp_dbg_print("tolal S2-mapped pages %lld (%lld Mbytes)\n",
				data->wdata.total>>12, data->wdata.total >> 20);
	if (ret < 0)
		return 1;
	else
		return 0;
}

static int print_databuf(struct walk_data *data)
{
	char buff[128] = "";
	char *type;

	switch (data->level) {
	case 0:
		type = "512G block ";
		break;
	case 1:
		type = "1G block   ";
		break;
	case 2:
		type = "2M block  ";
		break;
	case 3:
		type = "4K page(s)";
		break;
	default:
		type = "fail";
	}
	parse_attrs(buff, data->attr, data->stage);

	//return 0;
	return hyp_dbg_print("%3d * %s 0x%015llx -> 0x%012llx %s\n", data->size, type,
			data->start_ipa, data->start_phys, buff);
	hyp_print("%3d * %s 0x%015llx -> 0x%012llx %s\n", data->size, type,
			data->start_ipa, data->start_phys, buff);
}

static void clean_databuf(struct walk_data *data)
{
	data->size = 0;
}

static void init_databuf(struct walk_data *data, u64 addr, u32 level,
						 kvm_pte_t *ptep)
{
	data->size = 1;
	data->level = level;
	data->start_ipa = addr;
	data->attr = (*ptep) & ~KVM_PTE_ADDR_MASK;
	data->start_phys = (*ptep) & KVM_PTE_ADDR_MASK;
}

static int update_databuf(struct walk_data *data, u64 addr, u32 level,
						  kvm_pte_t *ptep)
{
	if (data->size == 0) {
		init_databuf(data, addr, level, ptep);
		return 1;
	}

	if ((data->attr == ((*ptep) & ~KVM_PTE_ADDR_MASK)) &&
	    (data->level == level)  &&
	    ((*ptep) & KVM_PTE_ADDR_MASK) ==
			    data->start_phys + data->size * (1UL << bit_shift(level))) {
		data->size++;
		return 1;
	}
	return 0;
}

static int print_mapping_walker(const struct kvm_pgtable_visit_ctx *ctx,
		enum kvm_pgtable_walk_flags visit)
{
	struct walk_data *data = ctx->arg;
	//hyp_print("walker %llx %llx\n",ctx->addr, ctx->ptep);

	if (visit == KVM_PGTABLE_WALK_LEAF) {
		if ((*ctx->ptep) & KVM_PTE_ADDR_MASK) {
			data->total += 1UL << bit_shift(ctx->level);
			if (update_databuf(data, ctx->addr, ctx->level, ctx->ptep))
				return 0;

			if (print_databuf(data) < 0)
				return 1;
			init_databuf(data, ctx->addr, ctx->level, ctx->ptep);
		} else {
			if (data->size) {
				if (print_databuf(data) < 0)
					return 1;
				clean_databuf(data);
			}
		}
	}

	if (visit == KVM_PGTABLE_WALK_TABLE_POST) {
		if (data->size) {
			if (print_databuf(data) < 0)
				return 1;
			clean_databuf(data);
		}
	}

	return 0;
}

u64 print_mappings(u32 id, u64 start, u64 size, bool cont)
{
	int ret = 0;
	struct kvm_pgtable *pgt;
	struct pkvm_hyp_vm *vm;
	u32 stage;

	struct kvm_pgtable_walker walker_s2 = {
		.cb	= print_mapping_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF |
			  KVM_PGTABLE_WALK_TABLE_POST,
		.arg	= &sdata.wdata,
	};

	if (!cont) {
		hyp_print("print_mappings id %x addr %llx, size %llx\n",
			   id, start, size);
		memset_el2(&sdata, 0, sizeof(struct stat_data));
		sdata.id = id;
	} else
		hyp_print("continue print_mappings id %x addr %llx, size %llx\n",
			  sdata.id, sdata.addr, sdata.size);

	if (sdata.id == 0) {
		stage = 1;
		pgt = dops->pkvm_pgtable;
	/* print hypervisor mappings */
	} else if (sdata.id == 1) {
		/* print the host mappings */
		stage = 2;
		pgt = dops->host_mmu->arch.mmu.pgt;
	} else {
		/* print the guest mappings */
		stage = 2;
		vm = dops->pkvm_get_hyp_vm(sdata.id);
		if (!vm) {
			hyp_print("No VM for ID %x\n", sdata.id);
			return -EINVAL;
		}
		pgt = &vm->pgt;


	}

	if (!cont) {
		if (size == 0) {
			/* prints the entire memory area */
			sdata.size = (1UL << pgt->ia_bits) - 1;
		} else
			sdata.size = size;
		sdata.addr = start;
		sdata.wdata.stage = stage;
		print_header();
	}

	if (sdata.addr + sdata.size > (1UL << pgt->ia_bits) - 1)
		sdata.size =  (1UL << pgt->ia_bits) - 1 - sdata.addr;

	hyp_print("kvm_pgtable_walk %llx, %llx %llx\n", pgt, sdata.addr, sdata.size);
	ret = dops->kvm_pgtable_walk(pgt, sdata.addr, sdata.size, &walker_s2);

	if (ret < 0)
		goto err;

	if (ret == 1) {
		hyp_print("print mappings id %x addr %llx size %llx\n", sdata.id,
				sdata.wdata.start_ipa,
				sdata.wdata.start_ipa - sdata.addr);
		sdata.size -= sdata.wdata.start_ipa - sdata.addr - 1;
		sdata.addr = sdata.wdata.start_ipa;
		return 1;
	}

	if (print_footer(&sdata) < 0) {
		hyp_print("buff full in footer\n");
		sdata.size = 0;
		return 1;
	}

err:;
	return ret;
}
