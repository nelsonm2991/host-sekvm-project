#include "hypsec.h"

/*
 * MemoryOps
 */

void __hyp_text __clear_vm_range(u32 vmid, u64 start, u64 size)
{
	u64 pfn = start >> PAGE_SHIFT;
	u64 num = size / PAGE_SIZE;
	while (num > 0UL)  {
		clear_vm_page(vmid, pfn);
		pfn += 1UL;
		num -= 1UL;
	}
}

void __hyp_text __clear_vm_stage2_range(u32 vmid, u64 size)
{
	u32 poweron = get_vm_poweron(vmid);
	if (size == KVM_PHYS_SIZE && poweron == 0U) {
		u32 n = get_mem_region_cnt(), i = 0U;
		while (i < n) {
			u64 base = get_mem_region_base(i);
			u64 sz = get_mem_region_size(i);
			u64 flags = get_mem_region_flag(i);
			if ((flags & MEMBLOCK_NOMAP) == 0)
				__clear_vm_range(vmid, base, sz);
			i++;
		}
	}
}

void __hyp_text clear_vm_range(u32 vmid, u64 pfn, u64 num)
{
	while (num > 0UL)
	{
		clear_vm_page(vmid, pfn);
		pfn += 1UL;
		num -= 1UL;
	}
}

/*
void __hyp_text __clear_vm_stage2_range(u32 vmid, u64 start, u64 size)
{
	u32 poweron = get_vm_poweron(vmid);
	if (size == KVM_PHYS_SIZE && poweron == 0U) {
		u32 i = 0U;
		u64 size = get_phys_mem_size();
		u64 num = size / PAGE_SIZE;
		u64 pfn = get_phys_mem_start_pfn();
		while (i < num) {
			clear_vm_page(vmid, pfn);
			pfn += 1;
			i += 1;
		}
	}
}
*/

#define PMD_PAGE_NUM	512
void __hyp_text prot_and_map_vm_s2pt(u32 vmid, u64 addr, u64 pte, u32 level)
{
	u64 pfn, gfn, num;
	u64 target_addr = phys_page(pte);
	pfn = target_addr / PAGE_SIZE;
	gfn = addr / PAGE_SIZE;

	if (pte == 0)
		return;

	if (level == 2U) {
		/* gfn is aligned to 2MB size */
		// print_string("\rLevel 2 in prot_and_map_vm_s2pt, see below for PTRS_PER_PMD\n");
		// printhex_ul(PTRS_PER_PMD);
		gfn = gfn / PTRS_PER_PMD * PTRS_PER_PMD;
		// print_string("\rPMD_PAGE_NUM output: \n");
		num = PMD_PAGE_NUM;
		// printhex_ul(num);
		// print_string("\r\n");
		// print_string("\rPAGE_SIZE: \n");
		// printhex_ul(PAGE_SIZE);
		// print_string("\raddr: \n");
		// printhex_ul(addr);
		// print_string("\r\n");
		// print_string("\rBreakdown of values being considered (target_addr, pfn, gfn):\n");
		// printhex_ul(target_addr);
		// printhex_ul(pfn);
		// printhex_ul(gfn);

		// Print out conclusions:
		// PTRS_PER_PMD = 0x200
		// PMD_PAGE_NUM = 0x200
		// PAGE_SIZE = 0x1000
		// pfn = (target_addr >> 12 bits)
		// gfn = (addr >> 12 bits)
		//


		//ret = assign_pfn_to_vm(vmid, gfn, pfn, PMD_PAGE_NUM);
		//if (ret == 1) {
		//	print_string("\rsplitting pmd to pte\n");
		//	new_pte += (agfn - gfn) * PAGE_SIZE;
		//	map_pfn_vm(vmid, fault_addr, new_pte, 3U);
		//}
		//else if (ret == 0) {
		//if (ret == 0) {
			//map_pfn_vm(vmid, fault_addr, new_pte, 2U);
		//}
	}
	else {
		/* agfn is aligned to 4KB size */
		//ret = assign_pfn_to_vm(vmid, agfn, pfn, 1UL);
		//if (ret == 0) {
		//	map_pfn_vm(vmid, fault_addr, new_pte, 3U);
		//}
		num = 1UL;
		level = 3U;
	}

	// Insight: num is the number of actual pages per VM IPA pages
	// Since the VM in this case is seeing 2MB pages but the actual
	// page_size is 4KB, we have to coalese the pages to some mapping
	// Thus we need to perform 512 mappings per 2MB page
	//
	// We do this so the 2MB is still contiguous
	while (num > 0UL) {
		assign_pfn_to_vm(vmid, gfn, pfn);
		gfn += 1UL;
		pfn += 1UL;
		num -= 1UL;
	}

	// for each actual page:
	//    assign_pfn_to_vm
	// map_pfn_vm

	map_pfn_vm(vmid, addr, pte, level);
}

void __hyp_text v_grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
    u64 len = (size & (PAGE_SIZE - 1) ? 1 : 0);
    if (size >> PAGE_SHIFT)
	len += size >> PAGE_SHIFT;

    while (len > 0UL)
    {
        u64 pte = walk_s2pt(vmid, addr);
	u32 level = 0;
        u64 pte_pa = phys_page(pte);
	if (pte & PMD_MARK)
		level = 2;
	else if (pte & PTE_MARK)
		level = 3;

        if (pte_pa != 0UL)
        {
            u64 pfn = pte_pa / PAGE_SIZE;
            if (level == 2U) {
                pfn += (addr & (PMD_SIZE - 1)) / PAGE_SIZE;
            }
            grant_vm_page(vmid, pfn);
        }
        addr += PAGE_SIZE;
        len -= 1UL;
    }
}

void __hyp_text v_revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
    u64 len = (size & (PAGE_SIZE - 1) ? 1 : 0);
    if (size >> PAGE_SHIFT)
	len += size >> PAGE_SHIFT;

    while (len > 0UL)
    {
        u64 pte = walk_s2pt(vmid, addr);
	u32 level = 0;
        u64 pte_pa = phys_page(pte);
	if (pte & PMD_MARK)
		level = 2;
	else if (pte & PTE_MARK)
		level = 3;
        if (pte_pa != 0UL)
        {
            u64 pfn = pte_pa / PAGE_SIZE;
            if (level == 2U) {
                pfn += (addr & (PMD_SIZE - 1)) / PAGE_SIZE;
            }
            revoke_vm_page(vmid, pfn);
        }
        addr += PAGE_SIZE;
        len -= 1UL;
    }
}
