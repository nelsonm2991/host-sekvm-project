#include "hypsec.h"

/*
 * MemManager
 */

extern void reject_invalid_mem_access(phys_addr_t addr);

void __hyp_text map_page_host(u64 addr)
{
	u64 pfn = addr / PAGE_SIZE;
	u64 new_pte = 0UL, perm;
	u32 owner, count;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == INVALID_MEM) {
		perm = 0x40000000000747LL;
		perm |= S2_RDWR;
		new_pte = (addr & PAGE_MASK) + perm;
		mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
	} else {
		if (owner == HOSTVISOR || count > 0U) {
			perm = 0xfff;
			new_pte = pfn * PAGE_SIZE + perm;
			mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
		} else {
			//reject_invalid_mem_access(addr);
			perm = 0xfff;
			new_pte = pfn * PAGE_SIZE + perm;
			mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
			print_string("\rfaults on host\n");
			printhex_ul(addr);
			v_panic();
		}
	}
	release_lock_s2page();
}

void __hyp_text clear_vm_page(u32 vmid, u64 pfn)
{
    u32 owner;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    if (owner == vmid) {
        set_pfn_owner(pfn, HOSTVISOR);
        set_pfn_count(pfn, 0U);
        set_pfn_map(pfn, 0UL);
	clear_phys_page(pfn);
    }
    release_lock_s2page();
}

void __hyp_text assign_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn)
{
	u64 map;
	u32 owner, count;

	acquire_lock_s2page();
	//ret = check_pfn_to_vm(vmid, gfn, pfn, pgnum);

	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == HOSTVISOR) {
		if (count == 0U) {
			set_pfn_owner(pfn, vmid);
			clear_pfn_host(pfn);
			set_pfn_map(pfn, gfn);	
		} else {
			//pfn is mapped to a hostvisor SMMU table
			print_string("\rassign pfn used by host smmu device\n");
			v_panic();
		}
	} else if (owner == vmid) {
		map = get_pfn_map(pfn);
		/* the page was mapped to another gfn already! */
		// if gfn == map, it means someone in my VM has mapped it
		if (gfn == map) {
 			if (count == INVALID_MEM) {
				set_pfn_count(pfn, 0U);
			}
		} else {
			print_string("\rmap != gfn || count != INVALID_MEM\n");
			v_panic();
		}
	}

	release_lock_s2page();
}

/*
void __hyp_text assign_pfn_to_smmu(u32 vmid, u64 gfn, u64 pfn)
{
    u32 owner, count;
    u64 map;

    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    count = get_pfn_count(pfn);
    map = get_pfn_map(pfn);

    if (owner == HOSTVISOR) {
	if (vmid == HOSTVISOR) {
	    //print_string("\rsmmu: map to host\n");
	    //printhex_ul(pfn);
	    set_pfn_count(pfn, count + 1U);
	} else {
	    if (count == 0) {
		set_pfn_to_vm(vmid, gfn, pfn, 1UL);
		set_pfn_count(pfn, INVALID_MEM);
	    }
	    else {
                print_string("\rpanic in assign_pfn_to_smmu: count is invalid\n");
		print_string("\rpfn\n");
                printhex_ul(pfn);
		print_string("\rcount\n");
		printhex_ul(count);
		v_panic();
	    }
	}
    } else if (owner == vmid) {
	if (gfn != map) {
        	print_string("\rpanic in assign_pfn_to_smmu: owner != vmid\n");
		v_panic();
	}
    } else if (owner == COREVISOR) {
	if (map == 0) {
		print_string("\rpanic in assign_pfn_to_smmu: owner = core\n");
		v_panic();
	}
    }
    release_lock_s2page();
}
*/

extern void t_mmap_s2pt(phys_addr_t addr, u64 desc, int level, u32 vmid);
void __hyp_text map_pfn_vm(u32 vmid, u64 addr, u64 pte, u32 level)
{
	u64 paddr = phys_page(pte);

	/* We give the VM RWX permission now. */
	u64 perm = 0xfff;
	u64 size = PAGE_SIZE;

	if (level == 2U) {
		/* FIXME: verified code has pte = paddr | perm; */
		pte = paddr + perm;
		pte &= ~PMD_TABLE_BIT;
		size = PMD_SIZE;
	} else if (level == 3U) {
		pte = paddr + perm;
	}
	mmap_s2pt(vmid, addr, level, pte);
	isb();
	__flush_dcache_area(__el2_va(pte), size);
}


void __hyp_text __kvm_phys_addr_ioremap(u32 vmid, u64 gpa, u64 pa)
{
	u64 pte;
	u32 owner;

	pte = pa + (0x40000000000747LL | S2_RDWR);

	acquire_lock_s2page();
	owner = get_pfn_owner(pa >> PAGE_SHIFT);
	// check if pfn is truly within an I/O area
	if (owner == INVALID_MEM) 
		mmap_s2pt(vmid, gpa, 3U, pte);
	release_lock_s2page();
}

void __hyp_text grant_vm_page(u32 vmid, u64 pfn)
{
    u32 owner, count;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    count = get_pfn_count(pfn);
    if (owner == vmid && count < MAX_SHARE_COUNT) {
        set_pfn_count(pfn, count + 1U);
    }
    release_lock_s2page();
}

void __hyp_text revoke_vm_page(u32 vmid, u64 pfn)
{
    u32 owner, count;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    count = get_pfn_count(pfn);
    if (owner == vmid && count > 0U) {
        set_pfn_count(pfn, count - 1U);
        if (count == 1U) {
            clear_pfn_host(pfn);
        }
    }
    release_lock_s2page();
}

#define SMMU_HOST_OFFSET 1000000000UL
void __hyp_text assign_pfn_to_smmu(u32 vmid, u64 gfn, u64 pfn)
{
	u64 map;
	u32 owner, count;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	map = get_pfn_map(pfn);

	if (owner == HOSTVISOR) {
		if (count == 0) {
			clear_pfn_host(pfn);
			set_pfn_owner(pfn, vmid);
			set_pfn_map(pfn, gfn);
			set_pfn_count(pfn, INVALID_MEM);
		}
		else {
			print_string("\r\assign_to_smmu: host pfn count\n");
			v_panic();
		}
	}
	else if (owner != vmid)
	{
		if (owner != INVALID_MEM) { 
			print_string("\rvmid\n");
			printhex_ul(vmid);
			print_string("\rowner\n");
			printhex_ul(owner);
			print_string("\rpfn\n");
			printhex_ul(pfn);
			print_string("\rassign_to_smmu: owner unknown\n");
			v_panic();
		}
	}
	release_lock_s2page();
}

void __hyp_text update_smmu_page(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte)
{
	u64 pfn, gfn;
	u32 owner, count, map;

	acquire_lock_s2page();
	pfn = phys_page(pte) / PAGE_SIZE;
	gfn = iova / PAGE_SIZE;

	owner = get_pfn_owner(pfn);
	map = get_pfn_map(pfn);
	if (owner == HOSTVISOR) {
		count = get_pfn_count(pfn);
		//if (count < EL2_SMMU_CFG_SIZE) {
			set_pfn_count(pfn, count + 1U);
		//}
		map = pfn + SMMU_HOST_OFFSET;
	}

	if (owner == INVALID_MEM || (vmid == owner && gfn == map)) {
		map_spt(cbndx, index, iova, pte);
	}
	release_lock_s2page();
}

void __hyp_text unmap_smmu_page(u32 cbndx, u32 index, u64 iova)
{
	u64 pte, pfn; 
	u32 owner, count;

	acquire_lock_s2page();
	pte = unmap_spt(cbndx, index, iova);
	pfn = phys_page(pte) / PAGE_SIZE;
	owner = get_pfn_owner(pfn);
	if (owner == HOSTVISOR) {
		count = get_pfn_count(pfn);
		if (count > 0U) {
			set_pfn_count(pfn, count - 1U);
		}
	}
	release_lock_s2page();
}

// Gives the hostvisor 4 * 2M pages to use for the stage-2 page tables of a
// guest VM.
//
// Kernel panic if:
// - The base address is not 2M-aligned
// - The size is not equal to SZ_2M * 4
// - This hypercall has previously been called without a corresponding VM_CREATE
void __hyp_text alloc_s2_mem(u64 base, u64 size)
{
    // The kernel has identity mappings from host physical addresses to machine
    // physical addresses, so base is already a machine physical address.
    u64 pfn, pgno;
    struct el2_data *el2_data;

    print_string("\rHVC_ALLOC_S2PAGETABLE_MEM: Called with arguments:\n");
    printhex_ul((unsigned long)base);
    printhex_ul((unsigned long)size);

    // Verify that base is 2M-aligned.
    //
    // 21 least-significant-bits should be zero for 2MB alignment.
    if (base & 0x1FFFFF) {
        print_string("\rHVC_HOST_ALLOC_S2PAGETABLE_MEM: base not 2M-aligned\n");
        v_panic;
    }

    // Verify that size is correct.
    if (size != STAGE2_VM_POOL_SIZE) {
        print_string("\rHVC_HOST_ALLOC_S2PAGETABLE_MEM: size not 4 * SZ_2M\n");
        v_panic;
    }

    // Verify that el2_data->s2_pagetable hasn't been set.
    acquire_lock_core();
	el2_data = get_el2_data_start();
    if (el2_data->s2_pagetable_set) {
        release_lock_core();
        v_panic;
    }
    release_lock_core();

    // Revoke host access to the memory used for the guest VM's s2 page table.
    pfn = base / PAGE_SIZE;
    for (pgno = 0; pgno < size / PAGE_SIZE; pgno++) {
        // 0 for GFN value since this memory will stay with the corevisor.
        assign_pfn_to_vm(COREVISOR_MEM, (u64)0, pfn + pgno);
    }

    // Store information about the region.
    acquire_lock_core();
    el2_data = get_el2_data_start();
    el2_data->s2_pagetable_base = base;
    el2_data->s2_pagetable_set = true;
    release_lock_core();
    print_string("\rHVC_ALLOC_S2PAGETABLE_MEM: Done\n");
}
