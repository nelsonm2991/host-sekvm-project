#include "hypsec.h"

/*
 * BootOps
 */

u32 __hyp_text vm_is_inc_exe(u32 vmid)
{
    u32 inc_exe;
    acquire_lock_vm(vmid);
    inc_exe = get_vm_inc_exe(vmid);
    release_lock_vm(vmid);
    return inc_exe;
}

void __hyp_text boot_from_inc_exe(u32 vmid)
{
    acquire_lock_vm(vmid);
    set_vm_inc_exe(vmid, 1U);
    release_lock_vm(vmid);
}

void __hyp_text set_vcpu_active(u32 vmid, u32 vcpuid)
{
    u32 vm_state, vcpu_state;
    acquire_lock_vm(vmid);
    vm_state = get_vm_state(vmid);
    vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vm_state == VERIFIED && vcpu_state == READY) {
        set_vcpu_state(vmid, vcpuid, ACTIVE);
    }
	else {
		print_string("\rset vcpu active\n");
		v_panic();
	}
    release_lock_vm(vmid);
}

void __hyp_text set_vcpu_inactive(u32 vmid, u32 vcpuid)
{
    u32 vcpu_state;
    acquire_lock_vm(vmid);
    vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vcpu_state == ACTIVE) {
        set_vcpu_state(vmid, vcpuid, READY);
    }
    else {
	print_string("\rset vcpu inactive\n");
	v_panic();
    }
    release_lock_vm(vmid);
}

u64 __hyp_text v_search_load_info(u32 vmid, u64 addr)
{
    u32 load_info_cnt, load_idx = -1;
    u64 ret;
    acquire_lock_vm(vmid);
    load_info_cnt = get_vm_next_load_idx(vmid);
    load_idx = 0U;
    ret = 0UL;
    while (load_idx < load_info_cnt)
    {
        u64 base = get_vm_load_addr(vmid, load_idx);
        u64 size = get_vm_load_size(vmid, load_idx);
        u64 remap_addr = get_vm_remap_addr(vmid, load_idx);
        if (addr >= base && addr < base + size)
        {
            ret = (addr - base) + remap_addr;
        }
        load_idx += 1U;
    }
    release_lock_vm(vmid);
    return ret;
}

u32 __hyp_text register_vcpu(u32 vmid, u32 vcpuid)
{
    u32 vm_state, vcpu_state;
    u64 vcpu;
    acquire_lock_vm(vmid);
    vm_state = get_vm_state(vmid);
    vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vm_state == READY || vcpu_state == UNUSED) {
	vcpu = get_shared_vcpu(vmid, vcpuid);
        set_vm_vcpu(vmid, vcpuid, vcpu);
	set_vcpu_state(vmid, vcpuid, READY);
        set_shadow_ctxt(vmid, vcpuid, V_DIRTY, INVALID64);
    }
    else {
	print_string("\rregister vcpu\n");
	v_panic();
    }
    release_lock_vm(vmid);
    return 0U;
}

// Takes in the addresses of 8 x 1M regions used for the stage-2 page table
// of the guest VM. We should probably pass the addresses of an array or a
// struct, but it seems like all existing hypercalls just use primitve types
// so let's just follow that for now.
u32 __hyp_text register_kvm(u64 pageZero, u64 pageOne, u64 pageTwo, u64 pageThree,
                    u64 pageFour, u64 pageFive, u64 pageSix, u64 pageSeven)
{
    // The first pmd_used_pages_vm iterator starts 17 pages inside of the first 1MB page.
    // The pgd iterator starts 1 page inside of this first 1 MB page. We must make sure
    // the VTTBR for the VM is set to the address of this first page
    // The remaining iterators all point to the tops of the corresponding pages they receive
    u32 vmid = gen_vmid();
    u32 state;
    u64 kvm, index, addr, end, owner, page_cnt = 0;
    u32 pte_iter;
    struct el2_data *el2_data;
    int i;

    // Place the addresses in an array.
    u64 page_starts[8];
    page_starts[0] = pageZero;
    page_starts[1] = pageOne;
    page_starts[2] = pageTwo;
    page_starts[3] = pageThree;
    page_starts[4] = pageFour;
    page_starts[5] = pageFive;
    page_starts[6] = pageSix;
    page_starts[7] = pageSeven;

    /*** START: Preprocess the 8*1M regions. ***/

    for (i = 0; i < 8; ++i) {
        addr = page_starts[i];
	    end = page_starts[i] + SZ_1M;
        print_string("register_kvm(): Pre-processing memory region:\n");
        printhex_ul(i);
        print_string("Base address for this region is:\n");
        printhex_ul(addr);
        print_string("End address for this region is:\n");
        printhex_ul(end);

        if (addr == 0) {
            // Hostvisor's alloc_pages() failed.
            __hyp_panic();
        }

        // Change the ownership of these pages to the corevisor.
        do {
	        index = get_s2_page_index(addr);
            owner = get_s2_page_vmid(index);

            if (owner != HOSTVISOR) {
                // The hostvisor shouldn't be giving memory that belongs to the
                // corevisor or to a VM.
                __hyp_panic();
            }

	        set_s2_page_vmid(index, COREVISOR);
	        addr += PAGE_SIZE;
            ++page_cnt;
	    } while (addr < end);

        // TODO: Why doesn't memset work?
        // memset((char*)__el2_va(page_starts[i]), 0, SZ_1M);
    }

    print_string("register_kvm(): Assigned the following number of pages to corevisor:\n");
    printhex_ul(page_cnt);

    /*** END: Preprocess the 8*1M regions. ***/

    /*** START: Build VM's s2 page table using these regions. ***/

    acquire_lock_vm(vmid);

    // change this so page_pool_start is set to physical address at top of very first 1MB region
    // passed to this function
    el2_data = get_el2_data_start();
    el2_data->vm_info[vmid].page_pool_start = page_starts[0];

    // https://github.com/columbia/osdi23-paper114-sekvm/blob/be2827dc1b45de10afab2462c177b902536bf5c6/arch/arm64/hypsec_proved/NPTWalk.c#L13
    // The VTTBR for the VM is set to the pool_start for the vmid.
    //                 vttbr_pa = pool_start(vmid);
    // make sure the page_pool_start from above is set correctly BEFORE the init_s2pt call
    // after this conditional as that is where VTTBR gets set
    // TODO: set the VTTBR here

    // Split iterator initialization for VMs only
    if (vmid != HOSTVISOR && vmid != COREVISOR) {
        // Initialize the pud_used_pages_vm, pmd, and pte arrays
        print_string("\rregister kvm: populating _vm iterators\n");
        el2_data->vm_info[vmid].pud_used_pages_vm[0] = 0;
        el2_data->vm_info[vmid].pmd_used_pages_vm[0] = 0;
        el2_data->vm_info[vmid].pmd_used_pages_vm[1] = 0;
        for (pte_iter = 0; pte_iter < PTE_USED_ITER_COUNT; pte_iter++) {
            el2_data->vm_info[vmid].pte_used_pages_vm[pte_iter] = 0;
        }

        // Initialize these to tops of pages, except pmd[1] which is in the middle of the first
        // page where the first 17 pages are for the pgd
        el2_data->vm_info[vmid].pud_pool_starts[0] = page_starts[0] + PGD_BASE;
        el2_data->vm_info[vmid].pmd_pool_starts[0] = page_starts[0] + PUD_BASE;
        // the below should point to top of a 1MB contig region
        el2_data->vm_info[vmid].pmd_pool_starts[1] = page_starts[1];
        for (pte_iter = 0; pte_iter < PTE_USED_ITER_COUNT; pte_iter++) {
            if (pte_iter > 5) {
                // We only allocated enough memory for 6 extra 1M pages.
                __hyp_panic();
            }
            el2_data->vm_info[vmid].pte_pool_starts[pte_iter] = page_starts[2 + pte_iter];
        }

        // End calculations for use in the iterator functions
        // calculating "ends" for each on:
        // make sure pud_pool_starts[0] end resolves to pud_pool_starts[0] + PUD_BASE
        // make sure pmd_pool_starts[0] end resolves to be pmd_pool_starts[0] + (SZ_2M / 2) - PUD_BASE
        // make sure pmd_pool_starts[1] end resolves to pmd_pool_starts[1] + (SZ_2M / 2)
        // and make sure pte_pool_starts[i] resolts to pte_pool_starts[i] + (SZ_2M / 2)

        // Initialize iterator we are currently using for each level
        // pud_pool implicitly is always the same and only has 1 iterator, so no work
        // for it there. The other pools have 2 and 6 respectively that must be set
        el2_data->vm_info[vmid].pud_pool_index = 0;
        el2_data->vm_info[vmid].pmd_pool_index = 0;
        el2_data->vm_info[vmid].pte_pool_index = 0;
    }

    /*** END: Build VM's s2 page table using these regions. ***/

    state = get_vm_state(vmid);
    if (state == UNUSED) {
        set_vm_inc_exe(vmid, 0U);
        kvm = get_shared_kvm(vmid);
        set_vm_kvm(vmid, kvm);
        init_s2pt(vmid);
	set_vm_public_key(vmid);
        set_vm_state(vmid, READY);
    }
    else {
	print_string("\rregister kvm\n");
	v_panic();
    }
    release_lock_vm(vmid);
    return vmid;
}

u32 __hyp_text set_boot_info(u32 vmid, u64 load_addr, u64 size)
{
    u32 state, load_idx = -1;
    u64 page_count, remap_addr;
    acquire_lock_vm(vmid);
    state = get_vm_state(vmid);
    if (state == READY)
    {
        load_idx = get_vm_next_load_idx(vmid);
        if (load_idx < MAX_LOAD_INFO_NUM)
        {
            set_vm_next_load_idx(vmid, load_idx + 1U);
            page_count = (size + PAGE_SIZE - 1UL) / PAGE_SIZE;
            remap_addr = alloc_remap_addr(page_count);
            set_vm_load_addr(vmid, load_idx, load_addr);
            set_vm_load_size(vmid, load_idx, size);
            set_vm_remap_addr(vmid, load_idx, remap_addr);
            set_vm_mapped_pages(vmid, load_idx, 0U);
	        set_vm_load_signature(vmid, load_idx);
        }
    }
    release_lock_vm(vmid);
    return load_idx;
}

void __hyp_text remap_vm_image(u32 vmid, u64 pfn, u32 load_idx)
{
    u32 state, load_info_cnt;
    u64 size, page_count, mapped, remap_addr, target;
    acquire_lock_vm(vmid);
    state = get_vm_state(vmid);
    if (state == READY)
    {
        load_info_cnt = get_vm_next_load_idx(vmid);
        if (load_idx < load_info_cnt)
        {
            size = get_vm_load_size(vmid, load_idx);
            page_count = (size + PAGE_SIZE - 1UL) / PAGE_SIZE;
            mapped = get_vm_mapped_pages(vmid, load_idx);
            remap_addr = get_vm_remap_addr(vmid, load_idx);
            target = remap_addr + mapped * PAGE_SIZE;
            if (mapped < page_count)
            {
                mmap_s2pt(COREVISOR, target, 3UL, pfn * PAGE_SIZE + 0x40000000000753LL);
                set_vm_mapped_pages(vmid, load_idx, mapped + 1UL);
            }
        }
    }
    else {
	print_string("\remap vm image\n");
        v_panic();
    }
    release_lock_vm(vmid);
}

void __hyp_text verify_and_load_images(u32 vmid)
{
    u32 state, load_info_cnt, load_idx, valid;
    u64 load_addr, remap_addr, mapped;
    acquire_lock_vm(vmid);
    state = get_vm_state(vmid);
    if (state == READY)
    {
        load_info_cnt = get_vm_next_load_idx(vmid);
        load_idx = 0U;
        while (load_idx < load_info_cnt)
        {
            load_addr = get_vm_load_addr(vmid, load_idx);
            remap_addr = get_vm_remap_addr(vmid, load_idx);
            mapped = get_vm_mapped_pages(vmid, load_idx);
	    unmap_and_load_vm_image(vmid, load_addr, remap_addr, mapped);
            valid = verify_image(vmid, load_idx);
            if (valid == 0U) {
		v_panic();
            }
            load_idx += 1U;
        }
        set_vm_state(vmid, VERIFIED);
    }
    else
	v_panic();
    release_lock_vm(vmid);
}

//NEW SMMU CODE
/////////////////////////////////////////////////////////////////////////////
void __hyp_text alloc_smmu(u32 vmid, u32 cbndx, u32 index)
{
	u32 state;

	acquire_lock_vm(vmid);
	if (HOSTVISOR < vmid && vmid < COREVISOR)
	{
		state = get_vm_state(vmid);
		if (state == VERIFIED)
		{
			print_string("\rpanic: alloc_smmu\n");
			v_panic();
		}
	}
	//FIXME: WHERE IS THE FOLLOWING FUNCTION?
	//init_smmu_spt(cbndx, index);
	release_lock_vm(vmid);
}

void __hyp_text assign_smmu(u32 vmid, u32 pfn, u32 gfn)
{
	u32 state;

	acquire_lock_vm(vmid);
	if (HOSTVISOR < vmid && vmid < COREVISOR)
	{
		state = get_vm_state(vmid);
		if (state == VERIFIED)
		{
			print_string("\rpanic: assign_smmu\n");
			v_panic();
		}
		assign_pfn_to_smmu(vmid, gfn, pfn);
	}
	release_lock_vm(vmid);
}

void __hyp_text map_smmu(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte)
{
	u32 state;
	acquire_lock_vm(vmid);
	if (HOSTVISOR < vmid && vmid < COREVISOR)
	{
		state = get_vm_state(vmid);
		if (state == VERIFIED)
		{
			print_string("\rpanic: map_smmu\n");
			v_panic();
		}
	}
	update_smmu_page(vmid, cbndx, index, iova, pte);
	release_lock_vm(vmid);
}

void __hyp_text clear_smmu(u32 vmid, u32 cbndx, u32 index, u64 iova)
{
	acquire_lock_vm(vmid);
	if (HOSTVISOR < vmid && vmid < COREVISOR)
	{
		/*
		state = get_vm_state(vmid);
		if (state == VERIFIED)
		{
			print_string("\rpanic: clear_smmu\n");
			v_panic();
		}
		*/
	}
	unmap_smmu_page(cbndx, index, iova);
	release_lock_vm(vmid);
}

void __hyp_text map_io(u32 vmid, u64 gpa, u64 pa)
{
	u32 state;

	acquire_lock_vm(vmid);
	state = get_vm_state(vmid);
	//if (state == READY)
	//{
		__kvm_phys_addr_ioremap(vmid, gpa, pa);
	//}
	//else
	//{
	//	print_string("\rpanic: map_io\n");
	//	v_panic();
	//}
	release_lock_vm(vmid);
}
