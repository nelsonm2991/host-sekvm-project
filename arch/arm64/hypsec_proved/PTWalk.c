#include "hypsec.h"
#include "MmioOps.h"

/*
 * PTWalk
 */

u64 __hyp_text walk_pgd(u32 vmid, u64 vttbr, u64 addr, u32 alloc)
{
    u64 vttbr_pa = phys_page(vttbr);
    u64 ret = 0UL;
    if (vttbr_pa != 0UL) {
	u64 pgd_idx = pgd_index(addr);
        /*if (vmid != COREVISOR && vmid != HOSTVISOR) {
            print_string("\rpgd_idx: \n");
            printhex_ul(pgd_idx);
            // Confirmed that for VM's when level is 2, pgd_idx is always 0.
        }*/
        u64 pgd = pt_load(vmid, vttbr_pa + pgd_idx * 8UL);
        // With VM's, pgd_idx is always zero, so pt_load is actually called as
        // pgd = pt_load(vmid, vttbr_pa)
        // Thus vttbr holds a pointer to the location that stores a pointer to
        // the top of the pgd (aka the address of the pgd)

        // physical address of the pgd page
        u64 pgd_pa = phys_page(pgd);
        // if we never set anything, then pgd_pa should be 0. So the pointer
        // at this location isn't actually set.
        if (pgd_pa == 0UL && alloc == 1U)
        {
            // Might come back as zero, but since pgd should only be 1 page (right?)
            // since pgd_idx is always zero, this will allocate one
	    pgd_pa = alloc_s2pt_pgd(vmid);
        // this is actually "allocating" a pud page that pgd then points to?
            pgd = pgd_pa | PUD_TYPE_TABLE;
            // store the location of the pgd at the address held in vttbr.
            // This should only happen 1 time per VM assuming pgd_idx remains 0
            // for all VM addresses.
            pt_store(vmid, vttbr_pa + pgd_idx * 8UL, pgd);
        }
	ret = pgd;
    }
    // Returning the address of the top of the pgd page
    // but with a PUD_TYPE_TABLE bit set.
    return ret;
}

u64 __hyp_text walk_pud(u32 vmid, u64 pgd, u64 addr, u32 alloc)
{
    u64 pgd_pa = phys_page(pgd);
    u64 ret = 0UL;
    if (pgd_pa != 0UL) {
        u64 pud_idx = pud_idx(addr);
        u64 pud = pt_load(vmid, pgd_pa + pud_idx * 8);
        u64 pud_pa = phys_page(pud);
        if (pud_pa == 0UL && alloc == 1U)
        {
	    pud_pa = alloc_s2pt_pud(vmid);
            pud = pud_pa | PUD_TYPE_TABLE;
            pt_store(vmid, pgd_pa + pud_idx * 8UL, pud);
        }
	ret = pud;
    }
    return ret;
}

u64 __hyp_text walk_pmd(u32 vmid, u64 pgd, u64 addr, u32 alloc)
{
    u64 pgd_pa = phys_page(pgd);
    u64 ret = 0UL;
    if (pgd_pa != 0UL) {
        u64 pmd_idx = pmd_idx(addr);
        u64 pmd = pt_load(vmid, pgd_pa + pmd_idx * 8);
        u64 pmd_pa = phys_page(pmd);
        if (pmd_pa == 0UL && alloc == 1U)
        {
            /*if (vmid != COREVISOR && vmid != HOSTVISOR) {
                print_string("\rwalk_pmd: calling alloc_s2pt_pmd for a page on behalf of VM\n");
            }*/
	    pmd_pa = alloc_s2pt_pmd(vmid);
            pmd = pmd_pa | PMD_TYPE_TABLE;
            pt_store(vmid, pgd_pa + pmd_idx * 8UL, pmd);
        }
	ret = pmd;
    }
    return ret;
}

u64 __hyp_text walk_pte(u32 vmid, u64 pmd, u64 addr)
{
    u64 pmd_pa = phys_page(pmd);
    u64 ret = 0UL;
    if (pmd_pa != 0UL) {
        u64 pte_idx = pte_idx(addr);
        ret = pt_load(vmid, pmd_pa + pte_idx * 8UL);
    }
    return ret;
}

void __hyp_text v_set_pmd(u32 vmid, u64 pgd, u64 addr, u64 pmd)
{
    u64 pgd_pa = phys_page(pgd);
    u64 pmd_idx = pmd_idx(addr);
    pmd |= PMD_MARK;
    pt_store(vmid, pgd_pa + pmd_idx * 8UL, pmd);
}

void __hyp_text v_set_pte(u32 vmid, u64 pmd, u64 addr, u64 pte)
{
    	u64 pmd_pa = phys_page(pmd);
    	u64 pte_idx = pte_idx(addr);
	pte |= PTE_MARK;
    	pt_store(vmid, pmd_pa + pte_idx * 8UL, pte);
}

/*
u64 __hyp_text walk_smmu_pgd(u64 ttbr, u64 addr, u32 alloc)
{
    u64 ttbr_pa = phys_page(ttbr);
    u64 ret = 0UL;
    u64 pgd_idx;
    u64 pgd;
    u64 pgd_pa;

    if (ttbr_pa != 0UL) {
        pgd_idx = stage2_pgd_idx(addr);
        pgd = smmu_pt_load(ttbr_pa + pgd_idx * 8UL);
        pgd_pa = phys_page(pgd);
        if (pgd_pa == 0UL && alloc == 1U)
        {
            pgd_pa = alloc_smmu_pgd_page();
            pgd = pgd_pa | ARM_LPAE_PTE_TYPE_TABLE;
            smmu_pt_store(ttbr_pa + pgd_idx * 8UL, pgd);
	    //__dma_map_area(__el2_va(ttbr_pa + pgd_idx * 8UL), sizeof(u64), 1);
        }
        ret = pgd;
    }
    return ret;
}

u64 __hyp_text walk_smmu_pmd(u64 pgd, u64 addr, u32 alloc)
{
    u64 pgd_pa = phys_page(pgd);
    u64 ret = 0UL;
    if (pgd_pa != 0UL) {
        u64 pmd_idx = pmd_index(addr);
        u64 pmd = smmu_pt_load(pgd_pa + pmd_idx * 8);
        u64 pmd_pa = phys_page(pmd);
        if (pmd_pa == 0UL && alloc == 1U)
        {
            pmd_pa = alloc_smmu_pmd_page();
            pmd = pmd_pa | ARM_LPAE_PTE_TYPE_TABLE;
            smmu_pt_store(pgd_pa + pmd_idx * 8UL, pmd);
	    //__dma_map_area(__el2_va(pgd_pa + pmd_idx * 8UL), sizeof(u64), 1);
        }
        ret = pmd;
    }
    return ret;
}

u64 __hyp_text walk_smmu_pte(u64 pmd, u64 addr)
{
    u64 pmd_pa = phys_page(pmd);
    u64 ret = 0UL;
    if (pmd_pa != 0UL) {
        u64 pte_idx = pte_index(addr);
        ret = smmu_pt_load(pmd_pa + pte_idx * 8UL);
    }
    return ret;
}

void __hyp_text set_smmu_pte(u64 pmd, u64 addr, u64 pte)
{
    u64 pmd_pa = phys_page(pmd);
    u64 pte_idx = pte_index(addr);
    smmu_pt_store(pmd_pa + pte_idx * 8UL, pte);
    //__dma_map_area(__el2_va(pmd_pa + pte_idx * 8UL), sizeof(u64), 1);
}
*/
