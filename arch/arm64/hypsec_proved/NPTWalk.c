#include "hypsec.h"

/*
 * NPTWalk
 */

void __hyp_text init_npt(u32 vmid)
{
	u64 vttbr, vttbr_pa, vmid64;

	vttbr = get_pt_vttbr(vmid);
	if (vttbr == 0) {
		vttbr_pa = pool_start(vmid);
		vmid64 = ((u64)(vmid & 255U) << VTTBR_VMID_SHIFT);
		vttbr = vttbr_pa | vmid64;
		set_pt_vttbr(vmid, vttbr);
	}
}

u32 __hyp_text get_npt_level(u32 vmid, u64 addr)
{
	u64 vttbr, pgd, pud, pmd;u32 ret;

	vttbr = get_pt_vttbr(vmid);
	pgd = walk_pgd(vmid, vttbr, addr, 0U);
	pud = walk_pud(vmid, pgd, addr, 0U);
	pmd = walk_pmd(vmid, pud, addr, 0U);

    	if (v_pmd_table(pmd) == PMD_TYPE_TABLE) {
		u64 pte = walk_pte(vmid, pmd, addr);
		if (phys_page(pte) == 0UL)
			ret = 0U;
		else
			ret = 3U;
	}
	else {
		if (phys_page(pmd) == 0UL)
			ret = 0U;
		else
			ret = 2U;
	}

	return ret;
}

u64 __hyp_text walk_npt(u32 vmid, u64 addr)
{
	u64 vttbr, pgd, pud, pmd, ret, pte;

	vttbr = get_pt_vttbr(vmid);
	pgd = walk_pgd(vmid, vttbr, addr, 0U);
	pud = walk_pud(vmid, pgd, addr, 0U);
	pmd = walk_pmd(vmid, pud, addr, 0U);

	if (v_pmd_table(pmd) == PMD_TYPE_TABLE) {
        	pte = walk_pte(vmid, pmd, addr);
        	ret = pte;
    	}
    	else {
        	ret = pmd;
	}

	return ret;
}

void __hyp_text set_npt(u32 vmid, u64 addr, u32 level, u64 pte)
{
	u64 vttbr, pgd, pud, pmd;

	vttbr = get_pt_vttbr(vmid);	
	pgd = walk_pgd(vmid, vttbr, addr, 1U);
	pud = walk_pud(vmid, pgd, addr, 1U);

	if (level == 2U)
	{
		pmd = walk_pmd(vmid, pud, addr, 0U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE && phys_page(addr)) {
			print_string("\rset existing npt: pmd\n");
			v_panic();
		} else
	   		v_set_pmd(vmid, pud, addr, pte);
	}
	else
	{
		pmd = walk_pmd(vmid, pud, addr, 1U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
			v_set_pte(vmid, pmd, addr, pte);
		else {
			print_string("\rset existing npt: pte\n");
			v_panic();
		}
	}
}

//3 Level PT walk in SMMU
void __hyp_text init_smmu_pt(u32 cbndx, u32 num)
{
	smmu_pt_clear(cbndx, num);
}

u64 __hyp_text walk_smmu_pt(u32 cbndx, u32 num, u64 addr)
{
	u64 ttbr, pgd, pmd, ret;

	ttbr = get_smmu_cfg_hw_ttbr(cbndx, num);
	pgd = walk_smmu_pgd(ttbr, addr, 0U);
	pmd = walk_smmu_pmd(pgd, addr, 0U);
	ret = walk_smmu_pte(pmd, addr);
	return ret;
}

void __hyp_text set_smmu_pt(u32 cbndx, u32 num, u64 addr, u64 pte)
{
	u64 ttbr, pgd, pmd;

	ttbr = get_smmu_cfg_hw_ttbr(cbndx, num);
	if (ttbr == 0UL) {
	    print_string("\rset smmu pt: vttbr = 0\n");
	    v_panic();
	} else {
		pgd = walk_smmu_pgd(ttbr, addr, 1U);
		pmd = walk_smmu_pmd(pgd, addr, 1U);
		set_smmu_pte(pmd, addr, pte);
	}
}
