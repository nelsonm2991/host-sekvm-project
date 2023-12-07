#include "hypsec.h"

/*
 * PTAlloc
 */

u64 __hyp_text alloc_s2pt_pgd(u32 vmid)
{
	// Some confusion:
	// get_pgd_next seems to skip ahead somewhat and actually grab from the pud pages?
	// so are these pud pages that pgd can then point to?
	u64 next = get_pgd_next(vmid);
	u64 end = pgd_pool_end(vmid);

	// The VM should call this once.
	if (vmid != COREVISOR && vmid != HOSTVISOR) {
		print_string("\ralloc_s2pt_pgd called for a VM\n");
		printhex_ul((u64)vmid);
		print_string("\rVMID ^\n");
	}

	if (next + PAGE_SIZE <= end) {
		set_pgd_next(vmid, 1);
	}
	else {
	        print_string("\rwe used all s2 pgd pages\n");
		printhex_ul(vmid);
		v_panic();
	}

	return next;
}

u64 __hyp_text alloc_s2pt_pud(u32 vmid)
{
	u64 next = get_pud_next(vmid);
	u64 end = pud_pool_end(vmid);

	if (next + PAGE_SIZE <= end) {
		set_pud_next(vmid, 1);
	}
	else {
	        print_string("\rwe used all s2 pud pages\n");
		printhex_ul(vmid);
		v_panic();
	}

	return next;
}

u64 __hyp_text alloc_s2pt_pmd(u32 vmid)
{
	u64 next = get_pmd_next(vmid);
	u64 end = pmd_pool_end(vmid);

	// next is the first address in the page we are using. Once the first address
	// hits the end of the region, we know we are out of pages
	if (next + PAGE_SIZE <= end) {
		set_pmd_next(vmid, 1);
	}
	else {
	        print_string("\rwe used all s2 pmd pages\n");
		printhex_ul(vmid);
		v_panic();
	}

	// next must be the correct absolute address here, so make sure
	// get_pmd_next and pmd_pool_end account for this.
	return next;
}

/*
u64 __hyp_text alloc_smmu_pgd_page(void)
{
	u64 next = get_smmu_pgd_next();
	u64 end = smmu_pgd_end();

	//print_string("\ralloc smmu pgd page\n");
	//printhex_ul(next);
	if (next + PAGE_SIZE <= end) {
		set_smmu_pgd_next(1);
	}
	else {
	        print_string("\rwe used all smmu pgd pages\n");
		v_panic();
	}
	return next;
}

u64 __hyp_text alloc_smmu_pmd_page(void)
{
	u64 next = get_smmu_pmd_next();
	u64 end = smmu_pmd_end();

	//print_string("\ralloc smmu pmd page\n");
	//printhex_ul(next);
	if (next + PAGE_SIZE <= end) {
		set_smmu_pmd_next(1);
	}
	else {
	        print_string("\rwe used all smmu pmd pages\n");
		v_panic();
	}
	return next;
}
*/
