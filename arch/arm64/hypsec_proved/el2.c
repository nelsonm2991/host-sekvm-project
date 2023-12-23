#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_mmio.h>
#include <asm/kvm_emulate.h>
#include <asm/virt.h>
#include <asm/kernel-pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

#include "hypsec.h"


static void __hyp_text self_test(void)
{
    int vmid = 0, i = 0;

	print_string("\rregister kvm\n");
	// vmid = register_kvm();
	do {
		print_string("\rregister vcpu\n");
		printhex_ul((unsigned long)i);
		register_vcpu(vmid, i++);
	} while (i < 4);
}


extern int __hypsec_register_vm(struct kvm *kvm);
void __hyp_text handle_host_stage2_fault(unsigned long host_lr,
					struct s2_host_regs *host_regs)
{
	phys_addr_t addr = (read_sysreg(hpfar_el2) & HPFAR_MASK) << 8;
	set_per_cpu_host_regs((u64)host_regs);
	if (emulate_mmio(addr, read_sysreg(esr_el2)) == INVALID64)
		map_page_host(addr);
}

/*
 * Since EL2 page tables were allocated in EL2, here we need to protect
 * them by setting the ownership of the pages to HYPSEC_VMID. This allows
 * the core to reject any following accesses from the host.
 */
static void __hyp_text protect_el2_mem(void)
{
	unsigned long addr, end, index;
	struct el2_data *el2_data = get_el2_data_start();

	/* Protect stage2 data and page pool. */
	addr = el2_data->core_start;
	end =  el2_data->core_end;
	do {
		index = get_s2_page_index(addr);
		set_s2_page_vmid(index, COREVISOR);
		addr += PAGE_SIZE;
	} while (addr < end);
}

extern u32 __init_stage2_translation(void);
//TODO: Did we prove the following?
static void __hyp_text hvc_enable_s2_trans(void)
{
	struct el2_data *el2_data;

	acquire_lock_core();
	el2_data = get_el2_data_start();

	if (!el2_data->installed) {
		protect_el2_mem();
		el2_data->installed = true;
	}

	__init_stage2_translation();

	write_sysreg(el2_data->host_vttbr, vttbr_el2);
	write_sysreg(HCR_HYPSEC_HOST_NVHE_FLAGS, hcr_el2);
	__kvm_flush_vm_context();

	release_lock_core();
	//self_test();
}

void __hyp_text handle_host_hvc(struct s2_host_regs *hr)
{
	u64 ret = 0, callno = get_host_reg(hr, 0);

	set_per_cpu_host_regs((u64)hr);
	/* FIXME: we write return val to reg[31] as this will be restored to x0 */
	switch (callno) {
	case HVC_ENABLE_S2_TRANS:
		print_string("\rHVC_ENABLE_S2_TRANS\n");
		hvc_enable_s2_trans();
		break;
	case HVC_VCPU_RUN:
		ret = (u64)__kvm_vcpu_run_nvhe((u32)get_host_reg(hr, 1), (int)get_host_reg(hr, 2));
		set_host_regs(0, ret);
		break;
	case HVC_TIMER_SET_CNTVOFF:
		__kvm_timer_set_cntvoff((u32)get_host_reg(hr, 1), (u32)get_host_reg(hr, 2));
		break;
	// The following can only be called when VM terminates.
	case HVC_CLEAR_VM_S2_RANGE:
		__clear_vm_stage2_range((u32)get_host_reg(hr, 1), (u64)get_host_reg(hr, 3));
		break;
	case HVC_SET_BOOT_INFO:
		ret = set_boot_info((u32)get_host_reg(hr, 1), (unsigned long)get_host_reg(hr, 2),
			      (unsigned long)get_host_reg(hr, 3));
		set_host_regs(0, ret);
		break;
	case HVC_REMAP_VM_IMAGE:
		remap_vm_image((u32)get_host_reg(hr, 1), (unsigned long)get_host_reg(hr, 2),
				     (int)get_host_reg(hr, 3));
		break;
	case HVC_VERIFY_VM_IMAGES:
		//ret = (u64)__el2_verify_and_load_images((u32)get_host_reg(hr, 1));
		//hr->regs[31] = (u64)ret;
		verify_and_load_images((u32)get_host_reg(hr, 1));
		set_host_regs(0, 1);
		break;
	case HVC_SMMU_FREE_PGD:
		//print_string("\rfree smmu pgd\n");
		__el2_free_smmu_pgd(get_host_reg(hr, 1), get_host_reg(hr, 2));
		//print_string("\rafter free smmu pgd\n");
		break;
	case HVC_SMMU_ALLOC_PGD:
		//print_string("\ralloc smmu pgd\n");
		__el2_alloc_smmu_pgd(get_host_reg(hr, 1),  get_host_reg(hr, 2), get_host_reg(hr, 3));
		//print_string("\rafter alloc smmu pgd\n");
		break;
	case HVC_SMMU_LPAE_MAP:
		//print_string("\rsmmu mmap\n");
		v_el2_arm_lpae_map(get_host_reg(hr, 1), get_host_reg(hr, 2), get_host_reg(hr, 3), get_host_reg(hr, 4),
				   get_host_reg(hr, 5));
		//print_string("\rafter smmu mmap\n");
		break;
	case HVC_SMMU_LPAE_IOVA_TO_PHYS:
		//print_string("\rsmmu iova to phys\n");
		ret = (u64)__el2_arm_lpae_iova_to_phys(get_host_reg(hr, 1), get_host_reg(hr, 2), get_host_reg(hr, 3));
		set_host_regs(0, ret);
		//print_string("\rafter smmu iova to phys\n");
		break;
	case HVC_SMMU_CLEAR:
		//print_string("\rsmmu clear\n");
		__el2_arm_lpae_clear(get_host_reg(hr, 1), get_host_reg(hr, 2), get_host_reg(hr, 3));
		//print_string("\rafter smmu clear\n");
		break;
	/*case HVC_BOOT_FROM_SAVED_VM:
		__el2_boot_from_inc_exe((u32)get_host_reg(hr, 1));
		break;
	case HVC_ENCRYPT_BUF:
		__el2_encrypt_buf((u32)get_host_reg(hr, 1), (void*)get_host_reg(hr, 2), (uint32_t)get_host_reg(hr, 3));
		break;
	case HVC_DECRYPT_BUF:
		__el2_decrypt_buf((u32)get_host_reg(hr, 1), (void*)get_host_reg(hr, 2), (uint32_t)get_host_reg(hr, 3));
		break;
	case HVC_SAVE_CRYPT_VCPU:
		__save_encrypted_vcpu((u32)get_host_reg(hr, 1), (int)get_host_reg(hr, 2));
		break;*/
	case HVC_REGISTER_KVM:
		ret = (int)register_kvm(
            (u64)get_host_reg(hr, 1),
            (u64)get_host_reg(hr, 2),
            (u64)get_host_reg(hr, 3),
            (u64)get_host_reg(hr, 4),
            (u64)get_host_reg(hr, 5),
            (u64)get_host_reg(hr, 6),
            (u64)get_host_reg(hr, 7),
            (u64)get_host_reg(hr, 8)
        );
		set_host_regs(0, ret);
		break;
	case HVC_REGISTER_VCPU:
		ret = (int)register_vcpu((u32)get_host_reg(hr, 1), (int)get_host_reg(hr, 2));
		set_host_regs(0, ret);
		break;
    case HVC_DESTROY_KVM:
        print_string("HVC_DESTROY_KVM hypercall called\n");
        destroy_kvm((u32)get_host_reg(hr, 1));
        break;
	case HVC_PHYS_ADDR_IOREMAP:
		//FIXME: We need to call to the new map_io function...
		//__kvm_phys_addr_ioremap((u32)get_host_reg(hr, 1), get_host_reg(hr, 2), get_host_reg(hr, 3), get_host_reg(hr, 4));
		v_kvm_phys_addr_ioremap((u32)get_host_reg(hr, 1), get_host_reg(hr, 2), get_host_reg(hr, 3), get_host_reg(hr, 4));
		break;
	case HVC_GET_CORE_MEM_USAGE:
		ret = get_core_mem_usage();
		set_host_regs(0, ret);
		break;
	default:
		print_string("\rno support hvc:\n");
		printhex_ul(callno);
		break;
		//__hyp_panic();
	};
}

//added by shih-wei
struct el2_vm_info* __hyp_text vmid_to_vm_info(u32 vmid)
{
	struct el2_data *el2_data;

	el2_data = get_el2_data_start();
	if (vmid < EL2_MAX_VMID)
		return &el2_data->vm_info[vmid];
	else
		__hyp_panic();
}

struct int_vcpu* __hyp_text vcpu_id_to_int_vcpu(
			struct el2_vm_info *vm_info, int vcpu_id)
{
	if (vcpu_id < 0 || vcpu_id >= HYPSEC_MAX_VCPUS)
		return NULL;
	else
		return &vm_info->int_vcpus[vcpu_id];
}
int __hyp_text hypsec_set_vcpu_active(u32 vmid, int vcpu_id)
{
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	struct int_vcpu *int_vcpu;
	int ret = 1;

	acquire_lock_vm(vmid);
	if (get_vm_state(vmid) != VERIFIED) {
		ret = 0;
		goto out;
	}

	int_vcpu = vcpu_id_to_int_vcpu(vm_info, vcpu_id);
	if (get_vcpu_state(vmid, vcpu_id) == READY)
		set_vcpu_state(vmid, vcpu_id, ACTIVE);
	else
		ret = 0;
out:
	release_lock_vm(vmid);
	return ret;
}

struct kvm_vcpu* __hyp_text hypsec_vcpu_id_to_vcpu(u32 vmid, int vcpu_id)
{
	struct kvm_vcpu *vcpu = NULL;
	int offset;
	struct shared_data *shared_data;

	if (vcpu_id >= HYPSEC_MAX_VCPUS)
		__hyp_panic();

	shared_data = get_shared_data_start();
	offset = VCPU_IDX(vmid, vcpu_id);
	vcpu = &shared_data->vcpu_pool[offset];
	if (!vcpu)
		__hyp_panic();
	else
		return vcpu;
}

struct kvm* __hyp_text hypsec_vmid_to_kvm(u32 vmid)
{
	struct kvm *kvm = NULL;
	struct shared_data *shared_data;

	shared_data = get_shared_data_start();
	kvm = &shared_data->kvm_pool[vmid];
	if (!kvm)
		__hyp_panic();
	else
		return kvm;
}

struct shadow_vcpu_context* __hyp_text hypsec_vcpu_id_to_shadow_ctxt(
	u32 vmid, int vcpu_id)
{
	struct el2_data *el2_data = get_el2_data_start();
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	int index;

	if (vcpu_id >= HYPSEC_MAX_VCPUS)
		__hyp_panic();

	index = VCPU_IDX(vmid, vcpu_id);
	shadow_ctxt = &el2_data->shadow_vcpu_ctxt[index];
	if (!shadow_ctxt)
		__hyp_panic();
	else
		return shadow_ctxt;
}

void __hyp_text hypsec_set_vcpu_state(u32 vmid, int vcpu_id, int state)
{
	acquire_lock_vm(vmid);
	set_vcpu_state(vmid, vcpu_id, state);
	release_lock_vm(vmid);
}

void __hyp_text reset_fp_regs(u32 vmid, int vcpu_id)
{
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	struct kvm_vcpu *vcpu = vcpu;
	struct kvm_regs *kvm_regs;

	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	kvm_regs = &vcpu->arch.ctxt.gp_regs;
	el2_memcpy(&shadow_ctxt->fp_regs, &kvm_regs->fp_regs,
					sizeof(struct user_fpsimd_state));
}

/*
void __hyp_text map_vgic_to_vm(u32 vmid)
{
	struct el2_data *el2_data = get_el2_data_start();
	unsigned long vgic_cpu_gpa = 0x08010000;
	u64 pte = el2_data->vgic_cpu_base + (pgprot_val(PAGE_S2_DEVICE) | S2_RDWR);
	mmap_s2pt(vmid, vgic_cpu_gpa, 3U, pte);
	mmap_s2pt(vmid, vgic_cpu_gpa + PAGE_SIZE, 3U, pte + PAGE_SIZE);
}
*/

#define CURRENT_EL_SP_EL0_VECTOR	0x0
#define CURRENT_EL_SP_ELx_VECTOR	0x200
#define LOWER_EL_AArch64_VECTOR		0x400
#define LOWER_EL_AArch32_VECTOR		0x600

enum exception_type {
	except_type_sync	= 0,
	except_type_irq		= 0x80,
	except_type_fiq		= 0x100,
	except_type_serror	= 0x180,
};

static u64 __hyp_text stage2_get_exception_vector(u64 pstate)
{
	u64 exc_offset;

	switch (pstate & (PSR_MODE_MASK | PSR_MODE32_BIT)) {
	case PSR_MODE_EL1t:
		exc_offset = CURRENT_EL_SP_EL0_VECTOR;
		break;
	case PSR_MODE_EL1h:
		exc_offset = CURRENT_EL_SP_ELx_VECTOR;
		break;
	case PSR_MODE_EL0t:
		exc_offset = LOWER_EL_AArch64_VECTOR;
		break;
	default:
		exc_offset = LOWER_EL_AArch32_VECTOR;
	}

	return read_sysreg(vbar_el1) + exc_offset;
}

/* Currently, we do not handle lower level fault from 32bit host */
void __hyp_text stage2_inject_el1_fault(unsigned long addr)
{
	u64 pstate = read_sysreg(spsr_el2);
	u32 esr = 0, esr_el2;
	bool is_iabt = false;

	write_sysreg(read_sysreg(elr_el2), elr_el1);
	write_sysreg(stage2_get_exception_vector(pstate), elr_el2);

	write_sysreg(addr, far_el1);
	write_sysreg(PSTATE_FAULT_BITS_64, spsr_el2);
	write_sysreg(pstate, spsr_el1);

	esr_el2 = read_sysreg(esr_el2);
	if ((esr_el2 << ESR_ELx_EC_SHIFT) == ESR_ELx_EC_IABT_LOW)
		is_iabt = true;

	/* To get fancier debug info that includes LR from the guest Linux,
	 * we can intentionally comment out the EC_LOW_ABT case and always
	 * inject the CUR mode exception.
	 */
	if ((pstate & PSR_MODE_MASK) == PSR_MODE_EL0t)
		esr |= (ESR_ELx_EC_IABT_LOW << ESR_ELx_EC_SHIFT);
	else
		esr |= (ESR_ELx_EC_IABT_CUR << ESR_ELx_EC_SHIFT);

	if (!is_iabt)
		esr |= ESR_ELx_EC_DABT_LOW << ESR_ELx_EC_SHIFT;

	esr |= ESR_ELx_FSC_EXTABT;
	write_sysreg(esr, esr_el1);
}

void __hyp_text reject_invalid_mem_access(phys_addr_t addr)
{
	print_string("\rinvalid access of guest memory\n\r");
	print_string("\rpc: \n");
	printhex_ul(read_sysreg(elr_el2));
	print_string("\rpa: \n");
	printhex_ul(addr);
	stage2_inject_el1_fault(addr);
}
