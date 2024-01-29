#![allow(unused_imports)]
use log::info;

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::{this_cpu_mut, PERCPU_AREAS, PERCPU_VMSAS, this_cpu};
use crate::error::SvsmError;
use crate::mm::virtualrange::{VIRT_ALIGN_2M, VIRT_ALIGN_4K};
use crate::mm::{PerCPUPageMappingGuard, pagetable};
use crate::mm::{valid_phys_address, writable_phys_addr, GuestPtr};
use crate::mm::alloc::allocate_zeroed_page;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::sev::utils::{
    pvalidate, rmp_clear_guest_vmsa, rmp_grant_guest_access, rmp_revoke_guest_access,
    rmp_set_guest_vmsa, PvalidateOp, RMPFlags, SevSnpError, rmp_adjust,
};
use crate::sev::vmsa::VMSA;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::zero_mem_region;
use crate::protocols::core::{check_vmsa, core_create_vcpu_error_restore};
use crate::protocols::schal::pagetable::PageTableRef;
use crate::mm::pagetable::PageTable;
use crate::mm::virtualrange;
use crate::protocols::schal::pagetable::PTEntryFlags;

pub fn check_vmsa_ind(new: &VMSA, sev_features: u64, svme_mask: u64, vmpl_level: u64) -> bool {
    new.vmpl == vmpl_level as u8
        && new.efer & svme_mask == svme_mask
        && new.sev_features == sev_features
}


pub fn schal_nothing(params: &mut RequestParams) -> Result<(),SvsmReqError>{
    params.rcx = 1;
    params.rdx = 2;
    params.r8 = 3;
    Ok(())
}

fn copy_vmsa(v: &mut VMSA, vin: &VMSA){
    v.es = vin.es;
    v.cs = vin.cs;
    v.ss = vin.ss;
    v.ds = vin.ds;
    v.fs = vin.fs;
    v.gs = vin.gs;
    v.gdt = vin.gdt;
    v.ldt = vin.ldt;
    v.idt = vin.idt;
    v.tr = vin.tr;
    v.pl0_ssp = vin.pl0_ssp;
    v.pl1_ssp = vin.pl1_ssp;
    v.pl2_ssp = vin.pl2_ssp;
    v.pl3_ssp = vin.pl3_ssp;
    v.u_cet = vin.u_cet;
    v.reserved_0c8 = vin.reserved_0c8;
    v.vmpl = vin.vmpl;
    v.cpl = vin.cpl;
    v.reserved_0cc = vin.reserved_0cc;
    v.efer = vin.efer;
    v.reserved_0d8 = vin.reserved_0d8;
    v.xss = vin.xss;
    v.cr4 = vin.cr4;
    v.cr3 = vin.cr3;
    v.cr0 = vin.cr0;
    v.dr7 = vin.dr7;
    v.dr6 = vin.dr6;
    v.rflags = vin.rflags;
    v.rip = vin.rip;
    v.dr0 = vin.dr0;
    v.dr1 = vin.dr1;
    v.dr2 = vin.dr2;
    v.dr3 = vin.dr3;
    v.dr0_mask = vin.dr0_mask;
    v.dr1_mask = vin.dr1_mask;
    v.dr2_mask = vin.dr2_mask;
    v.dr3_mask = vin.dr3_mask;
    v.reserved_1c0 = vin.reserved_1c0;
    v.rsp = vin.rsp;
    v.s_cet = vin.s_cet;
    v.ssp = vin.ssp;
    v.isst_addr = vin.isst_addr;
    v.rax = vin.rax;
    v.star = vin.star;
    v.lstar = vin.lstar;
    v.cstar = vin.cstar;
    v.sfmask = vin.sfmask;
    v.kernel_gs_base = vin.kernel_gs_base;
    v.sysenter_cs = vin.sysenter_cs;
    v.sysenter_esp = vin.sysenter_esp;
    v.sysenter_eip = vin.sysenter_eip;
    v.cr2 = vin.cr2;
    v.reserved_248 = vin.reserved_248;
    v.g_pat = vin.g_pat;
    v.dbgctl = vin.dbgctl;
    v.br_from = vin.br_from;
    v.br_to = vin.br_to;
    v.last_excp_from = vin.last_excp_from;
    v.last_excp_to = vin.last_excp_to;
    v.reserved_298 = vin.reserved_298;
    v.reserved_2e0 = vin.reserved_2e0;
    v.pkru = vin.pkru;
    v.reserved_2ec = vin.reserved_2ec;
    v.guest_tsc_scale = vin.guest_tsc_scale;
    v.guest_tsc_offset = vin.guest_tsc_offset;
    v.reg_prot_nonce = vin.reg_prot_nonce;
    v.rcx = vin.rcx;
    v.rdx = vin.rdx;
    v.rbx = vin.rbx;
    v.reserved_320 = vin.reserved_320;
    v.rbp = vin.rbp;
    v.rsi = vin.rsi;
    v.rdi = vin.rdi;
    v.r8 = vin.r8;
    v.r9 = vin.r9;
    v.r10 = vin.r10;
    v.r11 = vin.r11;
    v.r12 = vin.r12;
    v.r13 = vin.r13;
    v.r14 = vin.r14;
    v.r15 = vin.r15;
    v.reserved_380 = vin.reserved_380;
    v.guest_exitinfo1 = vin.guest_exitinfo1;
    v.guest_exitinfo2 = vin.guest_exitinfo2;
    v.guest_exitintinfo = vin.guest_exitintinfo;
    v.guest_nrip = vin.guest_nrip;
    v.sev_features = vin.sev_features;
    v.vintr_ctrl = vin.vintr_ctrl;
    v.guest_exit_code = vin.guest_exit_code;
    v.vtom = vin.vtom;
    v.tlb_id = vin.tlb_id;
    v.pcpu_id = vin.pcpu_id;
    v.event_inj = vin.event_inj;
    v.xcr0 = vin.xcr0;
    v.reserved_3f0= vin.reserved_3f0;
    v.x87_dp = vin.x87_dp;
    v.mxcsr = vin.mxcsr;
    v.x87_ftw = vin.x87_ftw;
    v.x87_fsw = vin.x87_fsw;
    v.x87_fcw = vin.x87_fcw;
    v.x87_fop = vin.x87_fop;
    v.x87_ds = vin.x87_ds;
    v.x87_cs = vin.x87_cs;
    v.x87_rip = vin.x87_rip;
    v.fpreg_x87 = vin.fpreg_x87;
    v.fpreg_xmm = vin.fpreg_xmm;
    v.fpreg_ymm = vin.fpreg_ymm;
    v.reserved_670 = vin.reserved_670;

}

pub fn schal_create_process(params: &mut RequestParams) -> Result<(),SvsmReqError>{
    log::info!("## Starting with new process creation ##");
    
    


    log::info!("Checking validity of all addresses");//Address must be valid; Prevents access and alignement issues
    let paddr_pages = PhysAddr::from(params.rcx);
    if !valid_phys_address(paddr_pages) || !paddr_pages.is_page_aligned(){
        log::info!("Not a valid address (valid: {}, aligend: {})",valid_phys_address(paddr_pages),paddr_pages.is_page_aligned());
        return Err(SvsmReqError::invalid_address());
    }
    let paddr_stack = PhysAddr::from(params.rdx);
    if !valid_phys_address(paddr_stack) || !paddr_stack.is_page_aligned(){
        log::info!("Not a valid address (valid: {}, aligend: {})",valid_phys_address(paddr_stack),paddr_stack.is_page_aligned());
        return Err(SvsmReqError::invalid_address());
    }
    let paddr_vmsa = PhysAddr::from(params.r8);
    if !valid_phys_address(paddr_vmsa) || !paddr_vmsa.is_page_aligned(){
        log::info!("Not a valid address (valid: {}, aligend: {})",valid_phys_address(paddr_vmsa),paddr_vmsa.is_page_aligned());
        return Err(SvsmReqError::invalid_address());
    }

    //

    log::info!("Allocating new page table");
    //TODO: Should also be move to memory from the guest to preserver memory in SVSM
    let vaddr_pagetable = allocate_zeroed_page().expect("Failed to allocate root page-table");
    let mut ptr = PageTableRef::new(unsafe { &mut *vaddr_pagetable.as_mut_ptr::<PageTable>() });

    log::info!("Mapping new page table");
    let mut virtrange = virtualrange::VirtualRange::new(); //Virtual mapping to create before inserting into the actual pagetable
    virtrange.init(VirtAddr::new(0x1000000), 1024, 12); //Set initial start of the virtual addresses
    
    let new_virt_pages = virtrange.alloc(1,0).expect("Unable to allocate page");
    ptr.map_region_4k(new_virt_pages, new_virt_pages+PAGE_SIZE, paddr_pages, PTEntryFlags::exec()).expect("Unable to map page to page table");
    

    let new_virt_stack = virtrange.alloc(1, 0)?;
    ptr.map_region_4k(new_virt_stack, new_virt_stack+PAGE_SIZE, paddr_stack, PTEntryFlags::data())?;

    log::info!("Exec: {:#X} {:#X}\n stack: {:#X} {:#X}",usize::from(new_virt_pages),usize::from( paddr_pages), usize::from(new_virt_stack), usize::from(paddr_stack));

    //

    log::info!("Add pages to current cpu pagetable"); //Temporary mappings to the current page table for rmpadjust and others
    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_pages)?;
    let vaddr_pages = mapping_guard.virt_addr();
    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_stack)?;
    let vaddr_stack = mapping_guard.virt_addr();
    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_vmsa)?;
    let vaddr_vmsa = mapping_guard.virt_addr();
    
    flush_tlb_global_sync();

    log::info!("Changing VMPL level of memory");

    rmp_adjust(vaddr_pages, RMPFlags::VMPL3 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_stack, RMPFlags::VMPL3 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_vmsa, RMPFlags::VMPL3 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_pages, RMPFlags::VMPL2 | RMPFlags::NONE, PageSize::Regular)?;
    rmp_adjust(vaddr_stack, RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_vmsa, RMPFlags::VMPL2 | RMPFlags::NONE, PageSize::Regular)?;
    
    flush_tlb_global_sync();


    




    flush_tlb_global_sync();

    log::info!("Creating new VMSA");
    rmp_set_guest_vmsa(vaddr_vmsa)?;
    rmp_revoke_guest_access(vaddr_vmsa, PageSize::Regular)?;
    rmp_adjust(
        vaddr_vmsa,
        RMPFlags::VMPL3 | RMPFlags::VMSA,
        PageSize::Regular,
    )?;
    let vmsa = VMSA::from_virt_addr(vaddr_vmsa);
    zero_mem_region(vaddr_vmsa, vaddr_vmsa + PAGE_SIZE);
    copy_vmsa(vmsa, &this_cpu_mut().guest_vmsa());

    vmsa.vmpl = 3 as u8;
    vmsa.cr3 = u64::from(ptr.cr3_value());
    vmsa.rbp = u64::from(new_virt_stack);
    vmsa.rsp = u64::from(new_virt_stack);
    vmsa.efer = vmsa.efer ^ 1u64 << 12;
    vmsa.rip = u64::from(new_virt_pages);
    log::info!("Checking VMSA correctness");

    let svme_mask: u64 = 1u64 << 12;
    if !check_vmsa_ind(vmsa, params.sev_features, svme_mask,RMPFlags::VMPL3.bits()) {
        log::info!("VMSA Check failed");
        log::info!("Bits: {}",vmsa.vmpl == RMPFlags::VMPL3.bits() as u8);
        log::info!("Efer & vsme_mask: {}", vmsa.efer & svme_mask == svme_mask);
        log::info!("SEV features: {}", vmsa.sev_features == params.sev_features);
        if vmsa.efer & svme_mask == svme_mask {
            PERCPU_VMSAS.unregister(paddr_vmsa, false).unwrap();
            core_create_vcpu_error_restore(vaddr_vmsa)?;
            return Err(SvsmReqError::invalid_parameter());   
        }
    }

    log::info!("Updating CPU");
    let apic_id = this_cpu().get_apic_id();
    let target_cpu = PERCPU_AREAS.get(apic_id).ok_or_else(SvsmReqError::invalid_parameter)?;
    PERCPU_VMSAS.register(paddr_vmsa, apic_id, true)?;

    assert!(PERCPU_VMSAS.set_used(paddr_vmsa) == Some(apic_id));
    log::info!("Creating new VMPL zone if it does not yet exsit");
    this_cpu_mut().ghcb().ap_create(paddr_vmsa,u64::from(apic_id), 3, params.sev_features)?;
    //target_cpu.update_guest_vmsa(paddr_vmsa);
    
    log::info!("");
   
    Ok(())
}





pub fn schal_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::info!("Request: {}, Parameters: rcx: {}; rdx: {}; r8: {}; sev_features: {};", request, params.rcx, params.rdx,params.r8,params.sev_features);
    
    match request{
        0 => schal_nothing(params),
        1 => schal_create_process(params),
        
        _ => Ok(())
    }
    
}