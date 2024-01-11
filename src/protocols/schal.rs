use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::{this_cpu_mut, PERCPU_AREAS, PERCPU_VMSAS};
use crate::error::SvsmError;
use crate::mm::virtualrange::{VIRT_ALIGN_2M, VIRT_ALIGN_4K};
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::{valid_phys_address, writable_phys_addr, GuestPtr};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::sev::utils::{
    pvalidate, rmp_clear_guest_vmsa, rmp_grant_guest_access, rmp_revoke_guest_access,
    rmp_set_guest_vmsa, PvalidateOp, RMPFlags, SevSnpError,
};
use crate::sev::vmsa::VMSA;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::zero_mem_region;

/*
pub struct RequestParams {
    pub guest_exit_code: GuestVMExit,
    sev_features: u64,
    rcx: u64,
    rdx: u64,
    r8: u64,
}

*/
pub fn schal_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::info!("Request: {}, Parameters: rcx: {}; rdx: {}; r8: {}; sev_features: {};", request, params.rcx, params.rdx,params.r8,params.sev_features);
    Ok(())
}