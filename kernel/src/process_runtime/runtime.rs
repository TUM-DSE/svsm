use cpuarch::vmsa::VMSA;
use igvm_defs::PAGE_SIZE_4K;
use core::ffi::CStr;
use core::convert::TryInto;
use core::str;
use core::ops::Range;
use core::cmp::Ordering;
extern crate alloc;
use alloc::collections::BTreeMap;
use num_enum::TryFromPrimitive;
use crate::address::PhysAddr;
use crate::process_manager::process_paging::TP_LIBOS_START_VADDR;
use crate::{address::VirtAddr, cpu::{cpuid::{cpuid_table_raw, CpuidResult}, percpu::{this_cpu, this_cpu_unsafe}}, map_paddr, mm::PerCPUPageMappingGuard, paddr_as_slice, process_manager::{process::{ProcessID, TrustedProcess, PROCESS_STORE}, process_memory::allocate_page, process_paging::{GraminePalProtFlags, ProcessPageFlags, ProcessPageTableRef}}, protocols::{errors::SvsmReqError, RequestParams}, vaddr_as_u64_slice};
use crate::process_manager::outb::{breakdown_outb, outb};

use crate::vaddr_as_slice;
use crate::types::PageSize;
use crate::sev::RMPFlags;
use crate::sev::rmp_adjust;
use crate::process_manager::process_memory::{PGD, addr_to_idx};
use crate::process_manager::memory_channels::{INPUT_VADDR, OUTPUT_VADDR};

#[cfg(feature = "stat")]
use core::sync::atomic;

const TRUSTLET_VMPL: u64 = 1;

pub trait ProcessRuntime {
    fn handle_process_request(&mut self) -> bool;
    fn pal_svsm_virt_alloc(&mut self) -> bool;
    fn pal_svsm_virt_free(&mut self) -> bool;
    fn pal_svsm_debug_print(&mut self) -> bool;
    fn pal_svsm_fail(&mut self) -> bool;
    fn pal_svsm_exit(&mut self) -> bool;
    fn pal_svsm_map(&mut self) -> bool;
    fn pal_svsm_mprotect(&mut self) -> bool;
    fn pal_svsm_print_info(&mut self) -> bool;
    fn pal_svsm_set_tcb(&mut self) -> bool;
    fn pal_svsm_cpuid(&mut self) -> bool;
    fn pal_svsm_get_result(&mut self) -> bool;
    fn pal_svsm_guest_request(&mut self) -> bool;
    fn handle_exception(&mut self) -> bool;
    fn handle_df(&mut self) -> bool;
    fn pal_svsm_call_outb(&mut self) -> bool;
    fn pal_svsm_call_outb_with_value(&mut self) -> bool;
    fn pal_svsm_call_exit(&mut self) -> bool;
    fn pal_svsm_inflate_channel(&mut self) -> bool;
    fn pal_nop(&mut self) -> bool;
    fn pal_svsm_finalize(&mut self) -> bool;
}

/// Invocation type of invokeTrustlet
#[derive(Debug,Clone,Copy,Eq,PartialEq,TryFromPrimitive)]
#[repr(u64)]
enum TrustletInvocationType {
    NORMAL=0,
    FILEATTR=1,
    OPEN=2,
    READ=3,
    MMAP=4,
}

/// Return value to the guest from invokeTrustlet
#[derive(Debug,Clone,Copy,Eq,PartialEq,TryFromPrimitive)]
#[repr(u64)]
enum TrustletReturnType {
    EXIT=0,
    GETRESULT=1,
    ERROR=2,
    FILEATTR=3,
    OPEN=4,
    READ=5,
    MMAP=6,
}

/// Guest request type from the trustlet (PAL)
#[derive(Debug,Clone,Copy,Eq,PartialEq,TryFromPrimitive)]
#[repr(u64)]
enum PalSvsmGuestRequestType {
    FILEATTR=0,
    OPEN=1,
    READ=2,
}

#[derive(Debug, Clone, Copy)]
pub struct MmapInfo {
    fd: i32, // File descriptor
    offset: usize, // Offset in the file
    addr: usize, // Start of trustlet's virtual address of the mapping
    size: usize, // Size of the mapping
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeWrapper(Range<usize>);

impl PartialOrd for RangeWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other)) // Delegate to the Ord implementation
    }
}

impl Ord for RangeWrapper {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare ranges by their start first, then by their end
        // e.g., [1..3] < [2..4] < [2..5] < [3..4]
        self.0.start.cmp(&other.0.start).then(self.0.end.cmp(&other.0.end))
    }
}

#[derive(Debug, Clone)]
pub struct MmapManager {
    mappings: BTreeMap<RangeWrapper, MmapInfo>,
}

impl MmapManager {
    pub fn new() -> Self {
        MmapManager {
            mappings: BTreeMap::new(),
        }
    }

    pub fn add_mapping(&mut self, addr: usize, size: usize, fd: i32, offset: usize) {
        let range = addr..(addr + size);
        let info = MmapInfo { fd, offset, addr, size};
        self.mappings.insert(RangeWrapper(range), info);
    }

    pub fn lookup(&self, addr: usize) -> Option<&MmapInfo> {
        // Search for the range that contains the address
        for (range, info) in self.mappings.range(..=RangeWrapper(addr..usize::max_value())).rev() {
            if range.0.contains(&addr) {
                return Some(info);
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct PALContext {
    process: &'static mut TrustedProcess,
    vmsa: &'static mut VMSA,
    string_buf: [u8;256],
    string_pos: usize,
    result_addr: u64,
    result_size: u64,
    guest_page_table: u64,
    invocation_arg_guest_vaddr: u64,
    invocation_arg_size: usize,
    return_value: u64,
}

pub fn early_invoke(zygote: &'static mut TrustedProcess) {
        //let zygote = PROCESS_STORE.get(ProcessID(id.try_into().unwrap()));

    let vmsa_paddr = zygote.context.vmsa;
    let vmsa_mapping = PerCPUPageMappingGuard::create_4k(zygote.context.vmsa).unwrap();
    let vmsa: &mut VMSA = unsafe { vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };

    let string_buf: [u8;256] = [0;256];
    let string_pos: usize = 0;
    let sev_features = zygote.context.sev_features;
    let apic_id = this_cpu().get_apic_id();

    let mut rc = PALContext{
        process: zygote,
        vmsa,
        string_buf,
        string_pos,
        // Only required for Trustlet
        result_addr: 0,
        result_size: 0,
        guest_page_table: 0,
        invocation_arg_guest_vaddr: 0,
        invocation_arg_size: 0,
        return_value: 0,
    };

    loop {
        unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(vmsa_paddr,
                                                       u64::from(apic_id),
                                                       TRUSTLET_VMPL,
                                                       sev_features).unwrap()}
        if !rc.handle_process_request(){
            break;
        }
    }

}

pub fn invoke_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::debug!("Invoking Trustlet");

    let id = params.rcx;

    // Get the invoke_data given from the guest
    // The structure of the invoke_data is as follows:
    // struct data {
    //    void* ptr;
    //    uint64_t size;
    // }
    // struct invoke_data {
    //   uint64_t invocation_type;      // invoke_data_struct[0]
    //   struct data function_arg;      // invoke_data_struct[1-2]
    //   struct data result;            // invoke_data_struct[3-4]
    //   struct data guest_request_arg; // invoke_data_struct[5-6]
    //}
    let guest_data = params.r8;
    let guest_data_size = params.r9;
    let guest_page_table = params.rdx;
    breakdown_outb(210);
    let (invoke_data, range) = ProcessPageTableRef::copy_data_from_guest(guest_data, guest_data_size, guest_page_table);
    let invoke_data_struct = vaddr_as_u64_slice!(invoke_data);

    let invocation_type : TrustletInvocationType = invoke_data_struct[0].try_into().unwrap();

    let function_arg = invoke_data_struct[1];
    let function_arg_size = invoke_data_struct[2];

    let result_addr = invoke_data_struct[3];
    let result_size = invoke_data_struct[4];

    let invocation_arg_guest_vaddr = invoke_data_struct[5];
    let invocation_arg_size = invoke_data_struct[6] as usize;
    breakdown_outb(211);
    range.unmount();
    range.delete();

    let trustlet = PROCESS_STORE.get(ProcessID(id.try_into().unwrap()));

    // Getting the current processes VMSA
    let vmsa_paddr = trustlet.context.vmsa;
    let vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet.context.vmsa).unwrap();
    let vmsa: &mut VMSA = unsafe { vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };

    let string_buf: [u8;256] = [0;256];
    let string_pos: usize = 0;
    let sev_features = trustlet.context.sev_features;

    let apic_id = this_cpu().get_apic_id();
    breakdown_outb(212);
    match invocation_type {
        TrustletInvocationType::NORMAL => {
            // log::info!("Invoking Trustlet: Normal");
            trustlet.context.channel.inflate_input(vmsa.cr3, function_arg_size as usize);
            trustlet.context.channel.inflate_output(vmsa.cr3, result_size as usize);
            if function_arg_size > 1 {
                trustlet.context.channel.copy_into(function_arg, guest_page_table, function_arg_size as usize);
            }
            #[cfg(not(feature = "boottime"))]
            {
            breakdown_outb(190);
            trustlet.measurements.input_data = trustlet.context.channel.measure_input();
            breakdown_outb(191);
            }
            breakdown_outb(213);
        } TrustletInvocationType::FILEATTR | TrustletInvocationType::OPEN | TrustletInvocationType::READ => {
            // log::info!("Invoking Trustlet: gueset request: {:?}", invocation_type);
            let mut guest_page_table_ref = ProcessPageTableRef::default();
            guest_page_table_ref.set_external_table(guest_page_table);
            let arg_page = guest_page_table_ref.get_page(VirtAddr::from(invocation_arg_guest_vaddr));
            let (_mapping, arg_mapping) = map_paddr!(arg_page);
            let arg = unsafe { core::slice::from_raw_parts_mut(arg_mapping.as_mut_ptr::<u8>(), invocation_arg_size) };

            // Copy the request arg data from the guest to the trustlet
            let data_ptr = vmsa.rcx;
            let mut page_table_ref = ProcessPageTableRef::default();
            page_table_ref.set_external_table(vmsa.cr3);
            let data_page = page_table_ref.get_page(VirtAddr::from(data_ptr));
            let offset = (data_ptr & 0xFFF) as usize;
            let (_mapping, data_mapping) = map_paddr!(data_page);
            assert!(offset + invocation_arg_size <= PAGE_SIZE_4K as usize, "Data size exceeds page size");
            let data = unsafe { core::slice::from_raw_parts_mut(data_mapping.as_mut_ptr::<u8>().wrapping_add(offset), invocation_arg_size) };
            //log::info!("invocation_arg_size: {}", invocation_arg_size);
            for i in 0..invocation_arg_size {
                data[i] = arg[i];
            }
        }
        TrustletInvocationType::MMAP => {
            // Handle page fault due to the mmap
            let mut guest_page_table_ref = ProcessPageTableRef::default();
            guest_page_table_ref.set_external_table(guest_page_table);
            let arg_page = guest_page_table_ref.get_page(VirtAddr::from(invocation_arg_guest_vaddr));
            let (_mapping, arg_mapping) = map_paddr!(arg_page);
            let arg = unsafe { core::slice::from_raw_parts_mut(arg_mapping.as_mut_ptr::<u64>(), 5) };

            // map guest provided buffer that cointains the file content for the faulting mmap
            // struct mmap_arg {
            //     uint64_t fd;
            //     uint64_t offset;
            //     uint64_t size;
            //     uint64_t addr_offset;
            //     uint64_t buf_addr;
            // }
            let buf_guest_addr = arg[4];
            let buf_page = guest_page_table_ref.get_page(VirtAddr::from(buf_guest_addr));
            let (_mapping, buf_mapping) = map_paddr!(buf_page);
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_mapping.as_mut_ptr::<u64>(), 512) };

            // allocate new physical page for the trustlet
            let mut page_table_ref = ProcessPageTableRef::default();
            page_table_ref.set_external_table(vmsa.cr3);
            let new_page = allocate_page();
            let (mapping, new_page_mapped) = paddr_as_slice!(new_page);
            rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
            // copy data from the guest buffer to the new page
            for i in 0..512 {
               new_page_mapped[i] = buf[i];
            }
            assert!(trustlet.pf_target_vaddr != 0);
            let dst = VirtAddr::from(trustlet.pf_target_vaddr);
            // update trustlet's page table
            let flags = ProcessPageFlags::FLAG_REUSE;
            page_table_ref.map_4k_page(dst, new_page, flags);
            log::info!("Mapped new page for the trustlet at 0x{:x}", trustlet.pf_target_vaddr);
        }
    }

    let mut rc = PALContext{
            process: trustlet,
            vmsa,
            string_buf,
            string_pos,
            result_addr,
            result_size,
            guest_page_table,
            invocation_arg_guest_vaddr,
            invocation_arg_size,
            return_value: TrustletReturnType::ERROR as u64,
        };

    // Execution loop of the trustlet
    // Currently the trustlet runs to completion
    loop {
        unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(vmsa_paddr,
                                                       u64::from(apic_id),
                                                       TRUSTLET_VMPL,
                                                       sev_features).unwrap()}
        if !rc.handle_process_request() {
            break;
        }
    }
    params.rcx = rc.return_value;
    breakdown_outb(214);
    Ok(())
}

pub fn create_channel(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let tid1 = params.rcx;
    let tid2 = params.rdx;

    log::info!("Creating Channel: tid={} tid={}", tid1, tid2);

    // map tid1's output channel to tid2's input channel

    let trustlet1 = PROCESS_STORE.get(ProcessID(tid1.try_into().unwrap()));
    let trustlet2 = PROCESS_STORE.get(ProcessID(tid2.try_into().unwrap()));

    let trustlet1_vmsa_paddr = trustlet1.context.vmsa;
    let trustlet1_vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet1_vmsa_paddr).unwrap();
    let trustlet1_vmsa: &mut VMSA = unsafe { trustlet1_vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };
    let trustlet1_cr3 = trustlet1_vmsa.cr3;
    let trustlet1_cr3_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(trustlet1_cr3)).unwrap();
    let trustlet1_pgd_table = vaddr_as_u64_slice!(trustlet1_cr3_mapping.virt_addr());
    let trustlet1_output_channel_pgd_idx = addr_to_idx(OUTPUT_VADDR as usize, PGD);

    let trustlet2_vmsa_paddr = trustlet2.context.vmsa;
    let trustlet2_vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet2_vmsa_paddr).unwrap();
    let trustlet2_vmsa: &mut VMSA = unsafe { trustlet2_vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };
    let trustlet2_cr3 = trustlet2_vmsa.cr3;
    let trustlet2_cr3_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(trustlet2_cr3)).unwrap();
    let trustlet2_pgd_table = vaddr_as_u64_slice!(trustlet2_cr3_mapping.virt_addr());
    let trustlet2_input_channel_pgd_idx = addr_to_idx(INPUT_VADDR as usize, PGD);

    log::info!("trustlet1_output_channel_pgd_idx: 0x{:x}", trustlet1_output_channel_pgd_idx);
    log::info!("trustlet2_input_channel_pgd_idx: 0x{:x}", trustlet2_input_channel_pgd_idx);

    // Update trustlet2's pgd entry
    //  Trustlet1 CR3 -> PGD [OUTPUT_VADDR] -> <PUD A> -> ...
    //  Trustlet2 CR3 -> PGD [INPUT_VADDR]  -> <PUD B> -> ...
    // change trustlet2's PGD entry of INPUT_VADDR to point to trustlet1's output channel
    //  Trustlet2 CR3 -> PGD [INPUT_VADDR]  -> <PUD A> -> ...
    let target_entry = trustlet1_pgd_table[trustlet1_output_channel_pgd_idx];
    trustlet2_pgd_table[trustlet2_input_channel_pgd_idx] = target_entry;

    trustlet2.context.channel.input = trustlet1.context.channel.output;

    // TODO: free trustlet2's old input channel pages

    Ok(())
}

impl ProcessRuntime for PALContext  {

    /// Handle request from the trustlet
    /// 
    /// CPUID instructions in a trustlet (VMPL1) results in control being passed to the SVSM
    /// We use this mechanism to implement monitor-call from the trustlet
    /// We use some part of (unused) cpuid leaf range for monitor calls
    /// Otherwise treat it as normal cpuid request and return the result
    /// 
    /// Monitor call arguments are passed in the trustlet's registers
    /// * rax: Monitor call code / cpuid leaf
    /// * others: arguments to the monitor call (depends on the call)
    fn handle_process_request(&mut self) -> bool {
        let vmsa = &mut self.vmsa;
        let rax = vmsa.rax;
        let rip = vmsa.rip;

        // Advance the trustlet's rip for the next execution (cpuid instruction is 2 bytes)
        vmsa.rip += 2;

        match rax {
            // normal cpuid
            0..=0x24 | 0x80000000..=0x80000021 => {
                return self.pal_svsm_cpuid();
            }
            // monitor calls from the Gramine PAL
            0x4FFFFFFF => {
                return self.pal_svsm_fail();
            }
            0x4FFFFFFE => {
                return self.pal_svsm_exit();
            }
            0x4FFFFFFD => {
                return self.pal_svsm_debug_print();
            }
            0x4FFFFFFC => {
                return self.pal_svsm_virt_alloc();
            }
            0x4FFFFFFB => {
                return self.pal_svsm_map();
            }
            0x4FFFFFFA => {
                return self.pal_svsm_set_tcb();
            }
            0x4FFFFFF9 => {
                return self.pal_svsm_mprotect();
            }
            0x4FFFFFF8 => {
                return self.pal_svsm_get_result();
            }
            0x4FFFFFF7 => {
                return self.pal_svsm_guest_request();
            }
            0x4FFFFFF6 => {
                return self.pal_svsm_virt_free();
            }
            0x4FFFFFF5 => {
                return self.pal_nop();
            }
            0x4FFFFFF4 => {
                return self.pal_svsm_finalize();
            }
            // monitor calls (other)
            0x4EFFFFFF => {
                return self.handle_exception();
            }
            0x4EFFFFFE => {
                return self.handle_df();
            }
            // Trustlet exit calls
            0x4FFFFFA0 => {
                return self.pal_svsm_call_outb();
            }
            0x4FFFFFA1 => {
                return self.pal_svsm_call_exit();
            }
            0x4FFFFFA2 => {
                return self.pal_svsm_call_outb_with_value();
            }
            0x4FFFFFA3 => {
                return self.pal_svsm_inflate_channel();
            }
            // debug
            99 => {
                let c = vmsa.rbx;
                log::info!("{}", c);

                let     c_str = core::char::from_digit(c as u32, 10).unwrap();
                log::info!("{}",c_str);
                return true
            }
            100 => {
                return self.pal_svsm_print_info();
            }
            _ => {
                log::info!("Unknown request code: {} (rip={:x})", rax, rip);
                let rbx = vmsa.rbx;
                log::info!("rbx {:?}", rbx);
                log::info!("vmsa CS: {:?}", self.vmsa.cs);
                return false;
            }

        }
       
    }

    #[cfg(feature = "no_cow")]
    fn pal_svsm_finalize(&mut self) -> bool {
        log::info!("Finalize called in No CoW mode");
        return true;
    }
    #[cfg(not(feature = "no_cow"))]
    fn pal_svsm_finalize(&mut self) -> bool {
        //Finalize should mark every current page as finalizsed, e.g. read only
        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);
        page_table_ref.finalize_pages();
        let rip = self.vmsa.rip;
        log::info!("RIP: {:#x?}",rip);
        log::info!("Fin done");
        return false;
    }

    fn pal_nop(&mut self) -> bool {
        return true;
    }

    fn pal_svsm_call_exit(&mut self) -> bool {
        return false;
    }

    fn pal_svsm_call_outb(&mut self) -> bool {
        outb(110);
        return true;
    }

    fn pal_svsm_call_outb_with_value(&mut self) -> bool {
        let value = self.vmsa.rcx;
        outb(value);
        return true;
    }

    fn pal_svsm_inflate_channel(&mut self) -> bool {
        let select = self.vmsa.rcx;
        let size = self.vmsa.rdx;
        if select == 0 {
            self.process.context.channel.inflate_input(self.vmsa.cr3, size as usize);
        }
        if select == 1 {
            self.process.context.channel.inflate_output(self.vmsa.cr3, size as usize);
        }
        return true;
    }

    /// Handle CPUID instruction from the trustlet
    /// 
    /// Register arguments:
    /// * rax: cpuid leaf
    /// * rcx: subleaf (if applicable)
    /// 
/// Return:
    /// * rax: eax value of the cpuid result
    /// * rbx: ebx value of the cpuid result
    /// * rcx: ecx value of the cpuid result
    /// * rdx: edx value of the cpuid result
    fn pal_svsm_cpuid(&mut self) -> bool {
        let eax =  self.vmsa.rax as u32;
        //let eax_tmp = self.vmsa.rax;
        //let ecx_tmp = self.vmsa.rcx;
        // Some cpuid leafs have subleaf (ecx) and some don't
        // for the ones that don't we set ecx to 0 (otherwise CPUID table lookup fails)
        let ecx = match eax {
            4 | 7 | 0xb | 0xd | 0xf|
            0x10 | 0x12 | 0x14 | 0x17 |
            0x18 | 0x1d | 0x1e | 0x1f |
            0x24 | 0x8000001d => {
                self.vmsa.rcx as u32
            }
            _ => 0
        };

        // NOTE: we must consult the cpuid table or make explict VMGEXIT, otherwise we'll get another #VC
        let res = match cpuid_table_raw(eax, ecx, 0, 0){
            Some(r) => r,
            None => CpuidResult{eax: 0,ebx: 0, ecx: 0, edx: 0}
        };

        self.vmsa.rax = res.eax as u64;
        self.vmsa.rbx = res.ebx as u64;
        if eax == 1 {
            self.vmsa.rcx = res.ecx as u64 | 0x8000000;
        } else {
            self.vmsa.rcx = res.ecx as u64;
        }
        self.vmsa.rdx = res.edx as u64;
        return true;
    }

    /// Inidicated that results are ready
    ///
    /// Return:
    /// Sets the trustlet return value to 0
    /// Copies the reuslts into the provided buffer
    fn pal_svsm_get_result(&mut self) -> bool {
        breakdown_outb(220);
        self.process.context.channel.copy_out(
            self.result_addr,
            self.guest_page_table,
            self.result_size as usize);
        self.return_value = TrustletReturnType::GETRESULT as u64;
        #[cfg(not(feature = "boottime"))]
        {
        breakdown_outb(192);
        self.process.measurements.output_data = self.process.context.channel.measure_output();
        breakdown_outb(193);
        }
        breakdown_outb(221);

        #[cfg(feature="stat")]
        {
            let page_table = self.vmsa.cr3;
            let mut page_table_ref = ProcessPageTableRef::default();
            page_table_ref.set_external_table(page_table);
            page_table_ref.mem_stat();
        }

        false
    }

    /// Free virtual memory in the trustlet's page table
    ///
    /// Register arguments:
    /// * rax: monitor call code ()
    /// * rbx: trustlet's virtual address to free
    /// *
    fn pal_svsm_virt_free(&mut self) -> bool {
        //log::info!("FREE");
        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;

        //TODO: Check if Address can used

        if size % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return true;
        }

        if addr % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return true;
        }
        page_table_ref.remove_pages(VirtAddr::from(addr), size / 4096);

        return true;
    }

    /// Allocate virtual memory in the trustlet's page table
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFC)
    /// * rbx: trustlet's virtual address to allocate
    /// * rcx: size of memory to allocate
    /// * rdx: flags (GraminePalProtFlags)
    /// 
    /// Retrun:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_virt_alloc(&mut self) -> bool {
        // Getting the Page Table of the current Trustlet being executed
        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;

        // Check if size is a multiple of pages
        if size % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return true;
        }

        // Check if address starts at page boundary
        if addr % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return true;
        }
        let mut page_flags = ProcessPageFlags::data();
        if flags & GraminePalProtFlags::WRITE.bits() != 0 {
            page_flags = page_flags | ProcessPageFlags::WRITABLE;
        }
        /*
        // XXX: we can omit this for now as currently we support only one thread
        if flags & GraminePalProtFlags::WRITECOPY.bits() != 0 {
            page_flags = page_flags | ProcessPageFlags::COPY_ON_WRITE;
            page_flags = page_flags & !ProcessPageFlags::WRITABLE;
        }
        */
        if flags & GraminePalProtFlags::EXEC.bits() != 0 {
            page_flags = page_flags & !ProcessPageFlags::NO_EXECUTE;
        }

        page_table_ref.add_pages(VirtAddr::from(addr), size / 4096, page_flags);

        self.vmsa.rcx = u64::from_ne_bytes((0i64).to_ne_bytes());

        true
    }

    /// Handle a PAL error
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFF)
    /// * rbx: error string address
    /// * rcx: error number
    /// 
    /// Return:
    /// * no return to the trustlet (exit the trustlet)
    fn pal_svsm_fail(&mut self) -> bool{
        // PAL reports error, exit the trustlet

        let page_table = self.vmsa.cr3;
        let string = self.vmsa.rbx;
        let errno = self.vmsa.rcx;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let string_address = string & !0xFFF;
        let string_phys_address = page_table_ref.get_page(VirtAddr::from(string_address));
        let (_mapping, string_mapping) = map_paddr!(string_phys_address);
        let c_string: *const i8 = unsafe {{ string_mapping.as_ptr::<i8>() }.offset((string & 0xFFF).try_into().unwrap())};
        let s = unsafe { CStr::from_ptr(c_string) };

        log::info!(" [Trustlet] PAL Error: {} {}",s.to_str().unwrap(), errno);
        false
    }

    /// Exit the trustlet
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFE)
    /// * rbx: exit code
    /// 
    /// Return:
    /// * no return to the trustlet (exit the trustlet)
    fn pal_svsm_exit(&mut self) -> bool{
        // PAL exits, exit the trustlet
        let exit_code = self.vmsa.rbx;
        log::info!(" [Trustlet] Exit with Status Code: {}", exit_code);
        self.return_value = TrustletReturnType::EXIT as u64;
        false
    }

    /// Print debug message from the trustlet
    /// 
    /// This function expects that the trustlet calls this function with each character,
    /// and the final character is 0
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFD)
    /// * rbx: character to print
    /// 
    /// Return:
    /// * no return value
    fn pal_svsm_debug_print(&mut self) -> bool {
        let c = self.vmsa.rbx;
        if self.string_pos < 255{
            self.string_buf[self.string_pos] = c as u8;
            self.string_pos += 1;
        } else {
            log::info!("Trustlet Debug Message to long");
            let debug_string = str::from_utf8(&self.string_buf).unwrap();
            log::info!(" [Trustlet](partial) {}", debug_string);
            self.string_pos = 0;
            self.string_buf = [0;256];
        }
        if c == 0 {
            let debug_string = str::from_utf8(&self.string_buf).unwrap();
            log::info!(" [Trustlet] {}", debug_string);
            self.string_pos = 0;
            self.string_buf = [0;256];
        }
        true
    }

    /// Map a file into the trustlet's memory space
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFB)
    /// * rbx: virtual address to map
    /// * rcx: size of memory to map
    /// * rdx: flags (GraminePalProtFlags)
    /// * r8: file descriptor
    /// * r9: offset
    /// 
    /// Return:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_map(&mut self) -> bool {
        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;
        let fd = self.vmsa.r8;
        let offset = self.vmsa.r9;

        log::debug!("[pal_svsm_map] addr={:#x}, size={}", addr, size);
        log::debug!("{:#}, {}", addr, size);

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        assert!(addr % 4096 == 0, "Address is not page aligned");
        assert!(size % 4096 == 0, "Size is not multiple of page size");
        assert!(offset % 4096 == 0, "Offset is not page aligned");

        if size % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return false;
        }
        let num_pages = size / 4096;

        let writable = (flags & GraminePalProtFlags::WRITE.bits()) != 0;
        let executable = (flags & GraminePalProtFlags::EXEC.bits()) != 0;
        let writecopy = (flags & GraminePalProtFlags::WRITECOPY.bits()) != 0;
        let mut flags = ProcessPageFlags::USER_ACCESSIBLE | ProcessPageFlags::ACCESSED;
        if writable {
            flags |= ProcessPageFlags::WRITABLE;
        }
        if writecopy {
            //flags |= ProcessPageFlags::COPY_ON_WRITE;
            flags &= !ProcessPageFlags::WRITABLE;
        }
        if !executable {
            flags |= ProcessPageFlags::NO_EXECUTE;
        }

        let vaddr = VirtAddr::from(addr);
        let libos_fd = u64::from_ne_bytes((-2i64).to_ne_bytes());

        if fd == libos_fd {
            // the monitor loads the libos file into the predefined address (TP_LIBOS_START_VADDR) at the start
            let s_vaddr = VirtAddr::from(TP_LIBOS_START_VADDR);

            flags |= ProcessPageFlags::PRESENT;

            for i in 0..num_pages {
                let src = s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize);
                let dst = vaddr + (i * PAGE_SIZE_4K).try_into().unwrap(); 
                let t = page_table_ref.virt_to_phys(src);

                /*
                // CoW version
                // FIXME: this does not work (unknown #PF with non-present page occurs)
                page_table_ref.map_4k_page(dst, t, flags);

                if writecopy {
                    page_table_ref.change_attr(src, true, false, true, true);
                    // TODO: flush trustleet's TLB
                }
                // check
                let t2 = page_table_ref.virt_to_phys(dst);
                assert!(t == t2, "Address mapping failed");
                continue;
                */

                // Non-CoW version (copy page content at this point for writecopy)
                if writecopy {
                    let (_old_mapping, old_page_mapped) = paddr_as_slice!(t);
                    let new_page = allocate_page();
                    let (mapping, new_page_mapped) = paddr_as_slice!(new_page);
                    rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
                    for i in 0..512 {
                       new_page_mapped[i] = old_page_mapped[i];
                    }
                    let flags = flags | ProcessPageFlags::WRITABLE;
                    page_table_ref.map_4k_page(dst, new_page, flags);
                } else {
                    page_table_ref.map_4k_page(dst, t, flags);

                    let t2 = page_table_ref.virt_to_phys(dst);
                    assert!(t == t2, "Address mapping failed");
                }
            }
            self.vmsa.rcx = u64::from_ne_bytes((0i64).to_ne_bytes());
            return true;
        }

        // Update mmap information
        let mmap_manger = &mut self.process.mmap_manager;
        /*
        // check if the address is already mapped
        let mmap_info = mmap_manger.lookup(addr as usize);
        if !mmap_info.is_none() {
            log::info!("[pal_svsm_map] Address already mapped: {:?}", mmap_info);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return true;

        }
        */
        // XXX: apparently overlapping mapping happens, so we allow it
        // mmap_manager keeps the address range like the following order
        // example: [1..3] < [2..4] < [2..5] < [3..4]
        // page fault hander uses mmap infomation whose range contains the faulting address
        // and priority is given to the latter one in the order
        // FIXME: as the ordering above does not consider the time of mapping,
        // the mmap handler might not use the latest mapping that includes the faulting address
        mmap_manger.add_mapping(addr as usize, size as usize, fd as i32, offset as usize);

        // Allocate virtul memory address
        // The actual content is loaded upon #PF
        for i in 0..num_pages {
            let dst = vaddr + (i * PAGE_SIZE_4K).try_into().unwrap(); 
            page_table_ref.map_4k_page(dst, PhysAddr::new(0), flags);
        }

        self.vmsa.rcx = u64::from_ne_bytes((0i64).to_ne_bytes());
        return true;
    }

    /// Update the trusted process' page entry permissions
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFF9)
    /// * rbx: virtual address
    /// * rcx: size of memory to update
    /// * rdx: flags (GraminePalProtFlags)
    /// 
    /// Return:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_mprotect(&mut self) -> bool {
        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;

        // log::info!("svsm_mprotect: addr={:#}, size={}, flags={}", addr, size, flags);

        let process_page_table = self.vmsa.cr3;
        let mut process_page_table_ref = ProcessPageTableRef::default();
        process_page_table_ref.set_external_table(process_page_table);

        let offset = addr & 0xFFF;
        let page_num = (offset + size + 4095) / PAGE_SIZE_4K;
        let aligned_addr = addr & !0xFFF;
        let vaddr = VirtAddr::from(aligned_addr);

        let readbable = flags & GraminePalProtFlags::READ.bits() != 0;
        let writable = flags & GraminePalProtFlags::WRITE.bits() != 0;
        let executable = flags & GraminePalProtFlags::EXEC.bits() != 0;
        let writecopy = flags & GraminePalProtFlags::WRITECOPY.bits() != 0;

        // FIXME: this walks the page table every time. we can optimize this by updating entries while walking
        for i in 0..page_num {
            let target = vaddr + (i* PAGE_SIZE_4K).try_into().unwrap();
            process_page_table_ref.change_attr(target, readbable, writable, executable, writecopy);
        }

        return true;
    }

    /// Set the TCB (Thread Control Block) for the trustlet
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFA)
    /// * rbx: TCB address
    /// 
    /// Return:
    /// * no return value
    fn pal_svsm_set_tcb(&mut self) -> bool {
      let tcb = self.vmsa.rbx;
      self.vmsa.gs.base = tcb; // Set the base of the GS segment
      return true;
    }

    fn pal_svsm_print_info(&mut self) -> bool {
        let addr = self.vmsa.rbx;
        let len = self.vmsa.rcx;
        //let print_vmsa = if self.vmsa.rdx == 0 { false } else { true };

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let addr_start = addr & !0xFFF;
        let paddr = page_table_ref.get_page(VirtAddr::from(addr_start));
        let (_mapping, addr_mapping) = map_paddr!(paddr);
        let content: *const u8 = unsafe {{ addr_mapping.as_ptr::<u8>() }.offset((addr & 0xFFF).try_into().unwrap())};
        let slice = unsafe {core::slice::from_raw_parts(content, len as usize)};

        if addr + len > addr_start + PAGE_SIZE_4K {
            log::info!("Unable to print -- Not within page");
        }
        if len % 8 != 0 {
            log::info!("Unable to print -- len not multiple of 8")
        }
        let mut i:usize = 0;
        while i != (len as usize){

            log::info!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                       slice[i],
                       slice[i+1],
                       slice[i+2],
                       slice[i+3],
                       slice[i+4],
                       slice[i+5],
                       slice[i+6],
                       slice[i+7]
            );
            i = i + 8;

        }
        //log::info!(" [Trustlet] PAL Error: {} {}",s.to_str().unwrap(), errno);
        let rdx = self.vmsa.rdx;
        log::info!("RDX: {:#x}", rdx);

        return true;
    }

    /// Make a guest request
    /// 
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFF7)
    /// * rbx: request type
    /// * rcx: additional data (pointer to the trustlet's data)
    /// * rdx: data size
    /// 
    /// Retrun:
    /// This function does not return to the trustle but return to the guest.
    /// The guest will call another invokeTruslet() after completing the request.
    fn pal_svsm_guest_request(&mut self) -> bool {
        let request_type: PalSvsmGuestRequestType = self.vmsa.rbx.try_into().unwrap();
        let data_ptr = self.vmsa.rcx;
        let data_size = self.vmsa.rdx as usize;
        assert!(data_size <= self.invocation_arg_size, "Data size exceeds the invocation arg size");

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        // Map user provided arguments
        // FIXME: for now we assume that the data is within a single page
        let data_page = page_table_ref.get_page(VirtAddr::from(data_ptr));
        let offset = (data_ptr & 0xFFF) as usize;
        let (_mapping, data_mapping) = map_paddr!(data_page);
        assert!(offset + data_size <= PAGE_SIZE_4K as usize, "Data size exceeds page size");
        let data = unsafe { core::slice::from_raw_parts(data_mapping.as_ptr::<u8>().wrapping_add(offset), data_size) };

        // copy the path into the guest arg struct
        let mut guest_page_table_ref = ProcessPageTableRef::default();
        guest_page_table_ref.set_external_table(self.guest_page_table);
        let arg_page = guest_page_table_ref.get_page(VirtAddr::from(self.invocation_arg_guest_vaddr));
        let (_mapping, arg_mapping) = map_paddr!(arg_page);
        let arg = unsafe { core::slice::from_raw_parts_mut(arg_mapping.as_mut_ptr::<u8>(), self.invocation_arg_size) };
        for i in 0..data_size {
            arg[i] = data[i];
        }
        
        self.return_value = match request_type {
            PalSvsmGuestRequestType::FILEATTR => {
                TrustletReturnType::FILEATTR as u64
            }
            PalSvsmGuestRequestType::OPEN => {
                TrustletReturnType::OPEN as u64
            }
            PalSvsmGuestRequestType::READ => {
                TrustletReturnType::READ as u64
            }
        };
        false
    }

    /// Handle an exception occured in the trustlet
    // XXX: Currently this function assumes that the exception is a #PF
    fn handle_exception(&mut self) -> bool {
        let exception = self.vmsa.rcx;
        match exception {
            13 => {
                let cr2 = self.vmsa.cr2;
                let error_code = self.vmsa.rbx;
                let rsp = self.vmsa.rsp;
                log::info!("[Trustlet] #GP: CR2=0x{:x}, error_code = {}", cr2, error_code);
                let mut process_page_table_ref = ProcessPageTableRef::default();
                process_page_table_ref.set_external_table(self.vmsa.cr3);
                // dump stack
                let stack_base_paddr = process_page_table_ref.get_page(VirtAddr::from(rsp));
                let offset = (rsp & 0xFFF) / 8;
                let (_mapping, stack_mapping) = map_paddr!(stack_base_paddr);
                for i in 0..9 {
                    log::info!("[Trustlet] Stack (rsp+{}): {:#x}", i*8, unsafe{stack_mapping.as_ptr::<u64>().offset((offset + i).try_into().unwrap()).read()});
                }
                let efer = self.vmsa.efer;
                let rip = self.vmsa.rip;
                let cr2 = self.vmsa.cr2;
                let cr4 = self.vmsa.cr4;
                let rsp = self.vmsa.rsp;
                let rflags = self.vmsa.rflags;
                let rdi = self.vmsa.rdi;
                log::info!("vmsa EFER: {:?}", efer);
                log::info!("vmsa CR2: {:?}", cr2);
                log::info!("vmsa cr4: {:?}", cr4);
                log::info!("vmsa rip: {:?}", rip);
                log::info!("vmsa CS: {:?}", self.vmsa.cs);
                log::info!("vmsa SS: {:?}", self.vmsa.ss);
                log::info!("vmsa DS: {:?}", self.vmsa.ds);
                log::info!("vmsa RFLAGS: {:?}", rflags);
                log::info!("vmsa rsp: {:?}", rsp);
                log::info!("vmsa rdi: {:?}", rdi);
                log::info!("Unhandled #GP");
                return false;
            }
            14 => {
                #[cfg(feature = "stat")]
                crate::sev::utils::stat::PF_COUNT.fetch_add(1, atomic::Ordering::Relaxed);

                let rip= self.vmsa.rip;
                let cr2 = self.vmsa.cr2;
                let error_code = self.vmsa.rbx;
                const PF_PRESENT: u64 = 1 << 0;
                const PF_WRITE: u64 = 1 << 1;
                const PF_USER: u64 = 1 << 2;
                const PF_RESERVED: u64 = 1 << 3;
                const PF_INSTRUCTION: u64 = 1 << 4;
                let mmap_manager = &self.process.mmap_manager;
                log::info!("[Trustlet] #PF: CR2=0x{:x}", cr2);
                if let Some(mmap_info) = mmap_manager.lookup(cr2 as usize) {
                    log::info!("Found file mapping: mmap_info={:?}", mmap_info);
                    if error_code & PF_PRESENT == 0 {
                        // non-presente page
                        log::debug!("[Trustlet] Page fault: not present page");
                        let target_page_addr = cr2 & !0xFFF;
                        self.process.pf_target_vaddr = target_page_addr;
                        assert!(target_page_addr >= mmap_info.addr as u64);
                        let addr_offset = target_page_addr - mmap_info.addr as u64;
                        assert!(addr_offset % 4096 == 0);

                        // guest arg structure:
                        // struct {
                        //   u64 fd;
                        //   u64 offset;
                        //   u64 size;
                        //   u64 addr_offset;
                        // }
                        let mut guest_page_table_ref = ProcessPageTableRef::default();
                        guest_page_table_ref.set_external_table(self.guest_page_table);
                        let arg_page = guest_page_table_ref.get_page(VirtAddr::from(self.invocation_arg_guest_vaddr));
                        let (_mapping, arg_mapping) = map_paddr!(arg_page);
                        let arg = unsafe { core::slice::from_raw_parts_mut(arg_mapping.as_mut_ptr::<u64>(), 4) };
                        arg[0] = mmap_info.fd as u64;
                        arg[1] = mmap_info.offset as u64;
                        arg[2] = mmap_info.size as u64;
                        arg[3] = addr_offset;

                        // make a guest request to load the page
                        self.return_value = TrustletReturnType::MMAP as u64;
                        return false;
                    } else {
                        log::info!("[Trustlet] #PF on present mmaped-page");
                    }
                } else {
                    log::info!("[Trustlet] #PF: address is not mmaped-page");
                }
                if error_code & PF_PRESENT != 0 && error_code & PF_WRITE != 0 {
                    // CoW
                    #[cfg(feature = "stat")]
                    crate::sev::utils::stat::COW_COUNT.fetch_add(1, atomic::Ordering::Relaxed);

                    let mut page_table_ref = ProcessPageTableRef::default();
                    page_table_ref.set_external_table(self.vmsa.cr3);
                    // Handle CoW
                    log::debug!("[Trustlet] CoW: RIP={:#x}, CR2={:#x}, Error code={:?}", rip, cr2, error_code);
                    let user_access = error_code & PF_USER != 0;
                    let handled = page_table_ref.handle_cow(VirtAddr::from(cr2), user_access);
                    if handled {
                        log::debug!("[Trustlet] CoW: handled");
                        return true;
                    }
                    log::info!("[Trustlet] [BUG] CoW: not handled");
                }

                // XXX: it should not come here
                // debug
                let efer = self.vmsa.efer;
                let rip = self.vmsa.rip;
                let cr2 = self.vmsa.cr2;
                let cr4 = self.vmsa.cr4;
                let rsp = self.vmsa.rsp;
                let rflags = self.vmsa.rflags;
                log::info!("[Trustlet] [BUG] Unhandled Page Fault!");
                log::info!("vmsa EFER: {:?}", efer);
                log::info!("vmsa CR2: {:?}", cr2);
                log::info!("vmsa cr4: {:?}", cr4);
                log::info!("vmsa rip: {:?}", rip);
                log::info!("vmsa CS: {:?}", self.vmsa.cs);
                log::info!("vmsa SS: {:?}", self.vmsa.ss);
                log::info!("vmsa DS: {:?}", self.vmsa.ds);
                log::info!("vmsa RFLAGS: {:?}", rflags);
                log::info!("vmsa rsp: {:?}", rsp);
                let mut process_page_table_ref = ProcessPageTableRef::default();
                process_page_table_ref.set_external_table(self.vmsa.cr3);
                // dump stack
                let stack_base_paddr = process_page_table_ref.get_page(VirtAddr::from(rsp));
                let offset = (rsp & 0xFFF) / 8;
                let (_mapping, stack_mapping) = map_paddr!(stack_base_paddr);
                for i in 0..9 {
                    log::info!("[Trustlet] Stack (rsp+{}): {:#x}", i*8, unsafe{stack_mapping.as_ptr::<u64>().offset((offset + i).try_into().unwrap()).read()});
                }

                /*
                // debug: allocate a page for the faulting address
                let mut page_table_ref = ProcessPageTableRef::default();
                page_table_ref.set_external_table(self.vmsa.cr3);
                page_table_ref.add_pages(VirtAddr::from(cr2), 1, ProcessPageFlags::data());
                return true;
                 */

                log::info!("[Trustlet] #PF: RIP={:#x}, CR2={:#x}, Error code={:?}", rip, cr2, error_code);
                if error_code & PF_PRESENT == 0 {
                    log::info!("[Trustlet] Page fault: not present");
                }
                if error_code & PF_WRITE != 0 {
                    log::info!("[Trustlet] Page fault: write");
                }
                if error_code & PF_USER != 0 {
                    log::info!("[Trustlet] Page fault: user");
                }
                if error_code & PF_RESERVED != 0 {
                    log::info!("[Trustlet] Page fault: reserved");
                }
                if error_code & PF_INSTRUCTION != 0 {
                    log::info!("[Trustlet] Page fault: instruction fetch");
                }
                false
            }
            _ => {
                todo!();
            }
        }
    }

    // handle double fault
    fn handle_df(&mut self) -> bool {
        log::info!(" [Trustlet] ---------------------------------");
        log::info!(" [Trustlet] Double Fault!");

        let error_code = self.vmsa.rbx;
        log::info!(" [Trustlet] Error Code: {:#x}", error_code);

        // Dump stack
        // Stak layout:
        // rsp + 0: rcx  (pushed by the hanlder)
        // rsp + 8: rbx  (pushed by the hanlder)
        // rsp + 16: rax (pushed by the hanlder)
        // rsp + 24: error_code
        // rsp + 32: rip
        // rsp + 40: cs
        // rsp + 48: rflags
        // rsp + 54: rsp
        // rsp + 64: ss
        let mut process_page_table_ref = ProcessPageTableRef::default();
        process_page_table_ref.set_external_table(self.vmsa.cr3);
        let rsp = self.vmsa.rsp;
        let stack_base_paddr = process_page_table_ref.get_page(VirtAddr::from(rsp));
        let offset = (rsp & 0xFFF) / 8;
        let (_mapping, stack_mapping) = map_paddr!(stack_base_paddr);
        for i in 0..9 {
            log::info!(" [Trustlet] Stack (rsp+{}): {:#x}", i*8, unsafe{stack_mapping.as_ptr::<u64>().offset((offset + i).try_into().unwrap()).read()});
        }

        // Dump GDT
        // RCX register points to the GDT (limit (2byte) + base (4byte))
        let gdt_ptr = self.vmsa.rcx;
        let page = process_page_table_ref.get_page(VirtAddr::from(gdt_ptr));
        let gdt_offset = (gdt_ptr & 0xFFF) as usize;
        let (_mapping, gdt_mapping) = map_paddr!(page);
        let gdt_limit = unsafe{gdt_mapping.as_ptr::<u8>().add(gdt_offset).cast::<u16>().read()};
        let gdt_base = unsafe{gdt_mapping.as_ptr::<u8>().add(gdt_offset+2).cast::<u64>().read()};
        log::info!(" [Trustlet] gdt_ptr: {:#x}", gdt_ptr);
        log::info!(" [Trustlet] GDT: limit={:#x}, base={:#x}", gdt_limit, gdt_base);
        let gdt_page = process_page_table_ref.get_page(VirtAddr::from(gdt_base));
        let (_mapping, gdt_mapping) = map_paddr!(gdt_page);
        let gdt_entries = gdt_limit as usize / 8;
        let gdt_entry_offset = (gdt_base & 0xFFF) as usize;
        for i in 0..=gdt_entries {
            let entry = unsafe{gdt_mapping.as_ptr::<u8>().add(gdt_entry_offset).cast::<u64>().add(i).read()};
            log::info!(" [Trustlet] GDT[{}]: {:#x}", i, entry);
        }
        
        // Dump CPU state
        // rax, rbx are pushed to the stack
        let rax = unsafe{stack_mapping.as_ptr::<u64>().offset((offset + 2).try_into().unwrap()).read()};
        let rbx = unsafe{stack_mapping.as_ptr::<u64>().offset((offset + 1).try_into().unwrap()).read()};
        let rcx = unsafe{stack_mapping.as_ptr::<u64>().offset((offset + 0).try_into().unwrap()).read()};
        let rdx = self.vmsa.rdx;
        let rsi = self.vmsa.rsi;
        let rdi = self.vmsa.rdi;
        let r8 = self.vmsa.r8;
        let r9 = self.vmsa.r9;
        let r10 = self.vmsa.r10;
        let r11 = self.vmsa.r11;
        let r12 = self.vmsa.r12;
        let r13 = self.vmsa.r13;
        let r14 = self.vmsa.r14;
        let r15 = self.vmsa.r15;

        log::info!(" [Trustlet] rax: {:#x}", rax);
        log::info!(" [Trustlet] rbx: {:#x}", rbx);
        log::info!(" [Trustlet] rcx: {:#x}", rcx);
        log::info!(" [Trustlet] rdx: {:#x}", rdx);
        log::info!(" [Trustlet] rsi: {:#x}", rsi);
        log::info!(" [Trustlet] rdi: {:#x}", rdi);
        log::info!(" [Trustlet] r8: {:#x}", r8);
        log::info!(" [Trustlet] r9: {:#x}", r9);
        log::info!(" [Trustlet] r10: {:#x}", r10);
        log::info!(" [Trustlet] r11: {:#x}", r11);
        log::info!(" [Trustlet] r12: {:#x}", r12);
        log::info!(" [Trustlet] r13: {:#x}", r13);
        log::info!(" [Trustlet] r14: {:#x}", r14);
        log::info!(" [Trustlet] r15: {:#x}", r15);

        let rip = self.vmsa.rip;
        let rsp = self.vmsa.rsp;

        log::info!(" [Trustlet] rip: {:#x}", rip);
        log::info!(" [Trustlet] rsp: {:#x}", rsp);

        let cr2 = self.vmsa.cr2;
        let cr3 = self.vmsa.cr3;
        let cr4 = self.vmsa.cr4;
        let rflags = self.vmsa.rflags;
        let efer = self.vmsa.efer;

        log::info!(" [Trustlet] cr2: {:#x}", cr2);
        log::info!(" [Trustlet] cr3: {:#x}", cr3);
        log::info!(" [Trustlet] cr4: {:#x}", cr4);
        log::info!(" [Trustlet] efer: {:#x}", efer);
        log::info!(" [Trustlet] rflags: {:#x}", rflags);

        let cs = self.vmsa.cs;
        let ss = self.vmsa.ss;
        let ds = self.vmsa.ds;
        log::info!(" [Trustlet] cs: {:?}", cs);
        log::info!(" [Trustlet] ss: {:?}", ss);
        log::info!(" [Trustlet] ds: {:?}", ds);

        log::info!(" [Trustlet] ---------------------------------");
        false
    }
}
