extern crate alloc;

use core::arch::global_asm;
use core::cell::UnsafeCell;
use alloc::vec::Vec;
use cpuarch::vmsa::VMSASegment;
use igvm_defs::PAGE_SIZE_4K;
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::address::PhysAddr;
use crate::cpu::percpu::this_cpu_shared;
use crate::cpu::percpu::this_cpu_unsafe;
use crate::cpu::tss::{X86Tss,TSS_LIMIT};
use crate::cpu::gdt::GDT;
use crate::cpu::idt::common::{IdtEntry, DF_VECTOR, IDT, PF_VECTOR, GP_VECTOR};
use crate::cpu::control_regs::read_cr3;
use crate::mm::PAGE_SIZE;
use crate::mm::pagetable::PageTableRef;
use crate::mm::SVSM_PERCPU_VMSA_BASE;
use crate::process_manager::process_memory;
use crate::process_manager::PROCESS_STORE_SIZE;
use crate::process_manager::process_memory::{allocate_page, free_page, ALLOCATION_RANGE_VIRT_START};
use crate::process_manager::allocation::AllocationRange;
use crate::process_manager::process_paging::{ProcessPageTableEntry, ProcessPageTableRef};
use crate::process_manager::process_paging::ProcessPageFlags;
use crate::process_runtime::runtime::MmapManager;
use crate::protocols::errors::SvsmResultCode;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::sev::RMPFlags;
use crate::sev::rmp_adjust;
//use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::percpu::this_cpu;
//use crate::cpu::flush_tlb_global_sync;
use crate::types::PageSize;
use crate::address::VirtAddr;
use crate::mm::PerCPUPageMappingGuard;
use crate::sev::utils::rmp_set_guest_vmsa;
use crate::vaddr_as_u64_slice;

use cpuarch::vmsa::VMSA;
use core::mem::replace;

use super::process_paging::{TP_STACK_START_VADDR,TP_KERN_STACK_START_VADDR};
use super::process_paging::{TP_LIBOS_START_VADDR,TP_MANIFEST_START_VADDR};
use super::memory_channels::MemoryChannel;
use crate::attestation::monitor::{ProcessMeasurements, measure};

trait FromVAddr {
    fn from_virt_addr(v: VirtAddr) -> &'static mut VMSA;
}

impl FromVAddr for VMSA {
    fn from_virt_addr(v: VirtAddr) -> &'static mut VMSA{
        unsafe { v.as_mut_ptr::<VMSA>().as_mut().unwrap() }
    }
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum TrustedProcessType {
    Undefined,
    Zygote,
    Trustlet,
}
pub const UNDEFINED_PROCESS: u32 = 0;
pub const ZYGOTE_PROCESS: u32 = 1;
pub const TRUSTLET_PROCESS: u32 = 2;

pub static PROCESS_STORE: TrustedProcessStore = TrustedProcessStore::new();

#[derive(Debug)]
pub struct TrustedProcessStore{
    processes: UnsafeCell<Vec<TrustedProcess>>,
}

unsafe impl Sync for TrustedProcessStore {}

impl TrustedProcessStore {
    const fn new() -> Self {
        Self {
            processes: UnsafeCell::new(Vec::new()),
        }
    }
    fn push(&self, process: TrustedProcess) {
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        ptr.push(process);
    }
    pub fn init(&self, size: u32){
        for _ in 0..size  {
            let empty_process = TrustedProcess::empty();
            self.push(empty_process);
        }
    }
    pub fn insert(&self, mut p: TrustedProcess) -> i64 {
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        for i in 0..(ptr.len()) {
            if ptr[i].process_type == TrustedProcessType::Undefined {
                // ID of the Process is set when inserting into the
                // store. Only after the insert is the process id valid
                p.id = i.try_into().unwrap();
                ptr[i] = p;
                return i.try_into().unwrap();
            }
        }
        -1
    }

    pub fn get(&self, pid: ProcessID) -> &mut TrustedProcess {
        let ptr = unsafe { self.processes.get().as_mut().unwrap() };
        &mut ptr[pid.0]
    }

    pub fn delete(&self, pid: ProcessID) {
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        ptr[pid.0] = TrustedProcess::empty();
    }
}

#[derive(Clone,Copy,Debug)]
pub struct ProcessData(PhysAddr);

impl ProcessData {
    pub fn dublicate_read_only(&self) -> ProcessData{
        ProcessData(self.0)
    }
    pub fn append_data(&self){
        
    }
}

#[derive(Clone,Copy,Debug, Default)]
pub struct ProcessID(pub usize);

#[derive(Clone,Debug)]
pub struct TrustedProcess {
    pub process_type: TrustedProcessType,
    pub id: u64,
    pub parent_id: u64,
    pub base: ProcessBaseContext,
    pub measurements: ProcessMeasurements,
    #[allow(dead_code)]
    pub context: ProcessContext,
    pub mmap_manager: MmapManager,
    pub pf_target_vaddr: u64,
}

impl TrustedProcess {

    pub fn zygote(data: u64,size: u64, pgt: u64) -> Self{

        // The Zygote is loaded in 3 files
        // We first load the a struct/array of addresses
        // that can then be used to get the next parts
        let (zygote_data, range) = ProcessPageTableRef::copy_data_from_guest(data, size, pgt);

        let zygote_data_struct = vaddr_as_u64_slice!(zygote_data);
        let pal = zygote_data_struct[0];
        let pal_size = zygote_data_struct[3];
        let manifest = zygote_data_struct[1];
        let manifest_size = zygote_data_struct[4];
        let libos = zygote_data_struct[2];
        let libos_size= zygote_data_struct[5];

        range.unmount();
        range.delete();


        // The allocation (AllocationRange) is always starting at the same virtual address which is why only one allocaiton is valid
        // at the same time. TODO: Allow for different start addresses
        let mut base = ProcessBaseContext::default();
        let mut measurements = ProcessMeasurements::default();

        let (pal_data, pal_range) = ProcessPageTableRef::copy_data_from_guest(pal, pal_size, pgt);
        log::debug!("pal_data {:?} pal_range {:?}", pal_data, pal_range);
        base.init_with_data(pal_data, pal_size, pal_range);
        measurements.init_measurement = measure(pal_data.into(), pal_size);
        pal_range.unmount();
        pal_range.delete();
        log::debug!("TODO: Compare with pal measurement of the policy");

        let (manifest_data, manifest_range) = ProcessPageTableRef::copy_data_from_guest(manifest, manifest_size, pgt);
        log::debug!("manifest_range {:?}", manifest_range);
        base.add_manifest(manifest_data, manifest_size, manifest_range);
        measurements.manifest_measurement = measure(manifest_data.into(), manifest_size);
        manifest_range.unmount();
        manifest_range.delete();
        log::debug!("TODO: Compare with manifest measurement of the policy");

        let (libos_data, libos_range) = ProcessPageTableRef::copy_data_from_guest(libos, libos_size, pgt);
        log::debug!("libos_range {:?}", libos_range);
        base.add_libos(libos_data, libos_size, libos_range);
        measurements.libos_measurement = measure(libos_data.into(), libos_size);
        libos_range.unmount();
        libos_range.delete();
        log::debug!("TODO: Compare with libos measurement of the policy");

        Self {
            process_type: TrustedProcessType::Zygote,
            id: 0,
            parent_id: 0,
            base,
            measurements,
            context: ProcessContext::default(),
            mmap_manager: MmapManager::new(),
            pf_target_vaddr: 0,
        }
    }

    fn dublicate(pid: ProcessID) -> TrustedProcess {
        let process = PROCESS_STORE.get(pid);
        let base: ProcessBaseContext = process.base;
        let measurements: ProcessMeasurements = process.measurements;
        let mut context = ProcessContext::default();
        context.init(base, measurements);

        TrustedProcess {
            process_type: TrustedProcessType::Trustlet,
            id: 0,
            parent_id: pid.0 as u64, // set the id of the parent zygote
            base,
            measurements,
            context,
            mmap_manager: MmapManager::new(),
            pf_target_vaddr: 0,
        }

    }

    pub fn trustlet(parent: ProcessID, data: u64, size: u64, pgt: u64) -> Self{
        // Inherit the data from the Zygote
        let mut trustlet = TrustedProcess::dublicate(parent);
        if data != 0 {
            let (function_code, function_code_range) = ProcessPageTableRef::copy_data_from_guest(data, size, pgt);
            trustlet.base.alloc_range_function.0 = function_code_range.0;
            trustlet.base.alloc_range_function.1 = size;

            log::debug!("Measuring trustlet function");
            trustlet.measurements.function_measurement = measure(function_code.into(), size);
            log::debug!("TODO: Compare with function measurement of the policy");

            log::debug!("Adding trustlet function");
            let size = (4096 - (size & 0xFFF)) + size;
            trustlet.context.page_table_ref.add_function(function_code, size);
            function_code_range.unmount();
            function_code_range.delete();
        }
        trustlet
    }

    pub fn empty() -> Self {
        Self {
            process_type: TrustedProcessType::Undefined,
            id: 0,
            parent_id: 0,
            base: ProcessBaseContext::default(),
            measurements: ProcessMeasurements::default(),
            context: ProcessContext::default(),
            mmap_manager: MmapManager::new(),
            pf_target_vaddr: 0,
        }
    }
}

impl Drop for TrustedProcess {
    fn drop(&mut self) {
        match self.process_type {
            TrustedProcessType::Undefined => {}
            TrustedProcessType::Zygote => {
                self.base.page_table_ref.delete(&[]);
                // self.context is empty for zygotes
            }
            TrustedProcessType::Trustlet => {
                // do not delete self.base as this belongs to the zygote
                self.context.page_table_ref.delete(&[
                    idt_trustlet().base_limit().0.into(),
                    (asm_entry_trustlet_pf as u64).into(),
                    unsafe { &gdt_desc as *const u8 as u64 }.into(),
                    tss_trustlet().base().into(),
                    gdt_trustlet().base_limit().0.into()
                ]); // nothing else for now
                free_page(self.context.vmsa);
                // input and output channels are deleted as part of page_table_ref
            }
        }
    }
}

pub fn check_vmsa_ind(new: &VMSA, sev_features: u64, svme_mask: u64, vmpl_level: u64) -> bool {
    new.vmpl == vmpl_level as u8
        && new.efer & svme_mask == svme_mask
        && new.sev_features == sev_features
}

pub fn create_trusted_process(params: &mut RequestParams, t: TrustedProcessType) -> Result<(), SvsmReqError>{

    let size = params.rcx;
    let process_addr = params.rdx;
    let guest_pgt = params.r8;

    log::info!("allocated memory before creation: {}", process_memory::allocated_amount());

    match t {
        TrustedProcessType::Undefined => panic!("Invalid Creation Request"),
        TrustedProcessType::Zygote => {

            log::debug!("create_trusted_process(): Creating and registering Zygote");

            // Create contexts for the Zygote
            // e.g. Copy the Zygote into memory
            // and parse it to create a page table
            let z: TrustedProcess = TrustedProcess::zygote(process_addr, size, guest_pgt);

            // Insert it into the process store
            // Each process is identified with an idea from
            // the store
            let res = PROCESS_STORE.insert(z);

            // Copy the value to the return register
            // Conversion is required because the store
            // id is signed but the register representation
            // is not
            params.rcx = u64::from_ne_bytes(res.to_ne_bytes());
           
            log::debug!("Created Zygote #{}", params.rcx);
            log::info!("allocated memory after zygote creation: {}", process_memory::allocated_amount());
            Ok(())
        },
        TrustedProcessType::Trustlet => {

            log::debug!("create_trusted_process(): Creating and registering Trustlet");

            // We get the Zygote ID from the guest
            // Each Trustlet requires one Zygote
            let zygote_id = ProcessID(params.r9 as usize);


            let trustlet = TrustedProcess::trustlet(zygote_id, process_addr, size, guest_pgt);

            // The creation process might fail
            if trustlet.process_type == TrustedProcessType::Undefined {
                params.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
                return Ok(());
            } 

            let res = PROCESS_STORE.insert(trustlet);
            params.rcx = u64::from_ne_bytes(res.to_ne_bytes());

            log::info!("allocated memory after trustlet creation: {}", process_memory::allocated_amount());
            Ok(())

        },
    }
}

pub fn dublicate_trusted_process(_params: &mut RequestParams) -> Result<(), SvsmReqError> {
    todo!()
}

pub fn append_trusted_process(_params: &mut RequestParams) -> Result<(), SvsmReqError> {
    todo!()
}

pub fn delete_trusted_process(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let process_id = ProcessID(params.rcx as usize);
    let process = PROCESS_STORE.get(process_id);

    if process.process_type == TrustedProcessType::Zygote {
        for i in 0..PROCESS_STORE_SIZE {
            if i as usize == process_id.0 {
                continue;
            }
            let process = PROCESS_STORE.get(ProcessID(i as usize));
            if process.process_type == TrustedProcessType::Trustlet {
                if process.parent_id as usize == process_id.0 {
                    return Err(SvsmReqError::RequestError(SvsmResultCode::INVALID_PARAMETER));
                }
            }
        }
    }

    log::info!("allocated memory before deletion of {}: {}", process_id.0, process_memory::allocated_amount());
    PROCESS_STORE.delete(process_id);
    log::info!("allocated memory after deletion: {}", process_memory::allocated_amount());
    Ok(())
}

pub fn attest_trusted_process(_params: &mut RequestParams) -> Result<(), SvsmReqError> {
    todo!()
}

pub fn check_page_table(pgd_addr: u64, test_location: u64) {
    log::info!("Using Address: {:#x}", pgd_addr);
    let mut page_table_ref = ProcessPageTableRef::default();
    page_table_ref.set_external_table(pgd_addr);
    log::info!("Trying to print page table");
    //page_table_ref.print_table();
    log::info!("Finding address");
    page_table_ref.copy_address_range(VirtAddr::from(test_location),1,VirtAddr::null());
}

pub fn create_trustlet_page_table_from_user_data(data: VirtAddr, size: u64) -> ProcessPageTableRef {

    log::info!("Trying to create Page Table");
    //Page Table ref for the Trustlet
    let mut page_table_ref = ProcessPageTableRef::default();
    page_table_ref.build_from_file(data, size);

    page_table_ref
}


#[derive(Debug, Copy, Clone)]
pub struct ProcessBaseContext {
    pub page_table_ref: ProcessPageTableRef,
    pub entry_point: VirtAddr,
    pub alloc_range: AllocationRange,
    pub alloc_range_manifest: AllocationRange,
    pub alloc_range_libos: AllocationRange,
    pub alloc_range_function: AllocationRange,
}

impl Default for ProcessBaseContext {
  fn default() -> Self {
      return ProcessBaseContext {
          page_table_ref: ProcessPageTableRef::default(),
          entry_point: VirtAddr::null(),
          alloc_range: AllocationRange(0,0),
          alloc_range_manifest: AllocationRange(0,0),
          alloc_range_libos: AllocationRange(0,0),
          alloc_range_function: AllocationRange(0,0),
      }
  }
}

impl ProcessBaseContext {
    pub fn init(&mut self, elf: VirtAddr, size: u64) {
        let mut ptr = ProcessPageTableRef::default();
        self.entry_point = ptr.build_from_file(elf, size);
        self.page_table_ref = ptr;
    }

    pub fn add_manifest(&mut self, manifest: VirtAddr, size: u64, data: AllocationRange) {
        let orig_size = size;
        let size = (4096 - (size & 0xFFF)) + size;
        self.page_table_ref.add_manifest(manifest, size);
        self.alloc_range_manifest.0 = data.0;
        self.alloc_range_manifest.1 = orig_size;
    }

    pub fn add_libos(&mut self, libos: VirtAddr, size: u64, data: AllocationRange){
        let orig_size = size;
        let size = (4096 - (size & 0xFFF)) + size;
        self.page_table_ref.add_libos(libos,size);
        self.alloc_range_libos.0 = data.0;
        self.alloc_range_libos.1 = orig_size;
    }

    pub fn init_with_data(&mut self, elf: VirtAddr, size: u64, data: AllocationRange) {
        self.init(elf, size);
        self.alloc_range.0 = data.0;
        self.alloc_range.1 = size;
    }

}

#[derive(Debug, Copy, Clone)]
pub struct ProcessContext {
    pub base: ProcessBaseContext,
    pub vmsa: PhysAddr,
    pub channel: MemoryChannel,
    pub sev_features: u64,
    pub measurements: ProcessMeasurements,
    pub page_table_ref: ProcessPageTableRef,
}

impl Default for ProcessContext {
    fn default() -> Self {
        return ProcessContext {
            base: ProcessBaseContext::default(),
            vmsa: PhysAddr::null(),
            channel: MemoryChannel::default(),
            sev_features: 0,
            measurements: ProcessMeasurements::default(),
            page_table_ref: ProcessPageTableRef::default(),
        }
    }
}

// FIXME: Allocarte the GDT, IDT, and TSS in a dedicated page
/// GDT for Trustlets (shared between all Trustlets)
static GDT_TRUSTLET: RWLock<GDT> = RWLock::new(GDT::new());

fn gdt_trustlet() -> ReadLockGuard<'static, GDT> {
    GDT_TRUSTLET.lock_read()
}

fn gdt_trustlet_mut() -> WriteLockGuard<'static, GDT> {
    GDT_TRUSTLET.lock_write()
}

/// IDT for Trustlets (shared between all Trustlets)
static IDT_TRUSTLET: RWLock<IDT> = RWLock::new(IDT::new());

fn idt_trustlet() -> ReadLockGuard<'static, IDT> {
    IDT_TRUSTLET.lock_read()
}

fn idt_trustlet_mut() -> WriteLockGuard<'static, IDT> {
    IDT_TRUSTLET.lock_write()
}

/// TSS for Trustlets
// FIXME: the current implementation use the same TSS for all Trustlets. This works because
// the only one Trustlet runs at a time.
static TSS_TRUSTLET: RWLock<X86Tss> = RWLock::new(X86Tss::new());

fn tss_trustlet() -> ReadLockGuard<'static, X86Tss> {
    TSS_TRUSTLET.lock_read()
}

fn tss_trustlet_mut() -> WriteLockGuard<'static, X86Tss> {
    TSS_TRUSTLET.lock_write()
}

global_asm!(
    r#"
    .align 4096
    .code64
    .section .text
    .global asm_entry_trustlet_pf
    asm_entry_trustlet_pf:
        pushq %rcx
        movq $14, %rcx
        jmp asm_entry_with_error_code

    asm_entry_with_error_code:
       # #PF pushes the error code on the stack
       pushq %rax
       pushq %rbx
       movq 24(%rsp), %rbx      # load error code
       movq $0x4EFFFFFF, %rax   # monitor call number
       cpuid                    # call the monitor

       movq %cr2, %rax          # load faulting address
       invlpg (%rax)            # invalidate the page

       popq %rbx
       popq %rax
       popq %rcx
       addq $8, %rsp            # remove error code

       iretq

    .global asm_entry_trustlet_gp
    asm_entry_trustlet_gp:
        # #GP pushes the error code on the stack
        pushq %rcx
        movq $13, %rcx
        jmp asm_entry_with_error_code

    .global asm_entry_trustlet_df
    asm_entry_trustlet_df:
       # #DF pushes the error code on the stack
       pushq %rax
       pushq %rbx
       pushq %rcx
       movq 24(%rsp), %rbx      # load error code
       movq $0x4EFFFFFE, %rax   # monitor call number
       sgdt gdt_desc(%rip)      # store current GDT
       lea gdt_desc(%rip), %rcx
       cpuid
       /* no return */

    # debug
    .section .data
    .global gdt_desc
    gdt_desc:
    .word gdt_entry_end - gdt_entry - 1 # 2 bytes for the GDT limit
    .quad gdt_entry                     # 8 bytes for the GDT base address
    .align 256
    gdt_entry:
    .quad 0x0000000000000000  # null
    .quad 0x00af9b000000ffff  # code_64_kernel
    .quad 0x00cf93000000ffff  # data_64_kernel
    .quad 0x00affb000000ffff  # code_64_user
    .quad 0x00cff3000000ffff  # data_64_user
    .quad 0x0000000000000000  # null
    .quad 0x0000000000000000  # tss
    .quad 0xAAAAAAAAAAAAAAAA  # tss
    gdt_entry_end:
    "#,
    options(att_syntax)
);

extern "C" {
    fn asm_entry_trustlet_pf();
    fn asm_entry_trustlet_df();
    fn asm_entry_trustlet_gp();
    static gdt_desc: u8;
}

impl ProcessContext {

    /// This function is called to create a Trustlet from a Zygote
    pub fn init(&mut self, base: ProcessBaseContext, measurements: ProcessMeasurements) {

        // Setup a new page table for the Process
        // FIXME: this performs full deep copy of memory and page table from the base
        // TODO:  implement proper CoW
        let mut new_page_table_ref = ProcessPageTableRef::default();
        new_page_table_ref.init_vmpl1();
        new_page_table_ref.copy_from(&base.page_table_ref);
        let page_table_ref = new_page_table_ref;
        //let page_table_ref = base.page_table_ref;

        //Creating new VMSA for the Process
        let new_vmsa_page = allocate_page();
        let new_vmsa_mapping = PerCPUPageMappingGuard::create_4k(new_vmsa_page).unwrap();
        let new_vmsa_vaddr = new_vmsa_mapping.virt_addr();

        //Permission Setup for VMSA
        rmp_adjust(new_vmsa_vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        rmp_set_guest_vmsa(new_vmsa_vaddr).unwrap();
        rmp_adjust(new_vmsa_vaddr, RMPFlags::VMPL1 | RMPFlags::VMSA, PageSize::Regular).unwrap();

        //Guest VMSA -> New VMSA
        let vmsa = VMSA::from_virt_addr(new_vmsa_vaddr);
        let locked = this_cpu_shared().guest_vmsa.lock();
        let old_vmsa_ptr = unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() };
        _ = replace(vmsa, *old_vmsa_ptr);
        drop(locked);

        //New VMSA Setup
        vmsa.vmpl = 1; // Trustlets always run in VMPL1
        vmsa.cpl = 3; // Ring 3
        vmsa.cr3 = u64::from(page_table_ref.process_page_table);
        vmsa.efer = vmsa.efer | 1u64 << 12;
        vmsa.rip = base.entry_point.into();
        vmsa.sev_features = old_vmsa_ptr.sev_features | 4; // 4 is for #VC Reflect
        vmsa.rflags &= !(1u64 << 9); // Clear IF;
        // New Stack
        vmsa.rbp = u64::from(TP_STACK_START_VADDR)+8*4096;
        vmsa.rsp = u64::from(TP_STACK_START_VADDR)+8*4096;
        // ---
        // Setup exception handlers

        let mut svsm_page_table_ref = ProcessPageTableRef::default();
        svsm_page_table_ref.set_external_table(read_cr3().into());

        // disable SMAP/SMEP to execute the handler in ring0
        // FIXME: propery setup the page flags for the handler
        vmsa.cr4 = vmsa.cr4 & !(1u64 << 20 | 1u64 << 21);

        log::debug!("asm_entry_trustlet_pf: {:x}", asm_entry_trustlet_pf as u64);
        log::debug!("asm_entry_trustlet_df: {:x}", asm_entry_trustlet_df as u64);
        log::debug!("gdt_desc: {:x}", unsafe { &gdt_desc as *const u8 as u64 });

        // setup IDT
        // 1. setup IDT entry for #PF, #DF
        idt_trustlet_mut().set_entry(PF_VECTOR, IdtEntry::trap_entry(asm_entry_trustlet_pf));
        idt_trustlet_mut().set_entry(GP_VECTOR, IdtEntry::trap_entry(asm_entry_trustlet_gp));
        idt_trustlet_mut().set_entry(DF_VECTOR, IdtEntry::entry(asm_entry_trustlet_df));
        //idt_trustlet_mut().set_entry(GP_VECTOR, IdtEntry::trap_entry(asm_entry_trustlet_df));
        // 2. rmpadjust for IDT and handlers
        let (idt_base, limit) = idt_trustlet().base_limit();
        rmp_adjust(idt_base.into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        rmp_adjust((asm_entry_trustlet_pf as u64).into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        rmp_adjust((unsafe { &gdt_desc as *const u8 as u64 }).into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        // 3. map IDT and handlers to trustlet's page table
        let idt_phys = svsm_page_table_ref.virt_to_phys(idt_base.into());
        let handler_phys = svsm_page_table_ref.virt_to_phys((asm_entry_trustlet_pf as u64).into());
        let gdt_desc_phys = svsm_page_table_ref.virt_to_phys((unsafe { &gdt_desc as *const u8 as u64 }).into());
        assert!(idt_phys != PhysAddr::null());
        assert!(handler_phys != PhysAddr::null());
        assert!(gdt_desc_phys != PhysAddr::null());
        // FIXME: this assertion is to check the virtual address is available, but this page could
        // be also used by GDT/TSS and in that case the assertion will fail. Currently IDT and TSS
        // is aligend to 4KB boundary to about this issue. Fix this by properly allocating and
        // managing the page for IDT, TSS and GDT.
        assert!(page_table_ref.virt_to_phys(idt_base.into()) == PhysAddr::null());
        assert!(page_table_ref.virt_to_phys((asm_entry_trustlet_pf as u64).into()) == PhysAddr::null());
        assert!(page_table_ref.virt_to_phys((unsafe { &gdt_desc as *const u8 as u64 }).into()) == PhysAddr::null());
        page_table_ref.map_4k_page(idt_base.into(), idt_phys, ProcessPageFlags::exec());
        page_table_ref.map_4k_page((asm_entry_trustlet_pf as u64).into(), handler_phys, ProcessPageFlags::exec());
        page_table_ref.map_4k_page((unsafe { &gdt_desc as *const u8 as u64 }).into(), gdt_desc_phys, ProcessPageFlags::data());
        // 4. setup IDT segment in VMSA
        let vmsa_idt = VMSASegment {
            selector: 0,
            flags: 0x0,
            base: idt_base,
            limit: limit-1,
        };
        vmsa.idt = vmsa_idt;

        // setup TSS
        let mut tss = tss_trustlet_mut();
        let tss_base = tss.base();
        let num_page = 1;
        // 1. setup kernel stack address
        tss.stacks[0] = (TP_KERN_STACK_START_VADDR + 4096*num_page-16).into();
        // 2. map the stack address to trustlet's page table
        page_table_ref.add_stack(TP_KERN_STACK_START_VADDR.into(), num_page);
        // 3. map the TSS to trustlet's page table
        let tss_phys = svsm_page_table_ref.virt_to_phys(tss_base.into());
        assert!(tss_phys != PhysAddr::null());
        assert!(page_table_ref.virt_to_phys(tss_base.into()) == PhysAddr::null());
        page_table_ref.map_4k_page(tss_base.into(), tss_phys, ProcessPageFlags::data());
        // 4. rmpadjust for TSS
        rmp_adjust(tss_base.into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        let vmsa_tss = VMSASegment {
            selector: 6*8,
            flags: 0x89, // TSS
            base: tss_base,
            limit: TSS_LIMIT as u32-1,
        };
        vmsa.tr = vmsa_tss;

        // setup GDT
        // GDT entreies:
        // 0. null
        // 1. code_64_kernel
        // 2. data_64_kernel
        // 3. code_64_user
        // 4. data_64_user
        // 5. null
        // 6-7. TSS
        let (desc0, desc1) = tss.to_gdt_entry();
        unsafe{
            // this sets the entry 6 for TSS
            gdt_trustlet_mut().set_tss_entry(desc0, desc1);
        }
        let (base_gdt, limit) = gdt_trustlet().base_limit();
        log::debug!("GDT base: {:x}, limit: {:x}", base_gdt, limit);
        // 1. rmpadjust for GDT
        rmp_adjust(base_gdt.into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        // 2. map GDT to trustlet's page table
        let gdt_phys = svsm_page_table_ref.virt_to_phys(base_gdt.into());
        assert!(gdt_phys != PhysAddr::null());
        // FIXME: currently use the same virtual address as the SVSM for the trustlet
        assert!(page_table_ref.virt_to_phys(base_gdt.into()) == PhysAddr::null());
        page_table_ref.map_4k_page(base_gdt.into(), gdt_phys, ProcessPageFlags::data());
        // 3. setup GDT segment in VMSA
        let vmsa_gdt = VMSASegment {
            selector: 0,
            flags: 0,
            base: base_gdt,
            limit: limit,
        };
        vmsa.gdt = vmsa_gdt;

        let cs = VMSASegment {
            selector: 3*8 | 0x3,
            flags: 0xAFB, // user, code, 4KB granularity, 64-bit
            base: 0,
            limit: 0xFFFF_FFFF,
        };
        let ds = VMSASegment {
            selector: 4*8 | 0x3,
            flags: 0xCF3, // user, data, 4KB granularity, 64-bit
            base: 0,
            limit: 0xFFFF_FFFF,
        };

        vmsa.cs = cs;
        vmsa.ds = ds;
        vmsa.es = ds;
        vmsa.fs = ds;
        vmsa.ss = ds;

        let efer = vmsa.efer;
        let cr4 = vmsa.cr4;
        let rflags = vmsa.rflags;
        log::debug!("vmsa EFER: {:?}", efer);
        log::debug!("vmsa cr4: {:?}", cr4);
        log::debug!("vmsa CS: {:?}", vmsa.cs);
        log::debug!("vmsa SS: {:?}", vmsa.ss);
        log::debug!("vmsa DS: {:?}", vmsa.ds);
        log::debug!("vmsa rflags: {:?}", rflags);

        // ------ end of exception handlers setup

        //Check VMSA
        let svme_mask: u64 = 1u64 << 12;
        if !check_vmsa_ind(vmsa, vmsa.sev_features, svme_mask, RMPFlags::VMPL1.bits()) {
            log::debug!("VMSA Check failed");
            log::debug!("Bits: {}",vmsa.vmpl == RMPFlags::VMPL1.bits() as u8);
            log::debug!("Efer & vsme_mask: {}", vmsa.efer & svme_mask == svme_mask);
            log::debug!("SEV features: {}", vmsa.sev_features == vmsa.sev_features);
            panic!("Failed to create new VMSA");
        }


        //Memory Channel setup -- No chain setup here
        let page_table_addr = vmsa.cr3;
        let mut pptr = ProcessPageTableRef::default();
        pptr.set_external_table(page_table_addr);
        self.channel.allocate_input(&mut pptr, PAGE_SIZE);
        self.channel.allocate_output(&mut pptr, PAGE_SIZE);


        self.vmsa = new_vmsa_page;
        self.sev_features = vmsa.sev_features;
        self.base = base;
        self.measurements = measurements;
        self.page_table_ref = page_table_ref;
    }

    pub fn add_function(&mut self, function: VirtAddr, size: u64) {
        let size = size + PAGE_SIZE_4K - (size % PAGE_SIZE_4K);
        self.base.page_table_ref.add_function(function, size);
    }

    pub fn test_run(&self) {
        let apic_id = this_cpu().get_apic_id();
        log::info!("Trying to execute Context");
        unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(self.vmsa,u64::from(apic_id), 1, self.sev_features | 4).unwrap()}
        log::info!("Done Trying");
        log::info!("Moving RIP");
        let mapping = PerCPUPageMappingGuard::create_4k(self.vmsa).unwrap();
        let vmsa_vaddr = mapping.virt_addr();
        let vmsa = unsafe {vmsa_vaddr.as_mut_ptr::<VMSA>().as_mut().unwrap() };
        let rip = vmsa.rip;
        log::info!("Now: {:?}",rip);
        vmsa.rip = vmsa.rip + 2; //cpuid is 2 Bytes long
    }

}

