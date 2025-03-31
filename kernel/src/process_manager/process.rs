extern crate alloc;
use crate::process_manager::memory_channels::MemoryChannel;
use crate::attestation::monitor::ProcessMeasurements;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::address::PhysAddr;
use crate::address::VirtAddr;
use cpuarch::vmsa::VMSA;
use core::cell::UnsafeCell;
use crate::process_manager::allocation::AllocationRange;
use alloc::vec::Vec;
use crate::process_runtime::runtime::MmapManager;
use crate::process_manager::exception_handling::gdt_trustlet;
use crate::process_manager::process_memory::free_page;
use crate::process_manager::exception_handling::tss_trustlet;
use crate::process_manager::exception_handling::asm_entry_trustlet_pf;
use crate::process_manager::exception_handling::gdt_desc;
use crate::process_manager::exception_handling::idt_trustlet;

#[cfg(not(feature = "no_cow"))]
pub mod process_cow;

#[cfg(feature = "no_cow")]
pub mod process_no_cow;

#[cfg(not(feature = "no_cow"))]
pub use process_cow::*;

#[cfg(feature = "no_cow")]
pub use process_no_cow::*;


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

#[derive(Clone,Debug)]
pub struct TrustedProcess {
    pub process_type: TrustedProcessType,
    pub id: u64,
    pub parent_id: u64,
    //#[cfg(feature = "attestation_benchmark")]
    pub base: ProcessBaseContext,
    pub measurements: ProcessMeasurements,
    #[allow(dead_code)]
    pub context: ProcessContext,
    pub mmap_manager: MmapManager,
    pub pf_target_vaddr: u64,
}

impl ProcessBaseContext {
    pub fn init(&mut self, elf: VirtAddr, size: u64) {
        let mut ptr = ProcessPageTableRef::default();
        self.entry_point = ptr.build_from_file(elf, size);
        self.page_table_ref = ptr;
    }

    #[allow(unused_variables)]
    pub fn add_manifest(&mut self, manifest: VirtAddr, size: u64, data: AllocationRange) {
        //let orig_size = size;
        let size = (4096 - (size & 0xFFF)) + size;
        self.page_table_ref.add_manifest(manifest, size);
        //self.alloc_range_manifest.0 = data.0;
        //self.alloc_range_manifest.1 = orig_size;
    }

    #[allow(unused_variables)]
    pub fn add_libos(&mut self, libos: VirtAddr, size: u64, data: AllocationRange){
        let orig_size = size;
        let size = (4096 - (size & 0xFFF)) + size;
        self.page_table_ref.add_libos(libos,size);
        //self.alloc_range_libos.0 = data.0;
        //self.alloc_range_libos.1 = orig_size;
    }

    #[allow(unused_variables)]
    pub fn init_with_data(&mut self, elf: VirtAddr, size: u64, data: AllocationRange) {
        self.init(elf, size);
        //self.alloc_range.0 = data.0;
        //self.alloc_range.1 = size;
    }

}

pub fn check_vmsa_ind(new: &VMSA, sev_features: u64, svme_mask: u64, vmpl_level: u64) -> bool {
    new.vmpl == vmpl_level as u8
        && new.efer & svme_mask == svme_mask
        && new.sev_features == sev_features
}

impl TrustedProcess {
    fn dublicate(pid: ProcessID) -> TrustedProcess {
        let process = PROCESS_STORE.get(pid);
        let base: ProcessBaseContext = process.base;
        let measurements: ProcessMeasurements = process.measurements;
        let mut context = ProcessContext::default();
        context.init(base, measurements, process.context);

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

impl TrustedProcess {
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
