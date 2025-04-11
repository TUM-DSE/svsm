//use core::arch::global_asm;
use crate::cpu::percpu::this_cpu_shared;
use crate::mm::PAGE_SIZE;
use crate::mm::SVSM_PERCPU_VMSA_BASE;
use crate::process_manager::process_memory;
use crate::process_manager::PROCESS_STORE_SIZE;
use crate::process_manager::process_memory::allocate_page;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::process_runtime::runtime::{early_invoke, MmapManager};
use crate::protocols::errors::SvsmResultCode;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::sev::RMPFlags;
use crate::sev::rmp_adjust;
use crate::types::PageSize;
use crate::address::VirtAddr;
use crate::mm::PerCPUPageMappingGuard;
use crate::sev::utils::rmp_set_guest_vmsa;
use crate::vaddr_as_u64_slice;
use super::*;
use cpuarch::vmsa::VMSA;
use core::mem::replace;

use crate::process_manager::process_paging::{TP_STACK_START_VADDR,TP_KERN_STACK_START_VADDR};
use crate::attestation::monitor::{ProcessMeasurements, measure};

use crate::process_manager::exception_handling::*;

use crate::process_manager::outb::{breakdown_outb};


impl TrustedProcess {

    pub fn zygote(data: u64,size: u64, pgt: u64) -> Self{

        // The Zygote is loaded in 3 files
        // We first load the a struct/array of addresses
        // that can then be used to get the next parts
        breakdown_outb(200);
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


        let mut base = ProcessBaseContext::default();
        let mut measurements = ProcessMeasurements::default();

        let (pal_data, pal_range) = ProcessPageTableRef::copy_data_from_guest(pal, pal_size, pgt);
        log::debug!("pal_data {:?} pal_range {:?}", pal_data, pal_range);
        base.init_with_data(pal_data, pal_size, pal_range);
        breakdown_outb(198);
        measurements.init_measurement = measure(pal_data.into(), pal_size);
        breakdown_outb(199);
        pal_range.unmount();
        pal_range.delete();
        log::debug!("TODO: Compare with pal measurement of the policy");

        let (manifest_data, manifest_range) = ProcessPageTableRef::copy_data_from_guest(manifest, manifest_size, pgt);
        log::debug!("manifest_range {:?}", manifest_range);
        base.add_manifest(manifest_data, manifest_size, manifest_range);
        breakdown_outb(198);
        measurements.manifest_measurement = measure(manifest_data.into(), manifest_size);
        breakdown_outb(199);
        manifest_range.unmount();
        manifest_range.delete();
        log::debug!("TODO: Compare with manifest measurement of the policy");

        let (libos_data, libos_range) = ProcessPageTableRef::copy_data_from_guest(libos, libos_size, pgt);
        log::debug!("libos_range {:?}", libos_range);
        base.add_libos(libos_data, libos_size, libos_range);
        breakdown_outb(198);
        measurements.libos_measurement = measure(libos_data.into(), libos_size);
        breakdown_outb(199);
        libos_range.unmount();
        libos_range.delete();
        log::debug!("TODO: Compare with libos measurement of the policy");
        breakdown_outb(201);
        let mut context = ProcessContext::default();
        context.early_init(base, measurements);
        breakdown_outb(202);
        Self {
            process_type: TrustedProcessType::Zygote,
            id: 0,
            parent_id: 0,
            base,
            measurements,
            context,
            mmap_manager: MmapManager::new(),
            pf_target_vaddr: 0,
        }
    }

    pub fn trustlet(parent: ProcessID, data: u64, size: u64, pgt: u64) -> Self{
        // Inherit the data from the Zygote
        breakdown_outb(203);
        let mut trustlet = TrustedProcess::dublicate(parent);
        breakdown_outb(204);
        if data != 0 {
            let (function_code, function_code_range) = ProcessPageTableRef::copy_data_from_guest(data, size, pgt);
            trustlet.base.alloc_range_function.0 = function_code_range.0;
            trustlet.base.alloc_range_function.1 = size;

            log::debug!("Measuring trustlet function");
            breakdown_outb(205);
            trustlet.measurements.function_measurement = measure(function_code.into(), size);
            breakdown_outb(206);
            log::debug!("TODO: Compare with function measurement of the policy");

            log::debug!("Adding trustlet function");
            let size = (4096 - (size & 0xFFF)) + size;
            trustlet.context.page_table_ref.add_function(function_code, size);
            function_code_range.unmount();
            function_code_range.delete();
            breakdown_outb(207);
        }
        trustlet
    }
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
            //context.early_init(base, measurements);



            // Insert it into the process store
            // Each process is identified with an idea from
            // the store
            let res = PROCESS_STORE.insert(z);

            let z = PROCESS_STORE.get(ProcessID(res.try_into().unwrap()));
            early_invoke(z);


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

impl ProcessContext {

    pub fn early_init(&mut self, base: ProcessBaseContext, measurements: ProcessMeasurements){

        let page_table_ref = base.page_table_ref;

        // Create VMSA for Zygote
        // Will be used as base for Trustlet VMSA
        let new_vmsa_page = allocate_page();
        let new_vmsa_mapping = PerCPUPageMappingGuard::create_4k(new_vmsa_page).unwrap();
        let new_vmsa_vaddr = new_vmsa_mapping.virt_addr();

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


        // Setup exception handlers

        setup_exceptions(vmsa, &page_table_ref);

        // ------ end of exception handlers setup

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
        //self.base = base;
        self.measurements = measurements;
        self.page_table_ref = page_table_ref;


    }

    /// This function is called to create a Trustlet from a Zygote
    pub fn init(&mut self, base: ProcessBaseContext, measurements: ProcessMeasurements, zygote_context: ProcessContext) {

        // Setup a new page table for the Process
        let mut new_page_table_ref = ProcessPageTableRef::default();
        new_page_table_ref.init_vmpl1();
        new_page_table_ref.copy_pgd(&zygote_context.page_table_ref);
        let page_table_ref = new_page_table_ref;

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
        let zygote_vmsa_mapping = PerCPUPageMappingGuard::create_4k(zygote_context.vmsa).unwrap();
        let zygote_vmsa_vaddr = zygote_vmsa_mapping.virt_addr();
        let zygote_vmsa = VMSA::from_virt_addr(zygote_vmsa_vaddr);
        *vmsa = *zygote_vmsa;

        //Trustlet VMSA Setup
        vmsa.cr3 = u64::from(page_table_ref.process_page_table);

        //Memory Channel setup -- No chain setup here
        let page_table_addr = vmsa.cr3;
        let mut pptr = ProcessPageTableRef::default();
        pptr.set_external_table(page_table_addr);
        self.channel.allocate_input(&mut pptr, PAGE_SIZE);
        self.channel.allocate_output(&mut pptr, PAGE_SIZE);
        pptr.handle_cow(VirtAddr::from(TP_KERN_STACK_START_VADDR), false);

        self.vmsa = new_vmsa_page;
        self.sev_features = vmsa.sev_features;
        self.base = base;
        self.measurements = measurements;
        self.page_table_ref = page_table_ref;
    }
}
