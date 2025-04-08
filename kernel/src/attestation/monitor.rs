use crate::{address::PhysAddr, greq::services::{get_regular_report, REPORT_RESPONSE_SIZE} };
use crate::greq::pld_report::{SnpReportResponse, AttestationReport};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::mm::PerCPUPageMappingGuard;
use core::slice;
extern crate alloc;
use alloc::vec::Vec;
use crate::vaddr_as_u64_slice;

#[allow(unused_imports)]
use crate::my_crypto_wrapper::my_SHA512;
use crate::my_crypto_wrapper::my_Hacl_Ed25519_sign;
use crate::my_crypto_wrapper::get_keys;
use crate::my_crypto_wrapper::decrypt;
use crate::my_crypto_wrapper::key_pair;

use crate::process_manager::PROCESS_STORE;
use crate::process_manager::process::ProcessID;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::mm::PAGE_SIZE;

/* crates for attestation microbenchmarks */
use crate::process_manager::process_paging::{TP_MANIFEST_START_VADDR, TP_LIBOS_START_VADDR, TP_FUNCTION_START_VADDR};
use crate::process_manager::process_memory::ALLOCATION_RANGE_VIRT_START;
use crate::cpu::control_regs::{read_cr3};
use crate::address::Address;
use crate::process_manager::process_memory::{PGD, addr_to_idx};
use crate::cpu::flush_tlb_global;
/* end of crates for attestation microbenchmarks */

struct StoredSNPReport {
  data: Vec<u8>, // Dynamically sized to hold only the actual report
  size: usize,
}

static mut SNP_REPORT_STORE: Option<StoredSNPReport> = None;

fn store_snp_report(report_data: &[u8], report_size: usize) {
  unsafe {
    SNP_REPORT_STORE = Some(StoredSNPReport {
          data: report_data.to_vec(),
          size: report_size,
      });
  }
}

fn get_snp_report() -> Option<(&'static [u8], usize)> {
  unsafe {
      SNP_REPORT_STORE.as_ref().map(|report| (&report.data[..], report.size))
  }
}

const SIGNATURE_SIZE: usize = 64;
const HASH_SIZE: usize = 64;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

pub const MONITOR_ATTESTATION: u64 = 0;
const ZYGOTE_ATTESTATION: u64 = 1;
const TRUSTLET_ATTESTATION: u64 = 2;
const FUNCTION_ATTESTATION: u64 = 3;
/* helper attestation options for microbenchmarks */
pub const MONITOR_ATTESTATION_COLD: u64 = 4;
const PREPARE_ZYGOTE_ATTESTATION_COLD: u64 = 5;
const ZYGOTE_ATTESTATION_COLD: u64 = 6;
const PREPARE_TRUSTLET_ATTESTATION_COLD: u64 = 7;
const TRUSTLET_ATTESTATION_COLD: u64 = 8;
/* end of helper attestation options for microbenchmarks */

#[derive(Debug, Copy, Clone)]
pub struct ProcessMeasurements {
    pub init_measurement: [u8; 64],
    pub manifest_measurement: [u8; 64],
    pub libos_measurement: [u8; 64],
    pub function_measurement: [u8; 64],
    pub input_data: [u8; 64],
    pub output_data: [u8; 64],
}

impl Default for ProcessMeasurements {
    fn default() -> Self {
        return ProcessMeasurements {
            init_measurement: [0; HASH_SIZE],
            manifest_measurement: [0; HASH_SIZE],
            libos_measurement: [0; HASH_SIZE],
            function_measurement: [0; HASH_SIZE],
            input_data: [0; HASH_SIZE],
            output_data: [0; HASH_SIZE],
        }
    }
}

#[cfg(not(feature = "boottime"))]
#[allow(non_snake_case)]
pub fn measure(start_address: u64, size: u64) -> [u8; HASH_SIZE] {

    // Unsafe part: ensure the memory region is accessible and valid
    let region = unsafe {
        core::slice::from_raw_parts(start_address as *const u8, size as usize)
    };
    log::debug!("[Measure] Region address {:p} and len { }", region, region.len());

    let mut hash: [u8; HASH_SIZE] = [0; HASH_SIZE];
    // Get the hash using SHA-512 over the entire memory region
    unsafe {
        my_SHA512(
            region.as_ptr() as *mut u8,
            region.len().try_into().unwrap(),
            hash.as_mut_ptr(),
        );
    }
    log::debug!("[Measure] resulting hash {:?}", hash);
    // Return the final hash measurement
    hash
}

fn sign_report(report: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let report_addr = report.as_ptr() as u64; // Convert the pointer to u64
    let report_size = report.len() as u64;   // Get the size of the report

    // Use a dummy private key for development
    // TODO: Use the function provider private key used for communication with the client
    let dummy_private_key: [u8; KEY_SIZE] = [0x69; KEY_SIZE];

    // Sign the report
    let mut signature: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];
    unsafe {
        my_Hacl_Ed25519_sign(
            report_addr as *const u8,
            report_size.try_into().unwrap(),
            dummy_private_key.as_ptr(),
            signature.as_mut_ptr(),
        );
    }

    // Return the signature
    signature
}

#[cfg(feature = "boottime")]
pub fn measure(_start_address: u64, _size: u64) -> [u8; HASH_SIZE] {
    let hash: [u8; HASH_SIZE] = [0; HASH_SIZE];
    hash
}

fn copy_back_report(report_buffer: u64, report_data: &[u8], report_size: usize) {
  // Ensure the size is within limits to avoid out-of-bounds access
  assert!(report_size <= PAGE_SIZE, "Report size exceeds the allowed page size.");

  let report_address = PhysAddr::from(report_buffer);
  let mapped_report_page = PerCPUPageMappingGuard::create_4k(report_address).unwrap();
  let report = unsafe {
        mapped_report_page.virt_addr()
            .as_mut_ptr::<[u8; PAGE_SIZE]>()
            .as_mut()
            .unwrap()
    };
  report[0..report_size].copy_from_slice(&report_data[0..report_size]);
}

#[allow(non_snake_case)]
fn monitor_report(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    if let Some((stored_report, stored_report_size)) = get_snp_report() {
        // If the report exists, just return it
        log::debug!("Monitor has cached the SNP report");
        copy_back_report(params.rcx, stored_report, stored_report_size);
    } else {
        // The report does not exist so, retrieve and store the Original SNP report
        log::debug!("Monitor retrieves the SNP report");
        let mut rep: [u8; REPORT_RESPONSE_SIZE] = [0; REPORT_RESPONSE_SIZE];

        /* Get a regular report of type struct SnpReportResponse */
        let _rep_struct_size = match get_regular_report(&mut rep) {
            Ok(e) => e,
            Err(e) => {
                log::info!("Error from get report: {:?}", e);
                panic!();
            }
        };

        // Cast the raw bytes into an SnpReportResponse
        let snp_response: &SnpReportResponse = unsafe {
          &*(rep.as_ptr() as *const SnpReportResponse)
        };

        // Check the response for validation
        match snp_response.validate() {
          Ok(e) => e,
          Err(e) => {
              log::info!("Invalid SNP report: {:?}", e);
              panic!();
          }
        };

        let report_size = snp_response.get_report_size() as usize;
        let report = snp_response.get_report();
        log::debug!("actual report size { }", snp_response.get_report_size());

        let report_bytes = unsafe {
          core::slice::from_raw_parts(
              (report as *const AttestationReport) as *const u8,
              report_size,
          )
        };

        // Store the report and its size
        store_snp_report(report_bytes, report_size);

        // Return the report (if requested)
        if params.rcx != 0 {
            copy_back_report(params.rcx, report_bytes, report_size);
        }
    }
    Ok(())
}

#[allow(non_snake_case)]
fn zygote_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let zygote_id = ProcessID(params.r8 as usize);
    let zygote = PROCESS_STORE.get(zygote_id);

    let init_measurement = zygote.measurements.init_measurement;
    let manifest_measurement = zygote.measurements.manifest_measurement;
    let libos_measurement = zygote.measurements.libos_measurement;
    let function_measurement = zygote.measurements.function_measurement;

    // Construct the new report
    let mut new_report: Vec<u8> = Vec::new();

    if let Some((existing_report, _existing_report_size)) = get_snp_report() {
        // Copy the existing report data into the new report
        new_report.extend_from_slice(existing_report);
    }
    else {
        log::info!("SNP report is missing");
        panic!();
    }

    // Append the measurements to the new report
    new_report.extend_from_slice(&init_measurement);
    new_report.extend_from_slice(&manifest_measurement);
    new_report.extend_from_slice(&libos_measurement);
    new_report.extend_from_slice(&function_measurement);

    // Now new_report holds the existing report data + measurements
    let new_report_size = new_report.len();

    // Perform the copy_back_report with the new cumulative report
    if params.rcx != 0 {
        copy_back_report(params.rcx, &new_report, new_report_size);
    }
    return Ok(());
}

#[allow(non_snake_case)]
fn trustlet_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let trustlet_id = ProcessID(params.r8 as usize);
    let trustlet = PROCESS_STORE.get(trustlet_id);

    let init_measurement = trustlet.measurements.init_measurement;
    let manifest_measurement = trustlet.measurements.manifest_measurement;
    let libos_measurement = trustlet.measurements.libos_measurement;
    let function_measurement = trustlet.measurements.function_measurement;

    // Construct the new report
    let mut new_report: Vec<u8> = Vec::new();

    if let Some((existing_report, _existing_report_size)) = get_snp_report() {
        // Copy the existing report data into the new report
        new_report.extend_from_slice(existing_report);
    }
    else {
        log::info!("SNP report is missing");
        panic!();
    }

    // Append the measurements to the new report
    new_report.extend_from_slice(&init_measurement);
    new_report.extend_from_slice(&manifest_measurement);
    new_report.extend_from_slice(&libos_measurement);
    new_report.extend_from_slice(&function_measurement);

    // Now new_report holds the existing report data + measurements
    let new_report_size = new_report.len();

    // Perform the copy_back_report with the new cumulative report
    if params.rcx != 0 {
        copy_back_report(params.rcx, &new_report, new_report_size);
    }

    return Ok(());
}

#[allow(non_snake_case)]
fn function_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let guest_pgt = params.r8;
    let size = PAGE_SIZE;
    let function_data_addr = params.r9;
    let (function_data, allocation) = ProcessPageTableRef::copy_data_from_guest(function_data_addr, (size).try_into().unwrap(), guest_pgt);

    // Extract the parameters from the struct
    let function_data_struct = vaddr_as_u64_slice!(function_data);
    let trustlet_id = function_data_struct[0];
    let fn_input_size = function_data_struct[1];
    let fn_input_addr = function_data_struct[2];
    let fn_output_size = function_data_struct[3];
    let fn_output_addr = function_data_struct[4];
    log::debug!("Extracted values { } { } { } { } { }", trustlet_id, fn_input_size, fn_input_addr, fn_output_size, fn_output_addr);

    allocation.unmount();
    allocation.delete();

    // Get the parent process of the function
    let trustlet_id = ProcessID(trustlet_id as usize);
    let trustlet = PROCESS_STORE.get(trustlet_id);

    let init_measurement = trustlet.measurements.init_measurement;
    let manifest_measurement = trustlet.measurements.manifest_measurement;
    let libos_measurement = trustlet.measurements.libos_measurement;
    let function_measurement = trustlet.measurements.function_measurement;

    // Get and measure the input data of the function
    let (input_data, allocation) = ProcessPageTableRef::copy_data_from_guest(fn_input_addr, fn_input_size, guest_pgt);
    let input_hash = measure(input_data.into(), fn_input_size);
    allocation.unmount();
    allocation.delete();

    // Get and measure the output data of the function
    let (output_data, allocation) = ProcessPageTableRef::copy_data_from_guest(fn_output_addr, fn_output_size, guest_pgt);
    let output_hash = measure(output_data.into(), fn_output_size);
    allocation.unmount();
    allocation.delete();

    // Construct the new report
    let mut new_report: Vec<u8> = Vec::new();

    if let Some((existing_report, _existing_report_size)) = get_snp_report() {
      // Copy the existing report data into the new report
      new_report.extend_from_slice(existing_report);
    }
    else {
        log::info!("SNP report is missing");
        panic!();
    }

    // Append the measurements to the new report
    new_report.extend_from_slice(&init_measurement);
    new_report.extend_from_slice(&manifest_measurement);
    new_report.extend_from_slice(&libos_measurement);
    new_report.extend_from_slice(&function_measurement);
    new_report.extend_from_slice(&input_hash);
    new_report.extend_from_slice(&output_hash);

    // Now new_report holds the existing report data + measurements
    let new_report_size = new_report.len();

    // Sign the new report with a dummy private key
    let signature = sign_report(&new_report);
    new_report.extend_from_slice(&signature);

    // Perform the copy_back_report with the new cumulative report
    if params.rcx != 0 {
        copy_back_report(params.rcx, &new_report, new_report_size + signature.len());
    }

    return Ok(());
}

#[allow(non_snake_case)]
pub fn diff_attestation(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    match params.rdx {
        MONITOR_ATTESTATION => {
            log::debug!("[Performing monitor attestation]");
            let _ = monitor_report(params);
        }
        ZYGOTE_ATTESTATION => {
            log::debug!("[Performing zygote {} attestation]", params.r8);
            let _ = zygote_report(params);
        }
        TRUSTLET_ATTESTATION => {
            log::debug!("[Performing trustlet {} attestation]", params.r8);
            let _ = trustlet_report(params);
        }
        FUNCTION_ATTESTATION => {
            log::debug!("[Performing function attestation]");
            let _ = function_report(params);
        }
        /* helper attestation options for microbenchmarks */
        MONITOR_ATTESTATION_COLD => {
            log::debug!("[Performing monitor cold report generation]");
            let _ = monitor_report_cold(params);
        }
        PREPARE_ZYGOTE_ATTESTATION_COLD => {
            log::debug!("[Preparing zygote {} cold report generation]", params.r8);
            let _ = prepare_zygote_report_cold(params);
        }
        ZYGOTE_ATTESTATION_COLD => {
            log::debug!("[Performing zygote {} cold report generation]", params.r8);
            let _ = zygote_report_cold(params);
        }
        PREPARE_TRUSTLET_ATTESTATION_COLD => {
            log::debug!("[Preparing trustlet {} cold report generation]", params.r8);
            let _ = prepare_trustlet_report_cold(params);
        }
        TRUSTLET_ATTESTATION_COLD => {
            log::debug!("[Performing trustlet {} cold report generation]", params.r8);
            let _ = trustlet_report_cold(params);
        }
        /* end of helper attestation options for microbenchmarks */
        _ => {
            log::info!("[Unknown attestation request type]");
        }
    }
    return Ok(());
}

#[allow(non_snake_case)]
pub fn get_public_key(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    //log::info!("[Monitor] Getting public key");

    let encryption_keys: key_pair = unsafe{*get_keys()};

    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};

    let mut i: usize = 0;
    while i < KEY_SIZE {
        target[i] = encryption_keys.public_key[i];
        i = i + 1;
    }   
    target[KEY_SIZE] = 0;
   
  Ok(())  
}

pub fn exec_elf(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // TODO: Get the PA of the 2 pages, copy contents 2 contiguous array.
    // Use the ELF read functions on the array and inspect the results
    // See how to execute the ELF. Modify a register and read it from monitor to verify program
    // execution
    // Create a nicer API for transfering ELF files to monitor.
    log::info!("Monitor received elf");
    let page1_address = PhysAddr::from(params.r8);
    let page1 = PerCPUPageMappingGuard::create_4k(page1_address).unwrap();
    let page1_data = unsafe {page1.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};

    let page2_address = PhysAddr::from(params.rcx);
    let page2 = PerCPUPageMappingGuard::create_4k(page2_address).unwrap();
    let page2_data = unsafe {page2.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};

    let elf_size : u32 = params.rdx.try_into().unwrap();

    log::info!("[Monitor] Elf size: {}", elf_size);

    //copy elf in contiguous array
    let mut elf_raw_data : [u8; PAGE_SIZE * 2] = [0; PAGE_SIZE * 2];

    let mut i = 0;
    while i < PAGE_SIZE {
        elf_raw_data[i] = page1_data[i];
        elf_raw_data[i + PAGE_SIZE] = page2_data[i];
        i = i + 1;
    }

    let elf_buf = unsafe { slice::from_raw_parts(elf_raw_data.as_ptr(), elf_size.try_into().unwrap()) };
    let elf = match elf::Elf64File::read(elf_buf) {
        Ok(elf) => elf,
        Err(e) => panic!("error reading ELF: {}", e),
    };
    log::info!("Elf file: {:?}", elf);
    Ok(())
}

// TODO: For now monitor just receives the policy here and decrypts it. Probablly want to do more with it!
pub fn send_policy(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    log::info!("[Monitor] Receiveing policy");
    let encrypted_data_address = PhysAddr::from(params.r8);
    let mapped_enc_data_page = PerCPUPageMappingGuard::create_4k(encrypted_data_address).unwrap();
    let encrypted_data = unsafe {mapped_enc_data_page.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};

    let sender_pub_key_address = PhysAddr::from(params.rcx);
    let mapped_sender_pub_key_page = PerCPUPageMappingGuard::create_4k(sender_pub_key_address).unwrap();
    let sender_pub_key = unsafe {mapped_sender_pub_key_page.virt_addr().as_mut_ptr::<[u8;32]>().as_mut().unwrap()};

    let encrypted_data_size: u32 = params.rdx.try_into().unwrap();
    let mut decrypted: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

    let mut nonce: [u8; NONCE_SIZE] = [0; NONCE_SIZE];
    let _n: u32 = unsafe{decrypt(decrypted.as_mut_ptr(), encrypted_data.as_mut_ptr(),
                                encrypted_data_size , nonce.as_mut_ptr(),
                                sender_pub_key.as_mut_ptr(), (*get_keys()).private_key.as_mut_ptr())};
    Ok(())
}

/* helper report generation options for attestation microbenchmarks */
#[allow(non_snake_case)]
fn monitor_report_cold(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    // The report does not exist so, retrieve and store the Original SNP report
    log::debug!("Monitor retrieves the SNP report");
    let mut rep: [u8; REPORT_RESPONSE_SIZE] = [0; REPORT_RESPONSE_SIZE];

    /* Get a regular report of type struct SnpReportResponse */
    let _rep_struct_size = match get_regular_report(&mut rep) {
        Ok(e) => e,
        Err(e) => {
            log::info!("Error from get report: {:?}", e);
            panic!();
        }
    };

    // Cast the raw bytes into an SnpReportResponse
    let snp_response: &SnpReportResponse = unsafe {
      &*(rep.as_ptr() as *const SnpReportResponse)
    };

    // Check the response for validation
    match snp_response.validate() {
      Ok(e) => e,
      Err(e) => {
          log::info!("Invalid SNP report: {:?}", e);
          panic!();
      }
    };

    let report_size = snp_response.get_report_size() as usize;
    let report = snp_response.get_report();
    log::debug!("actual report size { }", snp_response.get_report_size());

    let report_bytes = unsafe {
      core::slice::from_raw_parts(
          (report as *const AttestationReport) as *const u8,
          report_size,
      )
    };

    // Return the report (if requested)
    if params.rcx != 0 {
        copy_back_report(params.rcx, report_bytes, report_size);
    }
    Ok(())
}

#[allow(non_snake_case)]
fn prepare_zygote_report_cold(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let zygote_id = ProcessID(params.r8 as usize);
    let zygote = PROCESS_STORE.get(zygote_id);

    // we need to mount the allocation range for the init to have a valid translation
    // for the ALLOCATION_RANGE_VIRT_START address
    zygote.base.alloc_range.mount();
    //let init_ptr = ALLOCATION_RANGE_VIRT_START; //zygote.base.alloc_range.0;
    let manifest_ptr = TP_MANIFEST_START_VADDR; //zygote.base.alloc_range_manifest.0;
    let libos_ptr = TP_LIBOS_START_VADDR; //zygote.base.alloc_range_libos.0;

    // Getting the monitor page table ref
    let monitor_cr3 = read_cr3().bits() as u64;
    let monitor_cr3_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(monitor_cr3)).unwrap();
    let monitor_pgd_table = vaddr_as_u64_slice!(monitor_cr3_mapping.virt_addr());

    // Getting the zygote page table ref
    let zygote_cr3 = zygote.base.page_table_ref.process_page_table;
    let zygote_cr3_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(zygote_cr3)).unwrap();
    let zygote_pgd_table = vaddr_as_u64_slice!(zygote_cr3_mapping.virt_addr());

    // Get the page table indices for each entry
    // let monitor_init_pgd_idx = addr_to_idx(init_ptr as usize, PGD);
    // let zygote_init_pgd_idx = addr_to_idx(init_ptr as usize, PGD);
    let monitor_manifest_pgd_idx = addr_to_idx(manifest_ptr as usize, PGD);
    let zygote_manifest_pgd_idx = addr_to_idx(manifest_ptr as usize, PGD);
    let monitor_libos_pgd_idx = addr_to_idx(libos_ptr as usize, PGD);
    let zygote_libos_pgd_idx = addr_to_idx(libos_ptr as usize, PGD);

    // Update monitors's pgd entry
    // Note that for the init, the monitor's pgd entry is updated through the mount
    // monitor_pgd_table[monitor_init_pgd_idx] = zygote_pgd_table[zygote_init_pgd_idx];
    monitor_pgd_table[monitor_manifest_pgd_idx] = zygote_pgd_table[zygote_manifest_pgd_idx];
    monitor_pgd_table[monitor_libos_pgd_idx] = zygote_pgd_table[zygote_libos_pgd_idx];

    // Flush tlb
    flush_tlb_global();

    return Ok(());
}

#[allow(non_snake_case)]
fn zygote_report_cold(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let zygote_id = ProcessID(params.r8 as usize);
    let zygote = PROCESS_STORE.get(zygote_id);

    let init_ptr = ALLOCATION_RANGE_VIRT_START;//zygote.base.alloc_range.0;
    let init_size = zygote.base.alloc_range.1;
    let manifest_ptr = TP_MANIFEST_START_VADDR;//zygote.base.alloc_range_manifest.0;
    let manifest_size = zygote.base.alloc_range_manifest.1;
    let libos_ptr = TP_LIBOS_START_VADDR;//zygote.base.alloc_range_libos.0;
    let libos_size = zygote.base.alloc_range_libos.1;

    // calculate the measurements
    let manifest_measurement = measure(manifest_ptr.into(), manifest_size);
    let libos_measurement = measure(libos_ptr.into(), libos_size);
    let init_measurement = measure(init_ptr.into(), init_size);
    let function_measurement = zygote.measurements.function_measurement;

    // Construct the new report
    let mut new_report: Vec<u8> = Vec::new();

    if let Some((existing_report, _existing_report_size)) = get_snp_report() {
        // Copy the existing report data into the new report
        new_report.extend_from_slice(existing_report);
    }
    else {
        log::info!("SNP report is missing");
        panic!();
    }

    // Append the measurements to the new report
    new_report.extend_from_slice(&init_measurement);
    new_report.extend_from_slice(&manifest_measurement);
    new_report.extend_from_slice(&libos_measurement);
    new_report.extend_from_slice(&function_measurement);

    // Now new_report holds the existing report data + measurements
    let new_report_size = new_report.len();

    // Perform the copy_back_report with the new cumulative report
    if params.rcx != 0 {
        copy_back_report(params.rcx, &new_report, new_report_size);
    }
    zygote.base.alloc_range.unmount();
    return Ok(());
}

#[allow(non_snake_case)]
fn prepare_trustlet_report_cold(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let trustlet_id = ProcessID(params.r8 as usize);
    let trustlet = PROCESS_STORE.get(trustlet_id);

    let function_ptr = TP_FUNCTION_START_VADDR;

    // Getting the monitor page table ref
    let monitor_cr3 = read_cr3().bits() as u64;
    let monitor_cr3_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(monitor_cr3)).unwrap();
    let monitor_pgd_table = vaddr_as_u64_slice!(monitor_cr3_mapping.virt_addr());

    // Getting the trustlet page table ref
    let trustlet_cr3 = trustlet.context.page_table_ref.process_page_table;
    let trustlet_cr3_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(trustlet_cr3)).unwrap();
    let trustlet_pgd_table = vaddr_as_u64_slice!(trustlet_cr3_mapping.virt_addr());

    let monitor_function_pgd_idx = addr_to_idx(function_ptr as usize, PGD);
    let trustlet_function_pgd_idx = addr_to_idx(function_ptr as usize, PGD);

    monitor_pgd_table[monitor_function_pgd_idx] = trustlet_pgd_table[trustlet_function_pgd_idx];

    return Ok(());
}

#[allow(non_snake_case)]
fn trustlet_report_cold(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let trustlet_id = ProcessID(params.r8 as usize);
    let trustlet = PROCESS_STORE.get(trustlet_id);

    let function_ptr = TP_FUNCTION_START_VADDR;
    let function_size = trustlet.base.alloc_range_function.1;

    let init_measurement = trustlet.measurements.init_measurement;
    let manifest_measurement = trustlet.measurements.manifest_measurement;
    let libos_measurement = trustlet.measurements.libos_measurement;
    let function_measurement = measure(function_ptr.into(), function_size);

    // Construct the new report
    let mut new_report: Vec<u8> = Vec::new();

    if let Some((existing_report, _existing_report_size)) = get_snp_report() {
        // Copy the existing report data into the new report
        new_report.extend_from_slice(existing_report);
    }
    else {
        log::info!("SNP report is missing");
        panic!();
    }

    // Append the measurements to the new report
    new_report.extend_from_slice(&init_measurement);
    new_report.extend_from_slice(&manifest_measurement);
    new_report.extend_from_slice(&libos_measurement);
    new_report.extend_from_slice(&function_measurement);

    // Now new_report holds the existing report data + measurements
    let new_report_size = new_report.len();

    // Perform the copy_back_report with the new cumulative report
    if params.rcx != 0 {
        copy_back_report(params.rcx, &new_report, new_report_size);
    }

    return Ok(());
}
/* end of helper report generation options for attestation microbenchmarks */
