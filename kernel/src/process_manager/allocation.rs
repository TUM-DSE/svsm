use crate::cpu::flush_tlb_global;
use crate::process_manager::process_memory::{allocate_page, free_page};
use crate::mm::PAGE_SIZE;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::process_manager::process_paging::{ProcessPageTableEntry, ProcessPageTablePage, ProcessPageTableRef};
use crate::process_manager::process_paging::ProcessPageFlags;
use super::process_memory::PGD;
use crate::cpu::control_regs::read_cr3;
use crate::sev::{rmp_adjust, RMPFlags};
use crate::types::PageSize;
use crate::{paddr_as_slice, map_paddr, vaddr_as_slice, paddr_as_table, strip_paddr};
use crate::process_manager::memory_helper::strip_c_bit;
use crate::mm::PerCPUPageMappingGuard;

const ALLOCATION_VADDR_START: u64 = 0x30000000000u64;
pub const DEFAULT_ALLOCATION_RANGE_MOUNT: usize = 6;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocationRange(pub u64, pub u64);

impl AllocationRange {

    pub fn allocate(&mut self, pages: u64){
        // Allocates a new memory range for the Monitor
        // Currently the start virtual address is fixed to ALLOCATION_RANGE_VIRT_START
        // Reuses the Process page managment to add new memory to the Monitor
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(read_cr3().bits() as u64);
        self.allocate_(&mut page_table_ref, pages, ALLOCATION_VADDR_START, true, false);
    }

    pub fn allocate_with_start_addr(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64){
        self.allocate_(page_table_ref, pages, start_addr, false, true);
    }

    fn allocate_(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64, mount: bool, user: bool){
        // Reuses the Process page managment to add new memory to the Monitor
        //let mut page_table_ref = ProcessPageTableRef::default();
        //page_table_ref.set_external_table(read_cr3().bits() as u64);
        let mut table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
        ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED;

        if user {
            table_flags = table_flags | ProcessPageFlags::USER_ACCESSIBLE;
        }

        let start_address = VirtAddr::from(start_addr);

        for i in 0..(pages as usize) {
            let current_page = allocate_page();
            if !mount {
                let (mapping, _page_mapped) = paddr_as_slice!(current_page);
                let _ = rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular);
            }
            page_table_ref.map_4k_page(start_address + i * PAGE_SIZE, current_page, table_flags);
        };
        if mount {
            let (_mapping, pgd) = paddr_as_slice!(read_cr3());
            self.0 = pgd[DEFAULT_ALLOCATION_RANGE_MOUNT];
            self.1 = pages;
        } else {
            let offset: usize = start_address.to_pgtbl_idx::<PGD>();
            let (_mapping, pgd) = paddr_as_slice!(page_table_ref.process_page_table);
            self.0 = pgd[offset];
            self.1 = pages;
        }
        flush_tlb_global();
    }

    pub fn inflate(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64) {
        if self.1 >= pages {
            return;
        }
        let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
        ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED | ProcessPageFlags::USER_ACCESSIBLE;
        let start_address = VirtAddr::from(start_addr);
        let begin = self.1 as usize;
        for i in begin..(pages as usize) {
            let current_page = allocate_page();
            let (mapping, _page_mapped) = paddr_as_slice!(current_page);
            let _ = rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular);
            page_table_ref.map_4k_page(start_address + i * PAGE_SIZE, current_page, table_flags);
        }
        self.1 = pages;
    }

    pub fn mount(&self) {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        pgd[DEFAULT_ALLOCATION_RANGE_MOUNT] = self.0;
        flush_tlb_global();
    }

    pub fn unmount(&self) {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        pgd[DEFAULT_ALLOCATION_RANGE_MOUNT] = 0;
        flush_tlb_global();

    }

    pub fn mount_at(&self, loc: usize) -> u64 {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        let old_table = pgd[loc];
        pgd[loc] = self.0;
        return old_table;
    }

    pub fn reset_mount(&self, loc: usize, t: u64) {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        pgd[loc] = t;
    }

    pub fn delete(self) {
        let pgd_table_entry = ProcessPageTableEntry(PhysAddr::from(self.0));
        let (_mapping, pud_table) = paddr_as_table!(strip_paddr!(pgd_table_entry.0));
        for i in 0..512 {
            let pud_table_entry = pud_table[i];
            if !pud_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                break
            }

            let (_mapping, pmd_table) = paddr_as_table!(strip_paddr!(pud_table_entry.0));
            for i in 0..512 {
                let pmd_table_entry = pmd_table[i];
                if !pmd_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                    break
                }

                let (_mapping, pte_table) = paddr_as_table!(strip_paddr!(pmd_table_entry.0));
                for i in 0..512 {
                    let pte_table_entry = pte_table[i];
                    if !pte_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                        break
                    }

                    free_page(strip_paddr!(pte_table_entry.0));
                }
                free_page(strip_paddr!(pmd_table_entry.0));
            }
            free_page(strip_paddr!(pud_table_entry.0));
        }
        free_page(strip_paddr!(pgd_table_entry.0));
    }
}
