use crate::mm::PAGE_SIZE;
use crate::process_manager::process_memory::ALLOCATION_RANGE_VIRT_START;
use super::{allocation::AllocationRange, process::ProcessID, process_paging::ProcessPageTableRef};

pub const INPUT_VADDR: u64 = 0x280_0000_0000u64;
pub const OUTPUT_VADDR: u64 = 0x300_0000_0000u64;

#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryChannel {
    pub input: AllocationRange,
    pub output: AllocationRange,
    pub owner: ProcessID,
    pub last_in_channel: bool,
    pub next: ProcessID,
}

impl MemoryChannel {

    pub fn allocate_input(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize) {
        self.input = self.allocate_range(page_table_ref, size, INPUT_VADDR);
    }

    pub fn allocate_output(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize) {
        self.output = self.allocate_range(page_table_ref, size, OUTPUT_VADDR);
    }

    pub fn inflate_input(&mut self, page_table: u64, size: usize) {
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);
        let page_count = (size + PAGE_SIZE - (size % PAGE_SIZE)) / PAGE_SIZE;
        self.input.inflate(&mut page_table_ref, page_count as u64, INPUT_VADDR);
    }

    pub fn inflate_output(&mut self, page_table: u64, size: usize) {
        let mut page_table_ref = &mut ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);
        let page_count = (size + PAGE_SIZE - (size % PAGE_SIZE)) / PAGE_SIZE;
        self.output.inflate(&mut page_table_ref, page_count as u64, OUTPUT_VADDR);
    }

    pub fn copy_into(&mut self, source_addr: u64, page_table: u64, size: usize) {
        self.input.mount();
        ProcessPageTableRef::copy_data_from_guest_to(source_addr, size as u64, page_table, ALLOCATION_RANGE_VIRT_START);
        self.input.unmount();
    }

    pub fn copy_out(&mut self, target_addr: u64, page_table: u64, size: usize) {
        let copy_size = size + PAGE_SIZE - (size % PAGE_SIZE);
        self.output.mount();
        ProcessPageTableRef::copy_data_to_guest(target_addr, copy_size as u64, page_table);
        self.output.unmount();
    }

    #[cfg(not(feature = "boottime"))]
    pub fn measure_input(&self) -> [u8; 64] {
        use crate::attestation::monitor::measure;
        use igvm_defs::PAGE_SIZE_4K;
        self.input.mount();
        let size = self.input.1 * PAGE_SIZE_4K;
        let res = measure(ALLOCATION_RANGE_VIRT_START, size);
        self.input.unmount();
        return res;
    }

    #[cfg(not(feature = "boottime"))]
    pub fn measure_output(&self) -> [u8; 64] {
        use crate::attestation::monitor::measure;
        use igvm_defs::PAGE_SIZE_4K;
        self.output.mount();
        let size = self.output.1 * PAGE_SIZE_4K;
        let res =  measure(ALLOCATION_RANGE_VIRT_START, size);
        self.output.unmount();
        return res;
    }

    fn allocate_range(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize, start: u64) -> AllocationRange{
        let mut r = AllocationRange::default();
        let page_count = (size + PAGE_SIZE - (size % PAGE_SIZE)) / PAGE_SIZE;
        r.allocate_with_start_addr(page_table_ref, page_count as u64, start);
        return r;
    }

}
