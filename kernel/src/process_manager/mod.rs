use memory_helper::set_ecryption_mask_address_size;
use process_memory::additional_monitor_memory_init;

#[cfg(feature = "bench_mem")]
use process_memory::bench_mem;

#[cfg(feature = "prealloc")]
use process_memory::preallocate_memory;

pub use process::PROCESS_STORE;

use crate::utils::immut_after_init::ImmutAfterInitCell;

pub mod call_handler;
pub mod process;
pub mod process_memory;
pub mod process_paging;
pub mod memory_helper;
pub mod allocation;
pub mod memory_channels;
pub mod outb;
pub mod exception_handling;

static MONITOR_INIT_STATE: ImmutAfterInitCell<bool> = ImmutAfterInitCell::new(false);
const MONITOR_INIT_STATE_TRUE: bool = true;
pub const PROCESS_STORE_SIZE: u32 = 64;

pub fn monitor_init(){
    if *MONITOR_INIT_STATE {
        let _ = additional_monitor_memory_init();
        return;
    }
    set_ecryption_mask_address_size();
    let _ = additional_monitor_memory_init();
    PROCESS_STORE.init(PROCESS_STORE_SIZE);
    let _ = MONITOR_INIT_STATE.reinit(&MONITOR_INIT_STATE_TRUE);

    #[cfg(feature = "bench_mem")]
    bench_mem();

    #[cfg(feature = "prealloc")]
    preallocate_memory();
}
