use core::arch::asm;

#[cfg(any(feature = "boottime", feature = "bench_mem"))]
#[inline(always)]
pub fn outb(value: u64) {
    unsafe {
        asm!(
            "outb 0xF4",
            in("rax") value)
    };
}

#[cfg(not(any(feature = "boottime", feature = "bench_mem")))]
#[inline(always)]
pub fn outb(value: u64) {
   return;
}
