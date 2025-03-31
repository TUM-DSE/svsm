#[allow(unused_imports)]
use core::arch::asm;

#[cfg(any(feature = "boottime", feature = "bench_mem", feature = "breakdown"))]
#[inline(always)]
pub fn outb(value: u64) {
    unsafe {
        asm!(
            "outb 0xF4",
            in("rax") value)
    };
}

#[cfg(not(any(feature = "boottime", feature = "bench_mem", feature = "breakdown")))]
#[inline(always)]
pub fn outb(_value: u64) {
   return;
}

#[cfg(not(feature = "breakdown"))]
#[inline(always)]
pub fn breakdown_outb(_value: u64) {
    return;
}

#[cfg(feature = "breakdown")]
#[inline(always)]
pub fn breakdown_outb(value: u64) {
    outb(value);
}
