use core::arch::asm;

#[cfg(feature = "boottime")]
#[inline(always)]
pub fn outb(value: u64) {
    unsafe {
        asm!(
            "outb 0xF4",
            in("rax") value)
    };
}

#[cfg(not(feature = "boottime"))]
pub fn outb(value: u64) {
   return;
}
