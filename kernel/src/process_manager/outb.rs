use core::arch::asm;

pub fn outb(value: u64) {
    unsafe {
        asm!(
            "outb 0xF4",
            in("rax") value)
    };


}
