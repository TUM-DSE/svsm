
use crate::cpu::tss::{X86Tss,TSS_LIMIT};
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::cpu::idt::common::{IdtEntry, DF_VECTOR, IDT, PF_VECTOR, GP_VECTOR};
use crate::cpu::gdt::{GDTEntry, GDT};
use crate::mm::PerCPUPageMappingGuard;
use crate::process_manager::process_memory::allocate_page;
use core::arch::global_asm;
use cpuarch::vmsa::{VMSASegment, VMSA};
use crate::process_manager::process_paging::ProcessPageFlags;
use crate::address::PhysAddr;
use crate::types::PageSize;
use crate::sev::RMPFlags;
use crate::sev::rmp_adjust;
use super::process_paging::TP_KERN_STACK_START_VADDR;
use crate::cpu::control_regs::read_cr3;
use crate::process_manager::process_paging::ProcessPageTableRef;

// FIXME: Allocarte the GDT, IDT, and TSS in a dedicated page
/// GDT for Trustlets (shared between all Trustlets)
static GDT_TRUSTLET: RWLock<GDT> = RWLock::new(GDT::new());

pub fn gdt_trustlet() -> ReadLockGuard<'static, GDT> {
    GDT_TRUSTLET.lock_read()
}

pub fn gdt_trustlet_mut() -> WriteLockGuard<'static, GDT> {
    GDT_TRUSTLET.lock_write()
}

/// IDT for Trustlets (shared between all Trustlets)
static IDT_TRUSTLET: RWLock<IDT> = RWLock::new(IDT::new());

pub fn idt_trustlet() -> ReadLockGuard<'static, IDT> {
    IDT_TRUSTLET.lock_read()
}

pub fn idt_trustlet_mut() -> WriteLockGuard<'static, IDT> {
    IDT_TRUSTLET.lock_write()
}

/// TSS for Trustlets
// FIXME: the current implementation use the same TSS for all Trustlets. This works because
// the only one Trustlet runs at a time.
static TSS_TRUSTLET: RWLock<X86Tss> = RWLock::new(X86Tss::new());

pub fn tss_trustlet() -> ReadLockGuard<'static, X86Tss> {
    TSS_TRUSTLET.lock_read()
}

pub fn tss_trustlet_mut() -> WriteLockGuard<'static, X86Tss> {
    TSS_TRUSTLET.lock_write()
}

global_asm!(
    r#"
    .align 4096
    .code64
    .section .text
    .global asm_entry_trustlet_pf
    asm_entry_trustlet_pf:
        pushq %rcx
        movq $14, %rcx
        jmp asm_entry_with_error_code

    asm_entry_with_error_code:
       # #PF pushes the error code on the stack
       pushq %rax
       pushq %rbx
       movq 24(%rsp), %rbx      # load error code
       movq $0x4EFFFFFF, %rax   # monitor call number
       cpuid                    # call the monitor

       movq %cr2, %rax          # load faulting address
       invlpg (%rax)            # invalidate the page

       popq %rbx
       popq %rax
       popq %rcx
       addq $8, %rsp            # remove error code

       iretq

    .global asm_entry_trustlet_gp
    asm_entry_trustlet_gp:
        # #GP pushes the error code on the stack
        pushq %rcx
        movq $13, %rcx
        jmp asm_entry_with_error_code

    .global asm_entry_trustlet_df
    asm_entry_trustlet_df:
       # #DF pushes the error code on the stack
       pushq %rax
       pushq %rbx
       pushq %rcx
       movq 24(%rsp), %rbx      # load error code
       movq $0x4EFFFFFE, %rax   # monitor call number
       sgdt gdt_desc(%rip)      # store current GDT
       lea gdt_desc(%rip), %rcx
       cpuid
       /* no return */

    # debug
    .section .data
    .global gdt_desc
    gdt_desc:
    .word gdt_entry_end - gdt_entry - 1 # 2 bytes for the GDT limit
    .quad gdt_entry                     # 8 bytes for the GDT base address
    .align 256
    gdt_entry:
    .quad 0x0000000000000000  # null
    .quad 0x00af9b000000ffff  # code_64_kernel
    .quad 0x00cf93000000ffff  # data_64_kernel
    .quad 0x00affb000000ffff  # code_64_user
    .quad 0x00cff3000000ffff  # data_64_user
    .quad 0x0000000000000000  # null
    .quad 0x0000000000000000  # tss
    .quad 0xAAAAAAAAAAAAAAAA  # tss
    gdt_entry_end:
    "#,
    options(att_syntax)
);

extern "C" {
    pub fn asm_entry_trustlet_pf();
    pub fn asm_entry_trustlet_df();
    pub fn asm_entry_trustlet_gp();
    pub static gdt_desc: u8;
}

pub fn setup_exceptions(vmsa: &mut VMSA, page_table_ref: &ProcessPageTableRef) {
    let mut svsm_page_table_ref = ProcessPageTableRef::default();
    svsm_page_table_ref.set_external_table(read_cr3().into());

    // disable SMAP/SMEP to execute the handler in ring0
    // FIXME: propery setup the page flags for the handler
    vmsa.cr4 = vmsa.cr4 & !(1u64 << 20 | 1u64 << 21);

    log::debug!("asm_entry_trustlet_pf: {:x}", asm_entry_trustlet_pf as u64);
    log::debug!("asm_entry_trustlet_df: {:x}", asm_entry_trustlet_df as u64);
    log::debug!("gdt_desc: {:x}", unsafe { &gdt_desc as *const u8 as u64 });

    // setup IDT
    // 1. setup IDT entry for #PF, #DF
    idt_trustlet_mut().set_entry(PF_VECTOR, IdtEntry::trap_entry(asm_entry_trustlet_pf));
    idt_trustlet_mut().set_entry(GP_VECTOR, IdtEntry::trap_entry(asm_entry_trustlet_gp));
    idt_trustlet_mut().set_entry(DF_VECTOR, IdtEntry::entry(asm_entry_trustlet_df));
    //idt_trustlet_mut().set_entry(GP_VECTOR, IdtEntry::trap_entry(asm_entry_trustlet_df));
    // 2. rmpadjust for IDT and handlers
    let (idt_base, limit) = idt_trustlet().base_limit();
    rmp_adjust(idt_base.into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
    rmp_adjust((asm_entry_trustlet_pf as u64).into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
    rmp_adjust((unsafe { &gdt_desc as *const u8 as u64 }).into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
    // 3. map IDT and handlers to trustlet's page table
    let idt_phys = svsm_page_table_ref.virt_to_phys(idt_base.into());
    let handler_phys = svsm_page_table_ref.virt_to_phys((asm_entry_trustlet_pf as u64).into());
    let gdt_desc_phys = svsm_page_table_ref.virt_to_phys((unsafe { &gdt_desc as *const u8 as u64 }).into());
    assert!(idt_phys != PhysAddr::null());
    assert!(handler_phys != PhysAddr::null());
    assert!(gdt_desc_phys != PhysAddr::null());
    // FIXME: this assertion is to check the virtual address is available, but this page could
    // be also used by GDT/TSS and in that case the assertion will fail. Currently IDT and TSS
    // is aligend to 4KB boundary to about this issue. Fix this by properly allocating and
    // managing the page for IDT, TSS and GDT.
    //assert!(page_table_ref.virt_to_phys(idt_base.into()) == PhysAddr::null());
    //assert!(page_table_ref.virt_to_phys((asm_entry_trustlet_pf as u64).into()) == PhysAddr::null());
    //assert!(page_table_ref.virt_to_phys((unsafe { &gdt_desc as *const u8 as u64 }).into()) == PhysAddr::null());
    page_table_ref.map_4k_page(idt_base.into(), idt_phys, ProcessPageFlags::exec());
    page_table_ref.map_4k_page((asm_entry_trustlet_pf as u64).into(), handler_phys, ProcessPageFlags::exec());
    page_table_ref.map_4k_page((unsafe { &gdt_desc as *const u8 as u64 }).into(), gdt_desc_phys, ProcessPageFlags::data());
    // 4. setup IDT segment in VMSA
    let vmsa_idt = VMSASegment {
        selector: 0,
        flags: 0x0,
        base: idt_base,
        limit: limit-1,
    };
    vmsa.idt = vmsa_idt;

    // setup TSS
    //let mut tss = tss_trustlet_mut();
    const TSS_VADDR: u64 = TP_KERN_STACK_START_VADDR + 4096*2;
    let tss_phys = allocate_page();
    let tss_mapping = PerCPUPageMappingGuard::create_4k(tss_phys).unwrap();
    let tss_vaddr = tss_mapping.virt_addr();
    let tss = unsafe { &mut *tss_vaddr.as_mut_ptr::<X86Tss>() };
    let tss_base = TSS_VADDR;//tss.base();
    let num_page = 1;
    // 1. setup kernel stack address
    tss.stacks[0] = (TP_KERN_STACK_START_VADDR + 4096*num_page).into();
    // 2. map the stack address to trustlet's page table
    page_table_ref.add_stack(TP_KERN_STACK_START_VADDR.into(), num_page);
    // 3. map the TSS to trustlet's page table
    //let tss_phys = svsm_page_table_ref.virt_to_phys(tss_base.into());
    //assert!(tss_phys != PhysAddr::null());
    //assert!(page_table_ref.virt_to_phys(tss_base.into()) == PhysAddr::null());
    page_table_ref.map_4k_page(TSS_VADDR.into(), tss_phys, ProcessPageFlags::data());
    // 4. rmpadjust for TSS
    rmp_adjust(tss_vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
    let vmsa_tss = VMSASegment {
        selector: 6*8,
        flags: 0x89, // TSS
        base: TSS_VADDR,
        limit: TSS_LIMIT as u32-1,
    };
    vmsa.tr = vmsa_tss;

    // setup GDT
    // GDT entreies:
    // 0. null
    // 1. code_64_kernel
    // 2. data_64_kernel
    // 3. code_64_user
    // 4. data_64_user
    // 5. null
    // 6-7. TSS
    let mut desc0: u64 = 0;
    let mut desc1: u64 = 0;
    desc0 |= TSS_LIMIT & 0xffffu64;
    desc0 |= ((TSS_LIMIT >> 16) & 0xfu64) << 48;
    desc0 |= (TSS_VADDR & 0x00ff_ffffu64) << 16;
    desc0 |= (TSS_VADDR & 0xff00_0000u64) << 32;
    desc1 |= TSS_VADDR >> 32;
    desc0 |= 1u64 << 47;
    desc0 |= 0x9u64 << 40;

    let desc0 = GDTEntry::from_raw(desc0);
    let desc1 = GDTEntry::from_raw(desc1);

    //let (desc0, desc1) = tss.to_gdt_entry();
    unsafe{
        // this sets the entry 6 for TSS
        gdt_trustlet_mut().set_tss_entry(desc0, desc1);
    }
    let (base_gdt, limit) = gdt_trustlet().base_limit();
    log::debug!("GDT base: {:x}, limit: {:x}", base_gdt, limit);
    // 1. rmpadjust for GDT
    rmp_adjust(base_gdt.into(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
    // 2. map GDT to trustlet's page table
    let gdt_phys = svsm_page_table_ref.virt_to_phys(base_gdt.into());
    assert!(gdt_phys != PhysAddr::null());
    // FIXME: currently use the same virtual address as the SVSM for the trustlet
    //assert!(page_table_ref.virt_to_phys(base_gdt.into()) == PhysAddr::null());
    page_table_ref.map_4k_page(base_gdt.into(), gdt_phys, ProcessPageFlags::data());
    // 3. setup GDT segment in VMSA
    let vmsa_gdt = VMSASegment {
        selector: 0,
        flags: 0,
        base: base_gdt,
        limit: limit,
    };
    vmsa.gdt = vmsa_gdt;

    let cs = VMSASegment {
        selector: 3*8 | 0x3,
        flags: 0xAFB, // user, code, 4KB granularity, 64-bit
        base: 0,
        limit: 0xFFFF_FFFF,
    };
    let ds = VMSASegment {
        selector: 4*8 | 0x3,
        flags: 0xCF3, // user, data, 4KB granularity, 64-bit
        base: 0,
        limit: 0xFFFF_FFFF,
    };

    vmsa.cs = cs;
    vmsa.ds = ds;
    vmsa.es = ds;
    vmsa.fs = ds;
    vmsa.ss = ds;

    let efer = vmsa.efer;
    let cr4 = vmsa.cr4;
    let rflags = vmsa.rflags;
    log::debug!("vmsa EFER: {:?}", efer);
    log::debug!("vmsa cr4: {:?}", cr4);
    log::debug!("vmsa CS: {:?}", vmsa.cs);
    log::debug!("vmsa SS: {:?}", vmsa.ss);
    log::debug!("vmsa DS: {:?}", vmsa.ds);
    log::debug!("vmsa rflags: {:?}", rflags);


}
