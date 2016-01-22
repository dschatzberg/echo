.align 16
.global syscall_entry
.type syscall_entry, @function
syscall_entry:
.cfi_startproc simple
.cfi_def_cfa %rsp, 0
.cfi_undefined %rip
        outl %eax, $0x0
        jmp *%rcx
.cfi_endproc
.size syscall_entry, . - syscall_entry

        .align 16
.global vm_entry
.type vm_entry,@function
vm_entry:
.cfi_startproc simple
.cfi_def_cfa %rsp, 0
.cfi_undefined %rip

        //outl %eax, $0x90
        //inb $0x1, %al
        mov $syscall_entry, %rax
        mov $syscall_entry, %rdx
        shr $32, %rdx
        mov $0xc0000082, %ecx
        wrmsr
        lea stack_top, %rsp
        call vm_c_entry
1:
        hlt
        jmp 1b
.cfi_endproc
.size vm_entry, . - vm_entry

        .bss
        .align 16
stack_bottom = .
        .space 16 * 1024
stack_top = .
