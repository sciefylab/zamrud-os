/* Zamrud OS - Linker Script for Higher Half Kernel */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kernel_main)

/* Base address untuk virtual memory (Higher Half) */
KERNEL_VIRT_BASE = 0xffffffff80000000;

PHDRS
{
    text    PT_LOAD FLAGS(5);  /* r-x: Read + Execute */
    rodata  PT_LOAD FLAGS(4);  /* r--: Read Only */
    data    PT_LOAD FLAGS(6);  /* rw-: Read + Write */
}

SECTIONS
{
    /* Eksekusi dimulai di alamat virtual tinggi */
    . = KERNEL_VIRT_BASE;

    /* ================================================================
     * KERNEL START MARKER - untuk boot verification
     * ================================================================ */
    __kernel_start = .;

    /* AT(...) memastikan alamat FISIK berada di bawah (0 + offset) */
    .text : AT(ADDR(.text) - KERNEL_VIRT_BASE)
    {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    . = ALIGN(4096);

    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT_BASE)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    } :rodata

    . = ALIGN(4096);

    .data : AT(ADDR(.data) - KERNEL_VIRT_BASE)
    {
        __data_start = .;
        *(.data .data.*)

        /* Bagian krusial untuk protokol Limine bootloader */
        KEEP(*(.limine_requests_start_marker))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end_marker))

        __data_end = .;
    } :data

    . = ALIGN(4096);

    .bss : AT(ADDR(.bss) - KERNEL_VIRT_BASE)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    . = ALIGN(4096);

    /* ================================================================
     * KERNEL END MARKER - untuk boot verification
     * ================================================================ */
    __kernel_end = .;

    /* Buang bagian yang tidak diperlukan oleh kernel agar file lebih ramping */
    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note .note.*)
        *(.interp)
        *(.comment)
        *(.dynamic)
    }
}