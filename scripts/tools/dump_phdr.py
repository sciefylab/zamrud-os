#!/usr/bin/env python3
import sys
import struct

PT_TYPES = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
    0x6474e550: "GNU_EH_FRAME",
    0x6474e551: "GNU_STACK",
    0x6474e552: "GNU_RELRO",
}

def u16(b, off, le=True):
    return struct.unpack_from("<H" if le else ">H", b, off)[0]

def u32(b, off, le=True):
    return struct.unpack_from("<I" if le else ">I", b, off)[0]

def u64(b, off, le=True):
    return struct.unpack_from("<Q" if le else ">Q", b, off)[0]

def main():
    if len(sys.argv) != 2:
        print("Usage: python tools/dump_phdr.py <elf-file>")
        sys.exit(1)

    path = sys.argv[1]
    data = open(path, "rb").read()

    if data[:4] != b"\x7fELF":
        print("Not an ELF file")
        sys.exit(1)

    ei_class = data[4]     # 1 = 32-bit, 2 = 64-bit
    ei_data  = data[5]     # 1 = little, 2 = big
    le = (ei_data == 1)

    if ei_class != 2:
        print(f"ELF is not 64-bit (EI_CLASS={ei_class})")
        sys.exit(1)

    # ELF64 header offsets:
    # e_type      16 u16
    # e_machine   18 u16
    # e_version   20 u32
    # e_entry     24 u64
    # e_phoff     32 u64
    # e_shoff     40 u64
    # e_flags     48 u32
    # e_ehsize    52 u16
    # e_phentsize 54 u16
    # e_phnum     56 u16
    e_type      = u16(data, 16, le)
    e_machine   = u16(data, 18, le)
    e_entry     = u64(data, 24, le)
    e_phoff     = u64(data, 32, le)
    e_phentsize = u16(data, 54, le)
    e_phnum     = u16(data, 56, le)

    print(f"File: {path}")
    print(f"Endian: {'LE' if le else 'BE'}")
    print(f"e_type: 0x{e_type:04x}  (2=EXEC, 3=DYN)")
    print(f"e_machine: 0x{e_machine:04x} (0x3e=x86_64)")
    print(f"e_entry: 0x{e_entry:016x}")
    print(f"e_phoff: 0x{e_phoff:x}")
    print(f"e_phentsize: {e_phentsize}")
    print(f"e_phnum: {e_phnum}")
    print("\nProgram Headers:")

    if e_phoff == 0 or e_phnum == 0:
        print("  <no program headers>")
        sys.exit(0)

    # ELF64 Phdr layout (56 bytes):
    # p_type   u32
    # p_flags  u32
    # p_offset u64
    # p_vaddr  u64
    # p_paddr  u64
    # p_filesz u64
    # p_memsz  u64
    # p_align  u64
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type   = u32(data, off + 0, le)
        p_flags  = u32(data, off + 4, le)
        p_offset = u64(data, off + 8, le)
        p_vaddr  = u64(data, off + 16, le)
        p_paddr  = u64(data, off + 24, le)
        p_filesz = u64(data, off + 32, le)
        p_memsz  = u64(data, off + 40, le)
        p_align  = u64(data, off + 48, le)

        tname = PT_TYPES.get(p_type, f"0x{p_type:x}")
        print(f"  [{i:02d}] {tname:10} flags=0x{p_flags:x} off=0x{p_offset:x} vaddr=0x{p_vaddr:016x} paddr=0x{p_paddr:016x} filesz=0x{p_filesz:x} memsz=0x{p_memsz:x} align=0x{p_align:x}")

if __name__ == "__main__":
    main()