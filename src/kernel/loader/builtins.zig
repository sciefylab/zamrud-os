//! Zamrud OS - Built-in Test Programs (F5.4)
//! Pre-built ELF binaries embedded in kernel for testing
//!
//! Programs:
//!   - hello: Minimal program (just entry + ret)
//!   - syscall_test: Tests syscall interface
//!   - compute: Simple computation loop
//!   - nop_sled: NOP sled + return (tests code execution)
//!   - multi_seg: Two LOAD segments (code + data)

const serial = @import("../drivers/serial/serial.zig");
const elf_parser = @import("elf_parser.zig");
const zam_header = @import("zam_header.zig");
const capability = @import("../security/capability.zig");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_BUILTIN_SIZE: usize = 512;
pub const MAX_BUILTINS: usize = 8;

// ============================================================================
// Built-in program descriptor
// ============================================================================

pub const BuiltinProgram = struct {
    name: [16]u8,
    name_len: u8,
    description: [48]u8,
    desc_len: u8,
    caps: u32,
    trust: u8,
    active: bool,

    pub fn getName(self: *const BuiltinProgram) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getDesc(self: *const BuiltinProgram) []const u8 {
        return self.description[0..self.desc_len];
    }
};

// ============================================================================
// Built-in registry
// ============================================================================

var builtins: [MAX_BUILTINS]BuiltinProgram = undefined;
var builtin_count: usize = 0;
var initialized: bool = false;

pub fn init() void {
    serial.writeString("[BUILTINS] Initializing built-in programs...\n");

    builtin_count = 0;

    var i: usize = 0;
    while (i < MAX_BUILTINS) : (i += 1) {
        builtins[i].active = false;
        builtins[i].name_len = 0;
        builtins[i].desc_len = 0;
    }

    // Register built-in programs
    registerBuiltin("hello", "Minimal test program (entry + hlt)", capability.CAP_MINIMAL, zam_header.TRUST_USER);
    registerBuiltin("syscall", "Syscall interface test", capability.CAP_USER_DEFAULT, zam_header.TRUST_USER);
    registerBuiltin("compute", "Simple computation loop", capability.CAP_MINIMAL, zam_header.TRUST_USER);
    registerBuiltin("nopsled", "NOP sled execution test", capability.CAP_MINIMAL, zam_header.TRUST_UNTRUSTED);
    registerBuiltin("multiseg", "Two-segment ELF (code+data)", capability.CAP_USER_DEFAULT, zam_header.TRUST_USER);

    initialized = true;

    serial.writeString("[BUILTINS] Registered ");
    printDec(builtin_count);
    serial.writeString(" built-in programs\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn registerBuiltin(name: []const u8, desc: []const u8, caps: u32, trust: u8) void {
    if (builtin_count >= MAX_BUILTINS) return;

    const idx = builtin_count;
    builtins[idx].active = true;
    builtins[idx].caps = caps;
    builtins[idx].trust = trust;

    // Copy name
    const nlen = @min(name.len, 16);
    var ni: usize = 0;
    while (ni < nlen) : (ni += 1) {
        builtins[idx].name[ni] = name[ni];
    }
    builtins[idx].name_len = @intCast(nlen);

    // Copy description
    const dlen = @min(desc.len, 48);
    var di: usize = 0;
    while (di < dlen) : (di += 1) {
        builtins[idx].description[di] = desc[di];
    }
    builtins[idx].desc_len = @intCast(dlen);

    builtin_count += 1;
}

// ============================================================================
// Query API
// ============================================================================

pub fn getCount() usize {
    return builtin_count;
}

pub fn getBuiltin(index: usize) ?*const BuiltinProgram {
    if (index >= builtin_count) return null;
    if (!builtins[index].active) return null;
    return &builtins[index];
}

pub fn findByName(name: []const u8) ?usize {
    var i: usize = 0;
    while (i < builtin_count) : (i += 1) {
        if (builtins[i].active and strEql(builtins[i].getName(), name)) {
            return i;
        }
    }
    return null;
}

// ============================================================================
// ELF Builders — each returns bytes written to buf
// ============================================================================

/// Build the named built-in program as raw ELF into buf
pub fn buildElf(name: []const u8, buf: []u8) usize {
    if (strEql(name, "hello")) return buildHello(buf);
    if (strEql(name, "syscall")) return buildSyscallTest(buf);
    if (strEql(name, "compute")) return buildCompute(buf);
    if (strEql(name, "nopsled")) return buildNopSled(buf);
    if (strEql(name, "multiseg")) return buildMultiSeg(buf);
    return 0;
}

/// Build the named built-in as .zam (ZAM header + ELF)
pub fn buildZam(name: []const u8, buf: []u8) usize {
    const idx = findByName(name) orelse return 0;
    const prog = &builtins[idx];

    var elf_buf: [384]u8 = [_]u8{0} ** 384;
    const elf_size = buildElf(name, &elf_buf);
    if (elf_size == 0) return 0;

    const hdr_size = zam_header.buildHeader(
        buf,
        elf_buf[0..elf_size],
        prog.caps,
        prog.trust,
        64,
        0,
    );
    if (hdr_size == 0) return 0;

    // Copy ELF after header
    if (hdr_size + elf_size > buf.len) return 0;
    var i: usize = 0;
    while (i < elf_size) : (i += 1) {
        buf[hdr_size + i] = elf_buf[i];
    }

    return hdr_size + elf_size;
}

// ============================================================================
// Program 1: hello — minimal (hlt loop)
// ============================================================================

fn buildHello(buf: []u8) usize {
    if (buf.len < 184) return 0;
    initElfHeader(buf, 0x400000, 1);

    // Program header: code at 0x400000
    setProgramHeader(buf, 64, 0x400000, 184, 184, elf_parser.PF_R | elf_parser.PF_X);

    // Code at offset 120: hlt loop
    // cli; hlt; jmp -2
    buf[120] = 0xFA; // cli
    buf[121] = 0xF4; // hlt
    buf[122] = 0xEB; // jmp short -2
    buf[123] = 0xFD;

    return 184;
}

// ============================================================================
// Program 2: syscall — syscall interface test
// ============================================================================

fn buildSyscallTest(buf: []u8) usize {
    if (buf.len < 184) return 0;
    initElfHeader(buf, 0x400000, 1);

    setProgramHeader(buf, 64, 0x400000, 184, 184, elf_parser.PF_R | elf_parser.PF_X);

    // Code: mov eax, 60 (exit); xor edi, edi; syscall; hlt
    buf[120] = 0xB8; // mov eax, 60
    buf[121] = 0x3C;
    buf[122] = 0x00;
    buf[123] = 0x00;
    buf[124] = 0x00;
    buf[125] = 0x31; // xor edi, edi
    buf[126] = 0xFF;
    buf[127] = 0x0F; // syscall
    buf[128] = 0x05;
    buf[129] = 0xF4; // hlt (fallback)

    return 184;
}

// ============================================================================
// Program 3: compute — simple add loop
// ============================================================================

fn buildCompute(buf: []u8) usize {
    if (buf.len < 200) return 0;
    initElfHeader(buf, 0x400000, 1);

    setProgramHeader(buf, 64, 0x400000, 200, 200, elf_parser.PF_R | elf_parser.PF_X);

    // Code: xor eax, eax; mov ecx, 10; add eax, ecx; dec ecx; jnz -4; hlt
    buf[120] = 0x31; // xor eax, eax
    buf[121] = 0xC0;
    buf[122] = 0xB9; // mov ecx, 10
    buf[123] = 0x0A;
    buf[124] = 0x00;
    buf[125] = 0x00;
    buf[126] = 0x00;
    // loop:
    buf[127] = 0x01; // add eax, ecx
    buf[128] = 0xC8;
    buf[129] = 0xFF; // dec ecx
    buf[130] = 0xC9;
    buf[131] = 0x75; // jnz loop (-4)
    buf[132] = 0xFC;
    buf[133] = 0xF4; // hlt

    return 200;
}

// ============================================================================
// Program 4: nopsled — NOP sled + hlt
// ============================================================================

fn buildNopSled(buf: []u8) usize {
    if (buf.len < 200) return 0;
    initElfHeader(buf, 0x400000, 1);

    setProgramHeader(buf, 64, 0x400000, 200, 200, elf_parser.PF_R | elf_parser.PF_X);

    // 32 NOPs then HLT
    var i: usize = 120;
    while (i < 152) : (i += 1) {
        buf[i] = 0x90; // NOP
    }
    buf[152] = 0xF4; // HLT

    return 200;
}

// ============================================================================
// Program 5: multiseg — two LOAD segments (code RX + data RW)
// ============================================================================

fn buildMultiSeg(buf: []u8) usize {
    if (buf.len < 384) return 0;

    // Clear
    var ci: usize = 0;
    while (ci < 384) : (ci += 1) {
        buf[ci] = 0;
    }

    // ELF header with 2 program headers
    initElfHeader(buf, 0x400000, 2);

    // Segment 1: code (RX) at 0x400000, file offset 0, size 256
    setProgramHeader(buf, 64, 0x400000, 256, 256, elf_parser.PF_R | elf_parser.PF_X);

    // Segment 2: data (RW) at 0x401000, file offset 256, size 128 file, 256 mem (BSS)
    setProgramHeaderFull(buf, 120, 0x401000, 256, 128, 256, elf_parser.PF_R | elf_parser.PF_W);

    // Code at offset 176 (after 2 phdrs: 64 + 56 + 56 = 176)
    buf[176] = 0x31; // xor eax, eax
    buf[177] = 0xC0;
    buf[178] = 0xF4; // hlt

    // Data at offset 256
    buf[256] = 0x48; // 'H'
    buf[257] = 0x65; // 'e'
    buf[258] = 0x6C; // 'l'
    buf[259] = 0x6C; // 'l'
    buf[260] = 0x6F; // 'o'
    buf[261] = 0x00; // null terminator

    return 384;
}

// ============================================================================
// ELF header helpers
// ============================================================================

fn initElfHeader(buf: []u8, entry: u64, phnum: u16) void {
    buf[0] = 0x7F;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = elf_parser.ELFCLASS64;
    buf[5] = elf_parser.ELFDATA2LSB;
    buf[6] = 1; // version
    buf[7] = 0; // OS/ABI

    writeU16(buf, 16, elf_parser.ET_EXEC);
    writeU16(buf, 18, elf_parser.EM_X86_64);
    writeU32(buf, 20, 1); // version
    writeU64(buf, 24, entry);
    writeU64(buf, 32, 64); // phoff
    writeU16(buf, 52, 64); // ehsize
    writeU16(buf, 54, 56); // phentsize
    writeU16(buf, 56, phnum);
    writeU16(buf, 58, 64); // shentsize
}

fn setProgramHeader(buf: []u8, offset: usize, vaddr: u64, filesz: u64, memsz: u64, flags: u32) void {
    writeU32(buf, offset, elf_parser.PT_LOAD);
    writeU32(buf, offset + 4, flags);
    writeU64(buf, offset + 8, 0); // file offset
    writeU64(buf, offset + 16, vaddr);
    writeU64(buf, offset + 24, vaddr); // paddr
    writeU64(buf, offset + 32, filesz);
    writeU64(buf, offset + 40, memsz);
    writeU64(buf, offset + 48, 0x1000); // align
}

fn setProgramHeaderFull(buf: []u8, offset: usize, vaddr: u64, file_offset: u64, filesz: u64, memsz: u64, flags: u32) void {
    writeU32(buf, offset, elf_parser.PT_LOAD);
    writeU32(buf, offset + 4, flags);
    writeU64(buf, offset + 8, file_offset);
    writeU64(buf, offset + 16, vaddr);
    writeU64(buf, offset + 24, vaddr);
    writeU64(buf, offset + 32, filesz);
    writeU64(buf, offset + 40, memsz);
    writeU64(buf, offset + 48, 0x1000);
}

// ============================================================================
// Helpers
// ============================================================================

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn writeU16(buf: []u8, offset: usize, val: u16) void {
    buf[offset] = @intCast(val & 0xFF);
    buf[offset + 1] = @intCast((val >> 8) & 0xFF);
}

fn writeU32(buf: []u8, offset: usize, val: u32) void {
    buf[offset] = @intCast(val & 0xFF);
    buf[offset + 1] = @intCast((val >> 8) & 0xFF);
    buf[offset + 2] = @intCast((val >> 16) & 0xFF);
    buf[offset + 3] = @intCast((val >> 24) & 0xFF);
}

fn writeU64(buf: []u8, offset: usize, val: u64) void {
    var j: usize = 0;
    while (j < 8) : (j += 1) {
        buf[offset + j] = @intCast((val >> @intCast(j * 8)) & 0xFF);
    }
}

fn printDec(val: anytype) void {
    const v: u64 = @intCast(val);
    if (v == 0) {
        serial.writeChar('0');
        return;
    }
    var b: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;
    while (n > 0) : (i += 1) {
        b[i] = @intCast((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(b[i]);
    }
}
