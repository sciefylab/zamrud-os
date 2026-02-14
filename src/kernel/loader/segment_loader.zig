//! Zamrud OS - ELF Segment Loader (F5.1)
//! Loads PT_LOAD segments into memory with proper VMM mappings
//!
//! Supports:
//!   - Load PT_LOAD segments to allocated physical pages
//!   - VMM page mapping with correct permissions (RX, RW, RO)
//!   - BSS zero-fill (memsz > filesz)
//!   - Memory protection based on segment flags
//!   - Cleanup on failure (rollback all allocations)

const serial = @import("../drivers/serial/serial.zig");
const pmm = @import("../mm/pmm.zig");
const vmm = @import("../mm/vmm.zig");
const elf_parser = @import("elf_parser.zig");

// ============================================================================
// Constants
// ============================================================================

pub const PAGE_SIZE: u64 = 4096;

/// Maximum number of segments we can track for cleanup
pub const MAX_LOADED_SEGMENTS: usize = 16;

/// User-space address range validation
pub const USER_SPACE_MIN: u64 = 0x400000; // 4MB
pub const USER_SPACE_MAX: u64 = 0x80000000; // 2GB — safe conservative limit

/// Default user stack
pub const USER_STACK_TOP: u64 = 0x800000; // 8MB
pub const USER_STACK_PAGES: u64 = 16; // 64KB stack
pub const USER_STACK_BOTTOM: u64 = USER_STACK_TOP - (USER_STACK_PAGES * PAGE_SIZE);

// ============================================================================
// Error types
// ============================================================================

pub const LoadError = enum(u8) {
    None = 0,
    NoLoadSegments = 1,
    InvalidAddress = 2,
    AddressOutOfRange = 3,
    AllocationFailed = 4,
    MappingFailed = 5,
    CopyFailed = 6,
    TooManySegments = 7,
    SegmentOverlap = 8,
    AlignmentError = 9,
    StackAllocFailed = 10,
};

pub fn loadErrorName(err: LoadError) []const u8 {
    return switch (err) {
        .None => "None",
        .NoLoadSegments => "NoLoadSegments",
        .InvalidAddress => "InvalidAddress",
        .AddressOutOfRange => "AddressOutOfRange",
        .AllocationFailed => "AllocationFailed",
        .MappingFailed => "MappingFailed",
        .CopyFailed => "CopyFailed",
        .TooManySegments => "TooManySegments",
        .SegmentOverlap => "SegmentOverlap",
        .AlignmentError => "AlignmentError",
        .StackAllocFailed => "StackAllocFailed",
    };
}

// ============================================================================
// Loaded segment tracking (for cleanup)
// ============================================================================

pub const LoadedSegment = struct {
    vaddr: u64,
    page_count: u64,
    phys_pages: [64]u64,
    flags: u64,

    pub fn init() LoadedSegment {
        return LoadedSegment{
            .vaddr = 0,
            .page_count = 0,
            .phys_pages = [_]u64{0} ** 64,
            .flags = 0,
        };
    }
};

/// Result of loading all segments
pub const LoadResult = struct {
    segments: [MAX_LOADED_SEGMENTS]LoadedSegment,
    segment_count: usize,
    entry_point: u64,
    stack_top: u64,
    stack_bottom: u64,
    stack_pages: u64,
    stack_phys: [64]u64,
    total_pages_used: u64,
    err: LoadError,

    pub fn init() LoadResult {
        var result: LoadResult = undefined;
        result.segment_count = 0;
        result.entry_point = 0;
        result.stack_top = 0;
        result.stack_bottom = 0;
        result.stack_pages = 0;
        result.total_pages_used = 0;
        result.err = .None;
        var i: usize = 0;
        while (i < MAX_LOADED_SEGMENTS) : (i += 1) {
            result.segments[i] = LoadedSegment.init();
        }
        i = 0;
        while (i < 64) : (i += 1) {
            result.stack_phys[i] = 0;
        }
        return result;
    }
};

// ============================================================================
// ELF flags → VMM flags conversion
// ============================================================================

pub fn elfFlagsToVmm(elf_flags: u32, user_mode: bool) u64 {
    var flags: u64 = vmm.PageFlags.PRESENT;

    if (user_mode) {
        flags |= vmm.PageFlags.USER;
    }

    if ((elf_flags & elf_parser.PF_W) != 0) {
        flags |= vmm.PageFlags.WRITABLE;
    }

    if ((elf_flags & elf_parser.PF_X) == 0) {
        flags |= vmm.PageFlags.NO_EXECUTE;
    }

    return flags;
}

pub fn permString(elf_flags: u32) [3]u8 {
    return .{
        if ((elf_flags & elf_parser.PF_R) != 0) 'R' else '-',
        if ((elf_flags & elf_parser.PF_W) != 0) 'W' else '-',
        if ((elf_flags & elf_parser.PF_X) != 0) 'X' else '-',
    };
}

// ============================================================================
// Segment validation
// ============================================================================

fn validateSegmentAddress(phdr: *const elf_parser.ProgramHeader) LoadError {
    if (phdr.vaddr < USER_SPACE_MIN) return .AddressOutOfRange;
    if (phdr.vend() > USER_SPACE_MAX) return .AddressOutOfRange;
    if (phdr.memsz > 256 * 1024 * 1024) return .InvalidAddress;
    if (phdr.memsz < phdr.filesz) return .InvalidAddress;
    return .None;
}

fn validateAllSegments(parsed: *const elf_parser.ParsedElf) LoadError {
    if (parsed.load_count == 0) return .NoLoadSegments;
    if (parsed.load_count > MAX_LOADED_SEGMENTS) return .TooManySegments;

    var i: usize = 0;
    while (i < parsed.phdr_count) : (i += 1) {
        if (!parsed.phdrs[i].isLoad()) continue;
        const val_err = validateSegmentAddress(&parsed.phdrs[i]);
        if (val_err != .None) return val_err;
    }

    const overlap_err = elf_parser.checkOverlappingSegments(parsed);
    if (overlap_err != .None) return .SegmentOverlap;

    return .None;
}

// ============================================================================
// Core loading functions
// ============================================================================

fn copyToMapped(phys_addr: u64, src: []const u8, offset: usize, len: usize) void {
    const hhdm = pmm.getHhdmOffset();
    const dest_virt = hhdm + phys_addr + offset;

    var i: usize = 0;
    while (i < len) : (i += 1) {
        const ptr: *volatile u8 = @ptrFromInt(dest_virt + i);
        ptr.* = src[i];
    }
}

fn zeroMapped(phys_addr: u64, offset: usize, len: usize) void {
    const hhdm = pmm.getHhdmOffset();
    const dest_virt = hhdm + phys_addr + offset;

    var i: usize = 0;
    while (i < len) : (i += 1) {
        const ptr: *volatile u8 = @ptrFromInt(dest_virt + i);
        ptr.* = 0;
    }
}

fn loadSegment(
    phdr: *const elf_parser.ProgramHeader,
    elf_data: []const u8,
    seg: *LoadedSegment,
    user_mode: bool,
) LoadError {
    const page_aligned_vaddr = phdr.vaddr & ~@as(u64, PAGE_SIZE - 1);
    const vaddr_offset = phdr.vaddr - page_aligned_vaddr;

    const total_size = vaddr_offset + phdr.memsz;
    const page_count = (total_size + PAGE_SIZE - 1) / PAGE_SIZE;

    if (page_count > 64) {
        serial.writeString("[SEGLOAD] Segment too large (>64 pages)\n");
        return .AllocationFailed;
    }

    const vmm_flags = elfFlagsToVmm(phdr.flags, user_mode);

    serial.writeString("[SEGLOAD] Loading segment: va=0x");
    printHex64(phdr.vaddr);
    serial.writeString(" pages=");
    printDec(page_count);
    serial.writeString(" [");
    const perms = permString(phdr.flags);
    serial.writeChar(perms[0]);
    serial.writeChar(perms[1]);
    serial.writeChar(perms[2]);
    serial.writeString("]\n");

    seg.vaddr = page_aligned_vaddr;
    seg.page_count = page_count;
    seg.flags = vmm_flags;

    var pi: u64 = 0;
    while (pi < page_count) : (pi += 1) {
        const phys = pmm.allocPage() orelse {
            serial.writeString("[SEGLOAD] Failed to allocate page\n");
            cleanupSegment(seg, pi);
            return .AllocationFailed;
        };

        seg.phys_pages[@intCast(pi)] = phys;

        const virt = page_aligned_vaddr + pi * PAGE_SIZE;
        if (!vmm.mapPage(virt, phys, vmm_flags)) {
            serial.writeString("[SEGLOAD] Failed to map page\n");
            pmm.freePage(phys);
            cleanupSegment(seg, pi);
            return .MappingFailed;
        }
    }

    if (phdr.filesz > 0) {
        const file_offset = @as(usize, @intCast(phdr.offset));
        const file_size = @as(usize, @intCast(phdr.filesz));

        if (file_offset + file_size > elf_data.len) {
            serial.writeString("[SEGLOAD] Segment data out of bounds\n");
            cleanupLoadedSegment(seg);
            return .CopyFailed;
        }

        const src = elf_data[file_offset .. file_offset + file_size];

        var bytes_copied: usize = 0;
        const va_off = @as(usize, @intCast(vaddr_offset));

        while (bytes_copied < file_size) {
            const current_offset = va_off + bytes_copied;
            const page_idx: u64 = current_offset / PAGE_SIZE;
            const in_page_offset = current_offset % PAGE_SIZE;
            const remaining_in_page = PAGE_SIZE - in_page_offset;
            const remaining_data = file_size - bytes_copied;
            const copy_len = if (remaining_data < remaining_in_page) remaining_data else remaining_in_page;

            const phys = seg.phys_pages[@intCast(page_idx)];
            copyToMapped(phys, src[bytes_copied .. bytes_copied + copy_len], in_page_offset, copy_len);
            bytes_copied += copy_len;
        }
    }

    if (phdr.hasBss()) {
        const bss_start_offset = @as(usize, @intCast(vaddr_offset + phdr.filesz));
        const bss_size = @as(usize, @intCast(phdr.bssSize()));

        var bytes_zeroed: usize = 0;
        while (bytes_zeroed < bss_size) {
            const current_offset = bss_start_offset + bytes_zeroed;
            const page_idx: u64 = current_offset / PAGE_SIZE;
            const in_page_offset = current_offset % PAGE_SIZE;
            const remaining_in_page = PAGE_SIZE - in_page_offset;
            const remaining_bss = bss_size - bytes_zeroed;
            const zero_len = if (remaining_bss < remaining_in_page) remaining_bss else remaining_in_page;

            const phys = seg.phys_pages[@intCast(page_idx)];
            zeroMapped(phys, in_page_offset, zero_len);
            bytes_zeroed += zero_len;
        }
    }

    return .None;
}

fn cleanupSegment(seg: *LoadedSegment, pages_allocated: u64) void {
    var i: u64 = 0;
    while (i < pages_allocated) : (i += 1) {
        const virt = seg.vaddr + i * PAGE_SIZE;
        _ = vmm.unmapPage(virt);
        pmm.freePage(seg.phys_pages[@intCast(i)]);
        seg.phys_pages[@intCast(i)] = 0;
    }
    seg.page_count = 0;
}

fn cleanupLoadedSegment(seg: *LoadedSegment) void {
    cleanupSegment(seg, seg.page_count);
}

// ============================================================================
// Stack setup
// ============================================================================

fn setupStack(result: *LoadResult) LoadError {
    serial.writeString("[SEGLOAD] Setting up user stack: ");
    printDec(USER_STACK_PAGES);
    serial.writeString(" pages at 0x");
    printHex64(USER_STACK_BOTTOM);
    serial.writeString("\n");

    const stack_flags = vmm.PageFlags.PRESENT | vmm.PageFlags.WRITABLE |
        vmm.PageFlags.USER | vmm.PageFlags.NO_EXECUTE;

    var pi: u64 = 0;
    while (pi < USER_STACK_PAGES) : (pi += 1) {
        const phys = pmm.allocPage() orelse {
            serial.writeString("[SEGLOAD] Stack allocation failed\n");
            var j: u64 = 0;
            while (j < pi) : (j += 1) {
                _ = vmm.unmapPage(USER_STACK_BOTTOM + j * PAGE_SIZE);
                pmm.freePage(result.stack_phys[@intCast(j)]);
            }
            return .StackAllocFailed;
        };

        result.stack_phys[@intCast(pi)] = phys;

        const virt = USER_STACK_BOTTOM + pi * PAGE_SIZE;
        if (!vmm.mapPage(virt, phys, stack_flags)) {
            serial.writeString("[SEGLOAD] Stack mapping failed\n");
            pmm.freePage(phys);
            var j: u64 = 0;
            while (j < pi) : (j += 1) {
                _ = vmm.unmapPage(USER_STACK_BOTTOM + j * PAGE_SIZE);
                pmm.freePage(result.stack_phys[@intCast(j)]);
            }
            return .StackAllocFailed;
        }
    }

    result.stack_bottom = USER_STACK_BOTTOM;
    result.stack_top = USER_STACK_TOP;
    result.stack_pages = USER_STACK_PAGES;
    result.total_pages_used += USER_STACK_PAGES;

    return .None;
}

// ============================================================================
// Main API
// ============================================================================

pub fn loadSegments(
    parsed: *const elf_parser.ParsedElf,
    elf_data: []const u8,
    user_mode: bool,
) LoadResult {
    var result = LoadResult.init();
    result.entry_point = parsed.entryPoint();

    serial.writeString("\n[SEGLOAD] === Loading ELF Segments ===\n");
    serial.writeString("[SEGLOAD] Entry point: 0x");
    printHex64(result.entry_point);
    serial.writeString("\n");
    serial.writeString("[SEGLOAD] LOAD segments: ");
    printDec(parsed.load_count);
    serial.writeString("\n");

    const val_err = validateAllSegments(parsed);
    if (val_err != .None) {
        serial.writeString("[SEGLOAD] Validation failed: ");
        serial.writeString(loadErrorName(val_err));
        serial.writeString("\n");
        result.err = val_err;
        return result;
    }

    var i: usize = 0;
    while (i < parsed.phdr_count) : (i += 1) {
        if (!parsed.phdrs[i].isLoad()) continue;

        if (result.segment_count >= MAX_LOADED_SEGMENTS) {
            serial.writeString("[SEGLOAD] Too many segments\n");
            result.err = .TooManySegments;
            cleanupAllSegments(&result);
            return result;
        }

        const seg_idx = result.segment_count;
        const load_err = loadSegment(
            &parsed.phdrs[i],
            elf_data,
            &result.segments[seg_idx],
            user_mode,
        );

        if (load_err != .None) {
            serial.writeString("[SEGLOAD] Failed to load segment: ");
            serial.writeString(loadErrorName(load_err));
            serial.writeString("\n");
            result.err = load_err;
            cleanupAllSegments(&result);
            return result;
        }

        result.total_pages_used += result.segments[seg_idx].page_count;
        result.segment_count += 1;
    }

    if (user_mode) {
        const stack_err = setupStack(&result);
        if (stack_err != .None) {
            result.err = stack_err;
            cleanupAllSegments(&result);
            return result;
        }
    }

    serial.writeString("[SEGLOAD] === Load Complete ===\n");
    serial.writeString("[SEGLOAD] Segments loaded: ");
    printDec(result.segment_count);
    serial.writeString("\n");
    serial.writeString("[SEGLOAD] Total pages: ");
    printDec(result.total_pages_used);
    serial.writeString(" (");
    printDec(result.total_pages_used * 4);
    serial.writeString(" KB)\n");

    return result;
}

pub fn cleanupAllSegments(result: *LoadResult) void {
    serial.writeString("[SEGLOAD] Cleaning up loaded segments...\n");

    var i: usize = 0;
    while (i < result.segment_count) : (i += 1) {
        cleanupLoadedSegment(&result.segments[i]);
    }

    if (result.stack_pages > 0) {
        var pi: u64 = 0;
        while (pi < result.stack_pages) : (pi += 1) {
            if (result.stack_phys[@intCast(pi)] != 0) {
                _ = vmm.unmapPage(result.stack_bottom + pi * PAGE_SIZE);
                pmm.freePage(result.stack_phys[@intCast(pi)]);
            }
        }
    }

    result.segment_count = 0;
    result.total_pages_used = 0;
    result.stack_pages = 0;
}

pub fn getLoadInfo(result: *const LoadResult) struct {
    code_pages: u64,
    data_pages: u64,
    bss_pages: u64,
    stack_pages: u64,
    total_pages: u64,
} {
    var code: u64 = 0;
    var data: u64 = 0;

    var i: usize = 0;
    while (i < result.segment_count) : (i += 1) {
        const seg = &result.segments[i];
        if ((seg.flags & vmm.PageFlags.NO_EXECUTE) == 0) {
            code += seg.page_count;
        } else {
            data += seg.page_count;
        }
    }

    return .{
        .code_pages = code,
        .data_pages = data,
        .bss_pages = 0,
        .stack_pages = result.stack_pages,
        .total_pages = result.total_pages_used,
    };
}

// ============================================================================
// Print helpers
// ============================================================================

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printDec(val: anytype) void {
    const v: u64 = @intCast(val);
    if (v == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;
    while (n > 0) : (i += 1) {
        buf[i] = @intCast((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
