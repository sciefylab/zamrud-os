//! Zamrud OS - ACPI Driver
//! Advanced Configuration and Power Interface
//! Parses RSDP, RSDT/XSDT, FADT for power management
//! All reads are unaligned-safe for ACPI table compatibility

const std = @import("std");
const serial = @import("../../drivers/serial/serial.zig");
const limine = @import("../../core/limine.zig");
const pmm = @import("../../mm/pmm.zig");

// ============================================================================
// ACPI Table Signatures
// ============================================================================

pub const SIG_RSDP = "RSD PTR ";
pub const SIG_RSDT = "RSDT";
pub const SIG_XSDT = "XSDT";
pub const SIG_FADT = "FACP";
pub const SIG_MADT = "APIC";
pub const SIG_DSDT = "DSDT";
pub const SIG_SSDT = "SSDT";
pub const SIG_HPET = "HPET";
pub const SIG_MCFG = "MCFG";

// ============================================================================
// RSDP Structures
// ============================================================================

/// RSDP v1.0 (ACPI 1.0)
pub const RSDPDescriptor = extern struct {
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32 align(1),
};

/// RSDP v2.0 (ACPI 2.0+)
pub const RSDPDescriptor20 = extern struct {
    // ACPI 1.0 fields
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32 align(1),

    // ACPI 2.0+ fields
    length: u32 align(1),
    xsdt_address: u64 align(1),
    extended_checksum: u8,
    reserved: [3]u8,
};

// ============================================================================
// Generic Address Structure
// ============================================================================

pub const GenericAddressStructure = extern struct {
    address_space: u8 = 0,
    bit_width: u8 = 0,
    bit_offset: u8 = 0,
    access_size: u8 = 0,
    address: u64 align(1) = 0,

    pub const SPACE_SYSTEM_MEMORY: u8 = 0;
    pub const SPACE_SYSTEM_IO: u8 = 1;
    pub const SPACE_PCI_CONFIG: u8 = 2;
};

// ============================================================================
// FADT Field Offsets (from ACPI 6.4 spec)
// ============================================================================

const FADT_OFF_FIRMWARE_CTRL: u64 = 36;
const FADT_OFF_DSDT: u64 = 40;
const FADT_OFF_PREFERRED_PM: u64 = 45;
const FADT_OFF_SCI_INT: u64 = 46;
const FADT_OFF_SMI_CMD: u64 = 48;
const FADT_OFF_ACPI_ENABLE: u64 = 52;
const FADT_OFF_ACPI_DISABLE: u64 = 53;
const FADT_OFF_PM1A_EVT_BLK: u64 = 56;
const FADT_OFF_PM1B_EVT_BLK: u64 = 60;
const FADT_OFF_PM1A_CNT_BLK: u64 = 64;
const FADT_OFF_PM1B_CNT_BLK: u64 = 68;
const FADT_OFF_PM2_CNT_BLK: u64 = 72;
const FADT_OFF_PM_TMR_BLK: u64 = 76;
const FADT_OFF_GPE0_BLK: u64 = 80;
const FADT_OFF_GPE1_BLK: u64 = 84;
const FADT_OFF_PM1_EVT_LEN: u64 = 88;
const FADT_OFF_PM1_CNT_LEN: u64 = 89;
const FADT_OFF_FLAGS: u64 = 112;
const FADT_OFF_RESET_REG: u64 = 116;
const FADT_OFF_RESET_VALUE: u64 = 128;
const FADT_OFF_FADT_MINOR: u64 = 131;
const FADT_OFF_X_FIRMWARE_CTRL: u64 = 132;
const FADT_OFF_X_DSDT: u64 = 140;
const FADT_OFF_X_PM1A_EVT: u64 = 148;
const FADT_OFF_X_PM1B_EVT: u64 = 160;
const FADT_OFF_X_PM1A_CNT: u64 = 172;
const FADT_OFF_X_PM1B_CNT: u64 = 184;
const FADT_OFF_X_PM2_CNT: u64 = 196;
const FADT_OFF_X_PM_TMR: u64 = 208;
const FADT_OFF_X_GPE0: u64 = 220;
const FADT_OFF_X_GPE1: u64 = 232;

// SDT Header size
const SDT_HEADER_SIZE: u32 = 36;

// ============================================================================
// ACPI State
// ============================================================================

var initialized: bool = false;
var hhdm_offset: u64 = 0;

// RSDP info
var rsdp_address: u64 = 0;
var rsdp_is_virtual: bool = false;
var acpi_revision: u8 = 0;
var rsdt_address: u64 = 0;
var xsdt_address: u64 = 0;
var use_xsdt: bool = false;
var oem_id: [6]u8 = [_]u8{0} ** 6;

// FADT info
var fadt_phys_addr: u64 = 0;
var fadt_length: u32 = 0;
var pm1a_control_block: u32 = 0;
var pm1b_control_block: u32 = 0;
var pm1a_event_block: u32 = 0;
var pm1b_event_block: u32 = 0;
var pm_timer_block: u32 = 0;
var smi_command_port: u32 = 0;
var acpi_enable_val: u8 = 0;
var acpi_disable_val: u8 = 0;
var sci_interrupt: u16 = 0;
var fadt_flags: u32 = 0;

// Sleep type values from DSDT _S5
var slp_typa: u16 = 0;
var slp_typb: u16 = 0;
var s5_found: bool = false;

// Reset register
var reset_reg: GenericAddressStructure = .{};
var reset_value: u8 = 0;
var has_reset_reg: bool = false;

// ACPI state
var acpi_enabled: bool = false;
var hw_acpi_enabled: bool = false;

// Statistics
var tables_found: u32 = 0;

// ============================================================================
// Limine RSDP Request
// ============================================================================

pub export var rsdp_request: limine.RsdpRequest linksection(".limine_requests") = .{};

// ============================================================================
// Safe Unaligned Read Helpers
// ============================================================================

inline fn readU8At(base: u64, offset: u64) u8 {
    const ptr: *const u8 = @ptrFromInt(base + offset);
    return ptr.*;
}

inline fn readU16At(base: u64, offset: u64) u16 {
    const ptr: *align(1) const u16 = @ptrFromInt(base + offset);
    return ptr.*;
}

inline fn readU32At(base: u64, offset: u64) u32 {
    const ptr: *align(1) const u32 = @ptrFromInt(base + offset);
    return ptr.*;
}

inline fn readU64At(base: u64, offset: u64) u64 {
    const ptr: *align(1) const u64 = @ptrFromInt(base + offset);
    return ptr.*;
}

fn readBytesAt(base: u64, offset: u64, out: []u8) void {
    for (0..out.len) |i| {
        out[i] = readU8At(base, offset + i);
    }
}

// ============================================================================
// SDT Header Operations (unaligned safe)
// ============================================================================

fn readSDTSignature(virt: u64) [4]u8 {
    var sig: [4]u8 = undefined;
    readBytesAt(virt, 0, &sig);
    return sig;
}

fn readSDTLength(virt: u64) u32 {
    return readU32At(virt, 4);
}

fn readSDTRevision(virt: u64) u8 {
    return readU8At(virt, 8);
}

fn readSDTOemId(virt: u64) [6]u8 {
    var id: [6]u8 = undefined;
    readBytesAt(virt, 10, &id);
    return id;
}

fn readSDTOemTableId(virt: u64) [8]u8 {
    var id: [8]u8 = undefined;
    readBytesAt(virt, 16, &id);
    return id;
}

fn validateSDTChecksum(virt: u64, length: u32) bool {
    if (length == 0 or length > 0x200000) return false;
    var sum: u8 = 0;
    for (0..length) |i| {
        sum +%= readU8At(virt, i);
    }
    return sum == 0;
}

// ============================================================================
// GAS (Generic Address Structure) reading
// ============================================================================

fn readGAS(base: u64, offset: u64) GenericAddressStructure {
    return .{
        .address_space = readU8At(base, offset),
        .bit_width = readU8At(base, offset + 1),
        .bit_offset = readU8At(base, offset + 2),
        .access_size = readU8At(base, offset + 3),
        .address = readU64At(base, offset + 4),
    };
}

// ============================================================================
// Initialization
// ============================================================================

pub fn init() bool {
    serial.writeString("[ACPI] Initializing ACPI driver...\n");

    // Get HHDM offset
    hhdm_offset = pmm.getHhdmOffset();

    // Get RSDP from Limine
    if (rsdp_request.response) |response| {
        rsdp_address = response.address;
        serial.writeString("[ACPI] RSDP response addr: 0x");
        printHex64(rsdp_address);
        serial.writeString("\n");
    } else {
        serial.writeString("[ACPI] No RSDP from bootloader\n");
        serial.writeString("[ACPI] Using QEMU-only fallback mode\n");
        initialized = true;
        return true;
    }

    // Detect if address is already virtual (HHDM-mapped by Limine)
    rsdp_is_virtual = rsdp_address >= hhdm_offset;
    if (rsdp_is_virtual) {
        serial.writeString("[ACPI] RSDP is virtual (Limine HHDM)\n");
    } else {
        serial.writeString("[ACPI] RSDP is physical\n");
    }

    // Parse RSDP
    if (!parseRSDP()) {
        serial.writeString("[ACPI] Failed to parse RSDP, using fallback\n");
        initialized = true;
        return true;
    }

    // Parse root table (RSDT or XSDT)
    if (!parseRootTable()) {
        serial.writeString("[ACPI] Failed to parse root table, using fallback\n");
        initialized = true;
        return true;
    }

    // Enumerate tables
    enumerateTables();

    // Find and parse FADT
    if (findTable(SIG_FADT)) |fadt_addr| {
        parseFADT(fadt_addr);
    } else {
        serial.writeString("[ACPI] FADT not found\n");
    }

    initialized = true;

    serial.writeString("[ACPI] ═══════════════════════════════\n");
    serial.writeString("[ACPI] ACPI initialized successfully!\n");
    serial.writeString("[ACPI] Revision: ");
    if (acpi_revision == 0) {
        serial.writeString("1.0");
    } else {
        serial.writeString("2.0+");
    }
    serial.writeString(", Tables: ");
    printDec(tables_found);
    serial.writeString(", ACPI: ");
    if (acpi_enabled) {
        serial.writeString("ENABLED");
    } else {
        serial.writeString("FALLBACK");
    }
    serial.writeString("\n");
    serial.writeString("[ACPI] ═══════════════════════════════\n");

    return true;
}

// ============================================================================
// RSDP Parsing
// ============================================================================

fn parseRSDP() bool {
    // If Limine gave virtual address, use directly; otherwise add HHDM
    const rsdp_virt = if (rsdp_is_virtual) rsdp_address else hhdm_offset + rsdp_address;

    serial.writeString("[ACPI] RSDP virt: 0x");
    printHex64(rsdp_virt);
    serial.writeString("\n");

    // Read and verify signature
    var sig: [8]u8 = undefined;
    readBytesAt(rsdp_virt, 0, &sig);

    if (!std.mem.eql(u8, &sig, SIG_RSDP)) {
        serial.writeString("[ACPI] Invalid RSDP signature: '");
        for (sig) |c| {
            if (c >= 0x20 and c < 0x7F) serial.writeChar(c) else serial.writeChar('.');
        }
        serial.writeString("'\n");
        return false;
    }
    serial.writeString("[ACPI] RSDP signature OK\n");

    // Verify v1 checksum (first 20 bytes)
    var sum: u8 = 0;
    for (0..20) |i| {
        sum +%= readU8At(rsdp_virt, i);
    }
    if (sum != 0) {
        serial.writeString("[ACPI] RSDP v1 checksum failed\n");
        return false;
    }
    serial.writeString("[ACPI] RSDP checksum OK\n");

    // Read OEM ID
    readBytesAt(rsdp_virt, 9, &oem_id);
    serial.writeString("[ACPI] OEM: '");
    for (oem_id) |c| {
        if (c >= 0x20 and c < 0x7F) serial.writeChar(c) else serial.writeChar(' ');
    }
    serial.writeString("'\n");

    // Read revision
    acpi_revision = readU8At(rsdp_virt, 15);

    if (acpi_revision == 0) {
        // ACPI 1.0 - use RSDT
        serial.writeString("[ACPI] ACPI Revision: 1.0\n");
        rsdt_address = readU32At(rsdp_virt, 16);
        use_xsdt = false;

        serial.writeString("[ACPI] RSDT at: 0x");
        printHex64(rsdt_address);
        serial.writeString("\n");
    } else {
        // ACPI 2.0+ - prefer XSDT
        serial.writeString("[ACPI] ACPI Revision: 2.0+\n");

        // Verify extended checksum
        const ext_length = readU32At(rsdp_virt, 20);
        if (ext_length > 0 and ext_length <= 256) {
            var sum2: u8 = 0;
            for (0..ext_length) |i| {
                sum2 +%= readU8At(rsdp_virt, i);
            }
            if (sum2 != 0) {
                serial.writeString("[ACPI] RSDP extended checksum failed\n");
                return false;
            }
            serial.writeString("[ACPI] Extended checksum OK\n");
        }

        // Read XSDT address
        const xsdt_addr = readU64At(rsdp_virt, 24);
        const rsdt_addr = readU32At(rsdp_virt, 16);

        if (xsdt_addr != 0) {
            xsdt_address = xsdt_addr;
            use_xsdt = true;
            serial.writeString("[ACPI] XSDT at: 0x");
            printHex64(xsdt_address);
            serial.writeString("\n");
        } else {
            rsdt_address = rsdt_addr;
            use_xsdt = false;
            serial.writeString("[ACPI] RSDT at: 0x");
            printHex64(rsdt_address);
            serial.writeString("\n");
        }
    }

    return true;
}

// ============================================================================
// Root Table Parsing
// ============================================================================

fn parseRootTable() bool {
    const table_phys = if (use_xsdt) xsdt_address else rsdt_address;
    if (table_phys == 0) {
        serial.writeString("[ACPI] Root table address is 0\n");
        return false;
    }

    const table_virt = hhdm_offset + table_phys;

    // Read header
    const sig = readSDTSignature(table_virt);
    const length = readSDTLength(table_virt);

    serial.writeString("[ACPI] Root table: '");
    for (sig) |c| {
        if (c >= 0x20 and c < 0x7F) serial.writeChar(c) else serial.writeChar('.');
    }
    serial.writeString("' length=");
    printDec(length);
    serial.writeString("\n");

    // Sanity check length
    if (length < SDT_HEADER_SIZE or length > 0x100000) {
        serial.writeString("[ACPI] Root table invalid length\n");
        return false;
    }

    // Validate checksum
    if (!validateSDTChecksum(table_virt, length)) {
        serial.writeString("[ACPI] Root table checksum failed\n");
        return false;
    }
    serial.writeString("[ACPI] Root table checksum OK\n");

    // Count entries
    const entry_size: u32 = if (use_xsdt) 8 else 4;
    const entries_size = length - SDT_HEADER_SIZE;
    const entry_count = entries_size / entry_size;

    serial.writeString("[ACPI] Entries: ");
    printDec(entry_count);
    serial.writeString("\n");

    tables_found = entry_count;
    return true;
}

// ============================================================================
// Table Enumeration
// ============================================================================

fn enumerateTables() void {
    const table_phys = if (use_xsdt) xsdt_address else rsdt_address;
    if (table_phys == 0) return;

    const table_virt = hhdm_offset + table_phys;
    const length = readSDTLength(table_virt);
    const entry_size: u32 = if (use_xsdt) 8 else 4;

    if (length < SDT_HEADER_SIZE) return;

    const entries_size = length - SDT_HEADER_SIZE;
    const entry_count = entries_size / entry_size;
    const entries_base = table_virt + SDT_HEADER_SIZE;

    serial.writeString("[ACPI] ─── Table List ───\n");

    for (0..entry_count) |i| {
        var entry_phys: u64 = 0;

        if (use_xsdt) {
            entry_phys = readU64At(entries_base, i * 8);
        } else {
            entry_phys = readU32At(entries_base, i * 4);
        }

        if (entry_phys == 0) continue;

        const entry_virt = hhdm_offset + entry_phys;
        const entry_sig = readSDTSignature(entry_virt);
        const entry_len = readSDTLength(entry_virt);
        const entry_rev = readSDTRevision(entry_virt);

        serial.writeString("[ACPI]   [");
        printDec(i);
        serial.writeString("] '");
        for (entry_sig) |c| {
            if (c >= 0x20 and c < 0x7F) serial.writeChar(c) else serial.writeChar('.');
        }
        serial.writeString("' rev=");
        printDec(entry_rev);
        serial.writeString(" len=");
        printDec(entry_len);
        serial.writeString(" @ 0x");
        printHex64(entry_phys);
        serial.writeString("\n");
    }

    serial.writeString("[ACPI] ─────────────────\n");
}

// ============================================================================
// Table Finder
// ============================================================================

pub fn findTable(signature: *const [4]u8) ?u64 {
    const table_phys = if (use_xsdt) xsdt_address else rsdt_address;
    if (table_phys == 0) return null;

    const table_virt = hhdm_offset + table_phys;
    const length = readSDTLength(table_virt);

    if (length < SDT_HEADER_SIZE) return null;

    const entry_size: u32 = if (use_xsdt) 8 else 4;
    const entries_size = length - SDT_HEADER_SIZE;
    const entry_count = entries_size / entry_size;
    const entries_base = table_virt + SDT_HEADER_SIZE;

    for (0..entry_count) |i| {
        var entry_phys: u64 = 0;

        if (use_xsdt) {
            entry_phys = readU64At(entries_base, i * 8);
        } else {
            entry_phys = readU32At(entries_base, i * 4);
        }

        if (entry_phys == 0) continue;

        const entry_virt = hhdm_offset + entry_phys;
        const entry_sig = readSDTSignature(entry_virt);

        if (std.mem.eql(u8, &entry_sig, signature)) {
            return entry_phys;
        }
    }

    return null;
}

// ============================================================================
// FADT Parsing
// ============================================================================

fn parseFADT(fadt_phys: u64) void {
    const fadt_virt = hhdm_offset + fadt_phys;

    // Read and validate
    const length = readSDTLength(fadt_virt);
    if (length < 116) {
        serial.writeString("[ACPI] FADT too small: ");
        printDec(length);
        serial.writeString("\n");
        return;
    }

    if (!validateSDTChecksum(fadt_virt, length)) {
        serial.writeString("[ACPI] FADT checksum failed\n");
        return;
    }

    fadt_phys_addr = fadt_phys;
    fadt_length = length;

    serial.writeString("[ACPI] FADT length: ");
    printDec(length);
    serial.writeString("\n");

    // Read basic fields
    smi_command_port = readU32At(fadt_virt, FADT_OFF_SMI_CMD);
    acpi_enable_val = readU8At(fadt_virt, FADT_OFF_ACPI_ENABLE);
    acpi_disable_val = readU8At(fadt_virt, FADT_OFF_ACPI_DISABLE);
    sci_interrupt = readU16At(fadt_virt, FADT_OFF_SCI_INT);

    // PM blocks (legacy 32-bit)
    pm1a_event_block = readU32At(fadt_virt, FADT_OFF_PM1A_EVT_BLK);
    pm1b_event_block = readU32At(fadt_virt, FADT_OFF_PM1B_EVT_BLK);
    pm1a_control_block = readU32At(fadt_virt, FADT_OFF_PM1A_CNT_BLK);
    pm1b_control_block = readU32At(fadt_virt, FADT_OFF_PM1B_CNT_BLK);
    pm_timer_block = readU32At(fadt_virt, FADT_OFF_PM_TMR_BLK);

    // Try 64-bit extended addresses if available
    if (length >= 184) {
        const x_pm1a = readGAS(fadt_virt, FADT_OFF_X_PM1A_CNT);
        if (x_pm1a.address != 0) {
            pm1a_control_block = @truncate(x_pm1a.address);
        }

        const x_pm1b = readGAS(fadt_virt, FADT_OFF_X_PM1B_CNT);
        if (x_pm1b.address != 0) {
            pm1b_control_block = @truncate(x_pm1b.address);
        }
    }

    // Read flags
    if (length >= 116) {
        fadt_flags = readU32At(fadt_virt, FADT_OFF_FLAGS);
    }

    serial.writeString("[ACPI] PM1a_CNT:  0x");
    printHex32(pm1a_control_block);
    serial.writeString("\n");

    if (pm1b_control_block != 0) {
        serial.writeString("[ACPI] PM1b_CNT:  0x");
        printHex32(pm1b_control_block);
        serial.writeString("\n");
    }

    serial.writeString("[ACPI] SMI_CMD:   0x");
    printHex32(smi_command_port);
    serial.writeString("\n");

    serial.writeString("[ACPI] SCI_INT:   ");
    printDec(sci_interrupt);
    serial.writeString("\n");

    serial.writeString("[ACPI] PM_TMR:    0x");
    printHex32(pm_timer_block);
    serial.writeString("\n");

    // Read reset register
    if (length >= 129) {
        reset_reg = readGAS(fadt_virt, FADT_OFF_RESET_REG);
        reset_value = readU8At(fadt_virt, FADT_OFF_RESET_VALUE);
        has_reset_reg = reset_reg.address != 0;

        if (has_reset_reg) {
            serial.writeString("[ACPI] Reset: space=");
            printDec(reset_reg.address_space);
            serial.writeString(" addr=0x");
            printHex64(reset_reg.address);
            serial.writeString(" val=0x");
            printHex8(reset_value);
            serial.writeString("\n");
        }
    }

    // Parse DSDT for _S5 sleep type values
    parseDSDT(fadt_virt, length);

    // Enable ACPI if not already enabled
    enableACPI();

    acpi_enabled = true;
    serial.writeString("[ACPI] FADT parsed OK\n");
}

// ============================================================================
// Enable ACPI Mode
// ============================================================================

fn enableACPI() void {
    // Check if ACPI is already enabled
    if (pm1a_control_block != 0) {
        const pm1a_val = inw(@truncate(pm1a_control_block));
        if ((pm1a_val & 1) != 0) {
            serial.writeString("[ACPI] ACPI already enabled\n");
            hw_acpi_enabled = true;
            return;
        }
    }

    // Enable ACPI via SMI command
    if (smi_command_port != 0 and acpi_enable_val != 0) {
        serial.writeString("[ACPI] Enabling ACPI via SMI_CMD...\n");
        outb(@truncate(smi_command_port), acpi_enable_val);

        // Wait for ACPI to be enabled (SCI_EN bit in PM1a_CNT)
        if (pm1a_control_block != 0) {
            var timeout: u32 = 0;
            while (timeout < 1000000) : (timeout += 1) {
                const val = inw(@truncate(pm1a_control_block));
                if ((val & 1) != 0) {
                    serial.writeString("[ACPI] ACPI enabled after ");
                    printDec(timeout);
                    serial.writeString(" iterations\n");
                    hw_acpi_enabled = true;
                    return;
                }
            }
            serial.writeString("[ACPI] ACPI enable timeout\n");
        }
    } else {
        serial.writeString("[ACPI] No SMI command port (hardware-reduced ACPI?)\n");
        hw_acpi_enabled = true; // Assume enabled
    }
}

// ============================================================================
// DSDT Parsing for _S5 Sleep Type
// ============================================================================

fn parseDSDT(fadt_virt: u64, fadt_len: u32) void {
    // Get DSDT address
    var dsdt_phys: u64 = 0;

    // Try X_DSDT first (64-bit)
    if (fadt_len >= 148) {
        dsdt_phys = readU64At(fadt_virt, FADT_OFF_X_DSDT);
    }

    // Fall back to legacy DSDT (32-bit)
    if (dsdt_phys == 0) {
        dsdt_phys = readU32At(fadt_virt, FADT_OFF_DSDT);
    }

    if (dsdt_phys == 0) {
        serial.writeString("[ACPI] No DSDT, using default S5\n");
        slp_typa = 0;
        slp_typb = 0;
        return;
    }

    serial.writeString("[ACPI] DSDT at: 0x");
    printHex64(dsdt_phys);
    serial.writeString("\n");

    const dsdt_virt = hhdm_offset + dsdt_phys;
    const dsdt_length = readSDTLength(dsdt_virt);

    // Sanity check
    if (dsdt_length < SDT_HEADER_SIZE or dsdt_length > 0x200000) {
        serial.writeString("[ACPI] DSDT invalid length: ");
        printDec(dsdt_length);
        serial.writeString(", using defaults\n");
        slp_typa = 0;
        slp_typb = 0;
        return;
    }

    serial.writeString("[ACPI] DSDT length: ");
    printDec(dsdt_length);
    serial.writeString("\n");

    // Search for "_S5_" in AML bytecode
    const aml_start = dsdt_virt + SDT_HEADER_SIZE;
    const aml_length: u64 = dsdt_length - SDT_HEADER_SIZE;

    if (aml_length < 8) {
        slp_typa = 0;
        slp_typb = 0;
        return;
    }

    // Scan for "_S5_" pattern
    var offset: u64 = 0;
    while (offset + 4 < aml_length) : (offset += 1) {
        if (readU8At(aml_start, offset) == '_' and
            readU8At(aml_start, offset + 1) == 'S' and
            readU8At(aml_start, offset + 2) == '5' and
            readU8At(aml_start, offset + 3) == '_')
        {
            serial.writeString("[ACPI] Found _S5_ at offset ");
            printDec(offset);
            serial.writeString("\n");

            // Search forward for PackageOp (0x12)
            var p = offset + 4;
            const max_search = if (p + 32 < aml_length) p + 32 else aml_length;

            while (p < max_search) : (p += 1) {
                if (readU8At(aml_start, p) == 0x12) {
                    // Found PackageOp
                    p += 1; // Skip PackageOp

                    // Skip PkgLength (variable length encoding)
                    const pkg_lead = readU8At(aml_start, p);
                    if ((pkg_lead & 0xC0) == 0) {
                        p += 1; // 1-byte length
                    } else {
                        const extra = ((pkg_lead >> 6) & 0x3);
                        p += 1 + extra;
                    }

                    // Skip NumElements
                    p += 1;

                    // Read SLP_TYPa
                    if (p < aml_length) {
                        if (readU8At(aml_start, p) == 0x0A) {
                            // BytePrefix
                            p += 1;
                            if (p < aml_length) {
                                slp_typa = readU8At(aml_start, p);
                                p += 1;
                            }
                        } else {
                            slp_typa = readU8At(aml_start, p);
                            p += 1;
                        }
                    }

                    // Read SLP_TYPb
                    if (p < aml_length) {
                        if (readU8At(aml_start, p) == 0x0A) {
                            p += 1;
                            if (p < aml_length) {
                                slp_typb = readU8At(aml_start, p);
                            }
                        } else {
                            slp_typb = readU8At(aml_start, p);
                        }
                    }

                    s5_found = true;
                    serial.writeString("[ACPI] SLP_TYPa=");
                    printDec(slp_typa);
                    serial.writeString(" SLP_TYPb=");
                    printDec(slp_typb);
                    serial.writeString("\n");
                    return;
                }
            }
        }
    }

    serial.writeString("[ACPI] _S5 not found in DSDT, using defaults\n");
    slp_typa = 5; // Common default
    slp_typb = 0;
}

// ============================================================================
// Power Management - Shutdown
// ============================================================================

pub fn shutdown() void {
    serial.writeString("[ACPI] ══════════════════════════\n");
    serial.writeString("[ACPI] Initiating SHUTDOWN...\n");
    serial.writeString("[ACPI] ══════════════════════════\n");

    if (acpi_enabled and pm1a_control_block != 0) {
        // ACPI S5 shutdown
        const slp_en: u16 = 1 << 13; // SLP_EN bit
        const value: u16 = (slp_typa << 10) | slp_en;

        serial.writeString("[ACPI] PM1a_CNT=0x");
        printHex32(pm1a_control_block);
        serial.writeString(" value=0x");
        printHex16(value);
        serial.writeString("\n");

        // Write to PM1a_CNT
        outw(@truncate(pm1a_control_block), value);

        // Also write PM1b if present
        if (pm1b_control_block != 0) {
            const value_b: u16 = (slp_typb << 10) | slp_en;
            outw(@truncate(pm1b_control_block), value_b);
        }

        // Wait for shutdown to take effect
        busyWait(10000000);
        serial.writeString("[ACPI] ACPI S5 shutdown did not take effect\n");
    }

    // Fallback chain
    serial.writeString("[ACPI] Trying QEMU shutdown...\n");
    qemuShutdown();
}

// ============================================================================
// Power Management - Reboot
// ============================================================================

pub fn reboot() void {
    serial.writeString("[ACPI] ══════════════════════════\n");
    serial.writeString("[ACPI] Initiating REBOOT...\n");
    serial.writeString("[ACPI] ══════════════════════════\n");

    // Method 1: ACPI reset register
    if (acpi_enabled and has_reset_reg) {
        serial.writeString("[ACPI] Using ACPI reset register\n");

        switch (reset_reg.address_space) {
            GenericAddressStructure.SPACE_SYSTEM_IO => {
                serial.writeString("[ACPI] I/O space reset at 0x");
                printHex64(reset_reg.address);
                serial.writeString("\n");
                outb(@truncate(reset_reg.address), reset_value);
            },
            GenericAddressStructure.SPACE_SYSTEM_MEMORY => {
                serial.writeString("[ACPI] Memory space reset at 0x");
                printHex64(reset_reg.address);
                serial.writeString("\n");
                const addr: *volatile u8 = @ptrFromInt(hhdm_offset + reset_reg.address);
                addr.* = reset_value;
            },
            else => {
                serial.writeString("[ACPI] Unsupported reset address space: ");
                printDec(reset_reg.address_space);
                serial.writeString("\n");
            },
        }

        busyWait(10000000);
        serial.writeString("[ACPI] ACPI reset did not take effect\n");
    }

    // Method 2: Keyboard controller
    serial.writeString("[ACPI] Trying keyboard controller reset...\n");
    keyboardReboot();
}

// ============================================================================
// Fallback Methods
// ============================================================================

fn qemuShutdown() void {
    // QEMU PIIX4 PM
    outw(0x604, 0x2000);
    busyWait(1000000);

    // Bochs/older QEMU
    outw(0xB004, 0x2000);
    busyWait(1000000);

    // Virtualbox
    outw(0x4004, 0x3400);
    busyWait(1000000);

    // isa-debug-exit
    outl(0xF4, 0x00);
    busyWait(1000000);

    serial.writeString("[ACPI] All shutdown methods failed\n");
    serial.writeString("[ACPI] Halting CPU...\n");

    // Final halt
    while (true) {
        asm volatile ("cli; hlt");
    }
}

fn keyboardReboot() void {
    // Wait for keyboard controller input buffer to be empty
    var timeout: u32 = 0;
    while (timeout < 100000) : (timeout += 1) {
        if ((inb(0x64) & 0x02) == 0) break;
        asm volatile ("pause");
    }

    // Send CPU reset command to keyboard controller
    outb(0x64, 0xFE);
    busyWait(10000000);

    // If keyboard reset failed, try triple fault
    serial.writeString("[ACPI] Keyboard reset failed, triple faulting...\n");
    tripleFault();
}

fn tripleFault() noreturn {
    var null_idt: [10]u8 = [_]u8{0} ** 10;
    asm volatile ("lidt (%[idt])"
        :
        : [idt] "r" (&null_idt),
    );
    asm volatile ("int $3");

    while (true) {
        asm volatile ("hlt");
    }
}

fn busyWait(count: u32) void {
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        asm volatile ("pause");
    }
}

// ============================================================================
// Port I/O
// ============================================================================

inline fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [port] "{dx}" (port),
          [value] "{al}" (value),
    );
}

inline fn outw(port: u16, value: u16) void {
    asm volatile ("outw %[value], %[port]"
        :
        : [port] "{dx}" (port),
          [value] "{ax}" (value),
    );
}

inline fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [port] "{dx}" (port),
          [value] "{eax}" (value),
    );
}

inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

inline fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "{dx}" (port),
    );
}

// ============================================================================
// Public Getters
// ============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn isACPIEnabled() bool {
    return acpi_enabled;
}

pub fn getRevision() u8 {
    return acpi_revision;
}

pub fn getTablesFound() u32 {
    return tables_found;
}

pub fn getPM1aControlBlock() u32 {
    return pm1a_control_block;
}

pub fn getPM1bControlBlock() u32 {
    return pm1b_control_block;
}

pub fn getSleepTypeA() u16 {
    return slp_typa;
}

pub fn getSleepTypeB() u16 {
    return slp_typb;
}

pub fn hasResetRegister() bool {
    return has_reset_reg;
}

pub fn getResetRegAddress() u64 {
    return reset_reg.address;
}

pub fn getSMICommandPort() u32 {
    return smi_command_port;
}

pub fn getSCIInterrupt() u16 {
    return sci_interrupt;
}

pub fn getPMTimerBlock() u32 {
    return pm_timer_block;
}

pub fn getFADTFlags() u32 {
    return fadt_flags;
}

pub fn isS5Found() bool {
    return s5_found;
}

pub fn isHWACPIEnabled() bool {
    return hw_acpi_enabled;
}

pub fn getOemId() [6]u8 {
    return oem_id;
}

// ============================================================================
// Print Helpers
// ============================================================================

fn printHex64(value: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        const nibble: usize = @truncate((value >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printHex32(value: u32) void {
    const hex = "0123456789ABCDEF";
    const v: u64 = value;
    var i: u6 = 28;
    while (true) {
        const nibble: usize = @truncate((v >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printHex16(value: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[@as(usize, (value >> 12) & 0xF)]);
    serial.writeChar(hex[@as(usize, (value >> 8) & 0xF)]);
    serial.writeChar(hex[@as(usize, (value >> 4) & 0xF)]);
    serial.writeChar(hex[@as(usize, value & 0xF)]);
}

fn printHex8(value: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(value >> 4) & 0xF]);
    serial.writeChar(hex[value & 0xF]);
}

fn printDec(value: anytype) void {
    const T = @TypeOf(value);
    const v: u64 = switch (@typeInfo(T)) {
        .int, .comptime_int => @intCast(value),
        else => @as(u64, value),
    };

    if (v == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;
    while (n > 0) : (i += 1) {
        buf[i] = @truncate((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
