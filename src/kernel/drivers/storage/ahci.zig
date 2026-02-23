//! Zamrud OS - AHCI (Advanced Host Controller Interface) Driver
//! B2.4: SATA disk access via DMA
//!
//! AHCI is the standard interface for SATA controllers.
//! It uses memory-mapped I/O (MMIO) for register access and
//! DMA for data transfer, making it much faster than ATA PIO.
//!
//! Architecture:
//!   PCI Device (class 01h, subclass 06h, prog-if 01h)
//!     └── HBA (Host Bus Adapter) — BAR5 MMIO
//!           ├── Generic Host Control registers
//!           └── Port 0..31
//!                 ├── Command List (32 slots)
//!                 │     └── Command Table
//!                 │           ├── Command FIS (H2D register)
//!                 │           └── PRDT (Physical Region Descriptor Table)
//!                 └── FIS Receive Buffer

const serial = @import("../serial/serial.zig");
const pci = @import("../pci/pci.zig");
const pmm = @import("../../mm/pmm.zig");

// =============================================================================
// AHCI Constants
// =============================================================================

pub const SECTOR_SIZE: usize = 512;

// PCI Class/Subclass/ProgIF for AHCI
const AHCI_CLASS: u8 = 0x01; // Mass Storage
const AHCI_SUBCLASS: u8 = 0x06; // SATA
const AHCI_PROGIF: u8 = 0x01; // AHCI 1.0

// HBA Generic Host Control Register Offsets
const HBA_CAP: u32 = 0x00; // Host Capabilities
const HBA_GHC: u32 = 0x04; // Global Host Control
const HBA_IS: u32 = 0x08; // Interrupt Status
const HBA_PI: u32 = 0x0C; // Ports Implemented
const HBA_VS: u32 = 0x10; // Version
const HBA_CAP2: u32 = 0x24; // Host Capabilities Extended

// GHC Bits
const GHC_AE: u32 = 1 << 31; // AHCI Enable
const GHC_IE: u32 = 1 << 1; // Interrupt Enable
const GHC_HR: u32 = 1 << 0; // HBA Reset

// Port Register Offsets (from port base)
const PORT_CLB: u32 = 0x00; // Command List Base Address (low)
const PORT_CLBU: u32 = 0x04; // Command List Base Address (high)
const PORT_FB: u32 = 0x08; // FIS Base Address (low)
const PORT_FBU: u32 = 0x0C; // FIS Base Address (high)
const PORT_IS: u32 = 0x10; // Interrupt Status
const PORT_IE: u32 = 0x14; // Interrupt Enable
const PORT_CMD: u32 = 0x18; // Command and Status
const PORT_TFD: u32 = 0x20; // Task File Data
const PORT_SIG: u32 = 0x24; // Signature
const PORT_SSTS: u32 = 0x28; // SATA Status (SCR0: SStatus)
const PORT_SCTL: u32 = 0x2C; // SATA Control (SCR2: SControl)
const PORT_SERR: u32 = 0x30; // SATA Error (SCR1: SError)
const PORT_SACT: u32 = 0x34; // SATA Active
const PORT_CI: u32 = 0x38; // Command Issue

// PORT_CMD bits
const PORT_CMD_ST: u32 = 1 << 0; // Start
const PORT_CMD_SUD: u32 = 1 << 1; // Spin-Up Device
const PORT_CMD_POD: u32 = 1 << 2; // Power On Device
const PORT_CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
const PORT_CMD_FR: u32 = 1 << 14; // FIS Receive Running
const PORT_CMD_CR: u32 = 1 << 15; // Command List Running
const PORT_CMD_ICC_ACTIVE: u32 = 1 << 28; // Interface Communication Control

// PORT_TFD bits
const PORT_TFD_BSY: u32 = 1 << 7;
const PORT_TFD_DRQ: u32 = 1 << 3;
const PORT_TFD_ERR: u32 = 1 << 0;

// SATA Status (SStatus) — Device Detection
const SSTS_DET_MASK: u32 = 0x0F;
const SSTS_DET_PRESENT: u32 = 0x03; // Device present and PHY established
const SSTS_IPM_MASK: u32 = 0x0F00;
const SSTS_IPM_ACTIVE: u32 = 0x0100; // Interface active

// Port Signature Values
const SATA_SIG_ATA: u32 = 0x00000101; // SATA drive
const SATA_SIG_ATAPI: u32 = 0xEB140101; // SATAPI drive
const SATA_SIG_SEMB: u32 = 0xC33C0101; // Enclosure management bridge
const SATA_SIG_PM: u32 = 0x96690101; // Port multiplier

// FIS Types
const FIS_TYPE_REG_H2D: u8 = 0x27; // Register FIS - Host to Device
const FIS_TYPE_REG_D2H: u8 = 0x34; // Register FIS - Device to Host
const FIS_TYPE_DMA_ACT: u8 = 0x39; // DMA Activate FIS
const FIS_TYPE_DMA_SETUP: u8 = 0x41; // DMA Setup FIS
const FIS_TYPE_DATA: u8 = 0x46; // Data FIS
const FIS_TYPE_BIST: u8 = 0x58; // BIST Activate FIS
const FIS_TYPE_PIO_SETUP: u8 = 0x5F; // PIO Setup FIS
const FIS_TYPE_DEV_BITS: u8 = 0xA1; // Set Device Bits FIS

// ATA Commands
const ATA_CMD_READ_DMA_EX: u8 = 0x25; // READ DMA EXT (LBA48)
const ATA_CMD_WRITE_DMA_EX: u8 = 0x35; // WRITE DMA EXT (LBA48)
const ATA_CMD_IDENTIFY: u8 = 0xEC; // IDENTIFY DEVICE
const ATA_CMD_CACHE_FLUSH_EX: u8 = 0xEA; // FLUSH CACHE EXT

// =============================================================================
// AHCI Structures (in-memory, for DMA)
// =============================================================================

/// Command List Entry (Command Header) — 32 bytes each, 32 per port
const CommandHeader = extern struct {
    /// DW0: Description info
    flags: u16, // CFL (bits 0-4), A, W, P, R, B, C, PMP
    prdtl: u16, // Physical Region Descriptor Table Length (entries)
    /// DW1: PRD Byte Count
    prdbc: u32, // Physical Region Descriptor Byte Count (transferred)
    /// DW2-3: Command Table Base Address
    ctba: u32, // Command Table Descriptor Base Address (low, 128-byte aligned)
    ctbau: u32, // Command Table Descriptor Base Address (high)
    /// DW4-7: Reserved
    reserved: [4]u32,
};

comptime {
    if (@sizeOf(CommandHeader) != 32) @compileError("CommandHeader must be 32 bytes");
}

/// Physical Region Descriptor Table Entry — 16 bytes
const PrdtEntry = extern struct {
    dba: u32, // Data Base Address (low, word aligned)
    dbau: u32, // Data Base Address (high)
    reserved: u32, // Reserved
    dbc_i: u32, // Byte Count (bits 0-21, max 4MB), bit 31 = Interrupt on Completion
};

comptime {
    if (@sizeOf(PrdtEntry) != 16) @compileError("PrdtEntry must be 16 bytes");
}

/// FIS Register Host to Device — 20 bytes (padded to 64 in command table)
const FisRegH2D = extern struct {
    fis_type: u8, // FIS_TYPE_REG_H2D
    flags: u8, // bit 7: C (command/control), bits 0-3: PM Port
    command: u8, // ATA Command
    featurel: u8, // Feature low

    lba0: u8, // LBA bits 0-7
    lba1: u8, // LBA bits 8-15
    lba2: u8, // LBA bits 16-23
    device: u8, // Device register (bit 6 = LBA mode)

    lba3: u8, // LBA bits 24-31
    lba4: u8, // LBA bits 32-39
    lba5: u8, // LBA bits 40-47
    featureh: u8, // Feature high

    countl: u8, // Sector count low
    counth: u8, // Sector count high
    icc: u8, // Isochronous Command Completion
    control: u8, // Control

    reserved: [4]u8, // Reserved (pad to 20 bytes)
};

comptime {
    if (@sizeOf(FisRegH2D) != 20) @compileError("FisRegH2D must be 20 bytes");
}

// =============================================================================
// Port State
// =============================================================================

const MAX_PORTS: usize = 32;
const MAX_AHCI_DRIVES: usize = 8;
const CMD_SLOTS: usize = 32;

const AhciPort = struct {
    implemented: bool,
    connected: bool,
    is_atapi: bool,
    port_num: u8,

    /// Physical addresses of DMA structures
    clb_phys: u64, // Command List Base (1024 bytes)
    fb_phys: u64, // FIS Base (256 bytes)
    ct_phys: [CMD_SLOTS]u64, // Command Table per slot (256 bytes each)

    /// Drive info (from IDENTIFY)
    model: [41]u8,
    serial_str: [21]u8,
    sectors: u64,
    size_mb: u32,
    lba48: bool,

    pub fn init() AhciPort {
        return AhciPort{
            .implemented = false,
            .connected = false,
            .is_atapi = false,
            .port_num = 0,
            .clb_phys = 0,
            .fb_phys = 0,
            .ct_phys = [_]u64{0} ** CMD_SLOTS,
            .model = [_]u8{0} ** 41,
            .serial_str = [_]u8{0} ** 21,
            .sectors = 0,
            .size_mb = 0,
            .lba48 = false,
        };
    }
};

// =============================================================================
// Global State
// =============================================================================

var hba_base: u64 = 0; // MMIO base (via HHDM)
var hba_phys: u64 = 0; // Physical BAR5 address
var hhdm_offset: u64 = 0;

var ports: [MAX_AHCI_DRIVES]AhciPort = undefined;
var port_count: usize = 0;
var ahci_initialized: bool = false;
var ahci_detected: bool = false;

var pci_bus: u8 = 0;
var pci_dev: u8 = 0;
var pci_func: u8 = 0;
var pci_irq: u8 = 0;

// Data transfer buffer — 1 page, physically contiguous
var dma_buffer_phys: u64 = 0;
var dma_buffer_virt: u64 = 0;

// =============================================================================
// MMIO Access (via HHDM)
// =============================================================================

inline fn mmioRead32(offset: u32) u32 {
    const addr = hba_base + offset;
    return @as(*volatile u32, @ptrFromInt(addr)).*;
}

inline fn mmioWrite32(offset: u32, value: u32) void {
    const addr = hba_base + offset;
    @as(*volatile u32, @ptrFromInt(addr)).* = value;
}

inline fn portBase(port_num: u32) u32 {
    return 0x100 + port_num * 0x80;
}

inline fn portRead32(port_num: u32, reg: u32) u32 {
    return mmioRead32(portBase(port_num) + reg);
}

inline fn portWrite32(port_num: u32, reg: u32, value: u32) void {
    mmioWrite32(portBase(port_num) + reg, value);
}

// =============================================================================
// Initialization
// =============================================================================

pub fn init() bool {
    serial.writeString("[AHCI] Probing for AHCI controller...\n");

    hhdm_offset = pmm.getHhdmOffset();

    // B2.4: Ensure PCI bus is scanned before looking for AHCI
    // PCI might not be initialized yet if storage.init() runs before net.init()
    if (!pci.isInitialized()) {
        pci.init();
    }

    // 1. Find AHCI controller on PCI bus
    if (!findAhciController()) {
        serial.writeString("[AHCI] No AHCI controller found\n");
        return false;
    }

    ahci_detected = true;
    serial.writeString("[AHCI] Controller found at PCI ");
    printU8(pci_bus);
    serial.writeString(":");
    printU8(pci_dev);
    serial.writeString(".");
    printU8(pci_func);
    serial.writeString("\n");

    // 2. Read BAR5 (AHCI MMIO base)
    const bar5 = pci.readConfig(pci_bus, pci_dev, pci_func, 0x24);
    if (bar5 == 0 or (bar5 & 1) != 0) {
        serial.writeString("[AHCI] Invalid BAR5 (not MMIO)\n");
        return false;
    }

    hba_phys = bar5 & 0xFFFFF000;

    // Check for 64-bit BAR
    if ((bar5 & 0x06) == 0x04) {
        const bar5_hi = pci.readConfig(pci_bus, pci_dev, pci_func, 0x28);
        hba_phys |= @as(u64, bar5_hi) << 32;
    }

    // Access HBA via HHDM (direct physical-to-virtual translation)
    hba_base = hhdm_offset + hba_phys;

    serial.writeString("[AHCI] HBA MMIO at phys=0x");
    printHex64(hba_phys);
    serial.writeString(" virt=0x");
    printHex64(hba_base);
    serial.writeString("\n");

    // 3. Enable PCI bus mastering and memory space
    pci.enableBusMaster(&pci.getDevices()[findPciIndex()]);
    pci.enableMemorySpace(&pci.getDevices()[findPciIndex()]);

    // Read IRQ line
    pci_irq = pci.readConfigByte(pci_bus, pci_dev, pci_func, 0x3C);
    serial.writeString("[AHCI] IRQ line: ");
    printU8(pci_irq);
    serial.writeString("\n");

    // 4. Print version
    const version = mmioRead32(HBA_VS);
    serial.writeString("[AHCI] Version: ");
    printU8(@intCast((version >> 16) & 0xFF));
    serial.writeString(".");
    printU8(@intCast(version & 0xFF));
    serial.writeString("\n");

    // 5. Enable AHCI mode
    var ghc = mmioRead32(HBA_GHC);
    ghc |= GHC_AE;
    mmioWrite32(HBA_GHC, ghc);

    // 6. Read capabilities
    const cap = mmioRead32(HBA_CAP);
    const num_ports = (cap & 0x1F) + 1;
    const num_slots = ((cap >> 8) & 0x1F) + 1;
    const supports_64bit = (cap & (1 << 31)) != 0;

    serial.writeString("[AHCI] Ports: ");
    printU8(@intCast(num_ports));
    serial.writeString(", Cmd slots: ");
    printU8(@intCast(num_slots));
    if (supports_64bit) {
        serial.writeString(", 64-bit");
    }
    serial.writeString("\n");

    // 7. Allocate DMA transfer buffer (1 page = 4096 bytes = 8 sectors)
    dma_buffer_phys = pmm.allocPage() orelse {
        serial.writeString("[AHCI] Failed to allocate DMA buffer\n");
        return false;
    };
    dma_buffer_virt = hhdm_offset + dma_buffer_phys;

    // 8. Initialize ports
    const pi = mmioRead32(HBA_PI);
    serial.writeString("[AHCI] Ports Implemented: 0x");
    printHex32(pi);
    serial.writeString("\n");

    // Init port state
    for (&ports) |*p| {
        p.* = AhciPort.init();
    }
    port_count = 0;

    var port_num: u32 = 0;
    while (port_num < 32 and port_count < MAX_AHCI_DRIVES) : (port_num += 1) {
        if ((pi & (@as(u32, 1) << @intCast(port_num))) == 0) continue;

        if (initPort(port_num)) {
            port_count += 1;
        }
    }

    if (port_count == 0) {
        serial.writeString("[AHCI] No SATA devices found\n");
        pmm.freePage(dma_buffer_phys);
        return false;
    }

    // 9. Enable interrupts (global)
    ghc = mmioRead32(HBA_GHC);
    ghc |= GHC_IE;
    mmioWrite32(HBA_GHC, ghc);

    ahci_initialized = true;

    serial.writeString("[AHCI] Initialized with ");
    printU8(@intCast(port_count));
    serial.writeString(" device(s)\n");

    return true;
}

fn findAhciController() bool {
    const devices = pci.getDevices();
    for (devices) |dev| {
        if (dev.class_code == AHCI_CLASS and
            dev.subclass == AHCI_SUBCLASS)
        {
            pci_bus = dev.bus;
            pci_dev = dev.device;
            pci_func = dev.function;
            return true;
        }
    }
    return false;
}

fn findPciIndex() usize {
    const devices = pci.getDevices();
    for (devices, 0..) |dev, i| {
        if (dev.bus == pci_bus and dev.device == pci_dev and dev.function == pci_func) {
            return i;
        }
    }
    return 0;
}

// =============================================================================
// Port Initialization
// =============================================================================

fn initPort(port_num: u32) bool {
    // Check device detection
    const ssts = portRead32(port_num, PORT_SSTS);
    const det = ssts & SSTS_DET_MASK;
    const ipm = ssts & SSTS_IPM_MASK;

    if (det != SSTS_DET_PRESENT or ipm != SSTS_IPM_ACTIVE) {
        return false; // No device or not active
    }

    serial.writeString("[AHCI] Port ");
    printU8(@intCast(port_num));
    serial.writeString(": Device detected\n");

    // Check signature
    const sig = portRead32(port_num, PORT_SIG);
    const is_atapi = (sig == SATA_SIG_ATAPI);

    if (sig != SATA_SIG_ATA and sig != SATA_SIG_ATAPI) {
        serial.writeString("[AHCI]   Unknown signature: 0x");
        printHex32(sig);
        serial.writeString(" — skipping\n");
        return false;
    }

    if (is_atapi) {
        serial.writeString("[AHCI]   SATAPI device (optical) — skipping\n");
        return false;
    }

    // Stop port before configuring
    stopPort(port_num);

    // Allocate Command List (1KB) + FIS Receive (256 bytes)
    // Both fit in one 4KB page
    const cl_page = pmm.allocPage() orelse {
        serial.writeString("[AHCI]   Failed to alloc CL page\n");
        return false;
    };

    const clb_phys = cl_page;
    const fb_phys = cl_page + 1024; // FIS receive at offset 1024

    // Set Command List Base
    portWrite32(port_num, PORT_CLB, @intCast(clb_phys & 0xFFFFFFFF));
    portWrite32(port_num, PORT_CLBU, @intCast((clb_phys >> 32) & 0xFFFFFFFF));

    // Set FIS Base
    portWrite32(port_num, PORT_FB, @intCast(fb_phys & 0xFFFFFFFF));
    portWrite32(port_num, PORT_FBU, @intCast((fb_phys >> 32) & 0xFFFFFFFF));

    // Allocate Command Tables (one page per slot, we use 1 slot only)
    const ct_page = pmm.allocPage() orelse {
        serial.writeString("[AHCI]   Failed to alloc CT page\n");
        pmm.freePage(cl_page);
        return false;
    };

    // Setup command header 0 to point to command table
    const cl_virt = hhdm_offset + clb_phys;
    const ch: *volatile CommandHeader = @ptrFromInt(cl_virt);
    ch.ctba = @intCast(ct_page & 0xFFFFFFFF);
    ch.ctbau = @intCast((ct_page >> 32) & 0xFFFFFFFF);

    // Clear SATA Error
    portWrite32(port_num, PORT_SERR, 0xFFFFFFFF);

    // Clear interrupt status
    portWrite32(port_num, PORT_IS, 0xFFFFFFFF);

    // Start port
    startPort(port_num);

    // Store port info
    const idx = port_count;
    ports[idx].implemented = true;
    ports[idx].connected = true;
    ports[idx].is_atapi = is_atapi;
    ports[idx].port_num = @intCast(port_num);
    ports[idx].clb_phys = clb_phys;
    ports[idx].fb_phys = fb_phys;
    ports[idx].ct_phys[0] = ct_page;

    // Identify drive
    if (identifyDrive(idx)) {
        serial.writeString("[AHCI]   Model: ");
        for (ports[idx].model) |c| {
            if (c == 0) break;
            serial.writeChar(c);
        }
        serial.writeString("\n[AHCI]   Size: ");
        printU32(ports[idx].size_mb);
        serial.writeString(" MB (");
        printU64(ports[idx].sectors);
        serial.writeString(" sectors)\n");
        return true;
    } else {
        serial.writeString("[AHCI]   IDENTIFY failed\n");
        return false;
    }
}

fn stopPort(port_num: u32) void {
    var cmd = portRead32(port_num, PORT_CMD);

    // Clear ST (stop command processing)
    cmd &= ~PORT_CMD_ST;
    portWrite32(port_num, PORT_CMD, cmd);

    // Wait for CR to clear
    var timeout: u32 = 500000;
    while (timeout > 0) : (timeout -= 1) {
        if ((portRead32(port_num, PORT_CMD) & PORT_CMD_CR) == 0) break;
    }

    // Clear FRE
    cmd = portRead32(port_num, PORT_CMD);
    cmd &= ~PORT_CMD_FRE;
    portWrite32(port_num, PORT_CMD, cmd);

    // Wait for FR to clear
    timeout = 500000;
    while (timeout > 0) : (timeout -= 1) {
        if ((portRead32(port_num, PORT_CMD) & PORT_CMD_FR) == 0) break;
    }
}

fn startPort(port_num: u32) void {
    // Wait until CR is clear
    var timeout: u32 = 500000;
    while (timeout > 0) : (timeout -= 1) {
        if ((portRead32(port_num, PORT_CMD) & PORT_CMD_CR) == 0) break;
    }

    // Enable FRE first, then ST
    var cmd = portRead32(port_num, PORT_CMD);
    cmd |= PORT_CMD_FRE;
    portWrite32(port_num, PORT_CMD, cmd);

    cmd |= PORT_CMD_ST;
    portWrite32(port_num, PORT_CMD, cmd);
}

// =============================================================================
// Command Issue
// =============================================================================

fn waitPortReady(port_num: u32) bool {
    var timeout: u32 = 1000000;
    while (timeout > 0) : (timeout -= 1) {
        const tfd = portRead32(port_num, PORT_TFD);
        if ((tfd & (PORT_TFD_BSY | PORT_TFD_DRQ)) == 0) return true;
    }
    return false;
}

fn findFreeSlot(port_num: u32) ?u5 {
    const sact = portRead32(port_num, PORT_SACT);
    const ci = portRead32(port_num, PORT_CI);
    const busy = sact | ci;

    var slot: u5 = 0;
    while (slot < 32) : (slot += 1) {
        if ((busy & (@as(u32, 1) << slot)) == 0) return slot;
    }
    return null;
}

/// Issue a command on slot 0 of given port and wait for completion
fn issueCommand(port_idx: usize, slot: u5) bool {
    const port_num: u32 = ports[port_idx].port_num;

    // Wait for port to be ready
    if (!waitPortReady(port_num)) {
        serial.writeString("[AHCI] Port not ready\n");
        return false;
    }

    // Clear interrupt status
    portWrite32(port_num, PORT_IS, 0xFFFFFFFF);

    // Issue command
    portWrite32(port_num, PORT_CI, @as(u32, 1) << slot);

    // Wait for completion (poll)
    var timeout: u32 = 10000000;
    while (timeout > 0) : (timeout -= 1) {
        const ci = portRead32(port_num, PORT_CI);
        if ((ci & (@as(u32, 1) << slot)) == 0) {
            // Command completed — check for errors
            const tfd = portRead32(port_num, PORT_TFD);
            if ((tfd & PORT_TFD_ERR) != 0) {
                serial.writeString("[AHCI] Command error, TFD=0x");
                printHex32(tfd);
                serial.writeString("\n");
                return false;
            }
            return true;
        }

        // Check for errors
        const is = portRead32(port_num, PORT_IS);
        if ((is & (1 << 30)) != 0) { // TFES - Task File Error Status
            serial.writeString("[AHCI] Task file error\n");
            return false;
        }
    }

    serial.writeString("[AHCI] Command timeout\n");
    return false;
}

// =============================================================================
// Command Setup Helpers
// =============================================================================

fn setupCommandHeader(port_idx: usize, slot: u5, write: bool, prdt_count: u16, fis_len_dwords: u5) void {
    const cl_virt = hhdm_offset + ports[port_idx].clb_phys;
    const ch_addr = cl_virt + @as(u64, slot) * @sizeOf(CommandHeader);
    const ch: *volatile CommandHeader = @ptrFromInt(ch_addr);

    var flags: u16 = fis_len_dwords; // CFL in DW0 bits 0-4
    if (write) {
        flags |= (1 << 6); // W bit
    }

    ch.flags = flags;
    ch.prdtl = prdt_count;
    ch.prdbc = 0;
    ch.reserved = [_]u32{0} ** 4;
    // JANGAN sentuh ch.ctba dan ch.ctbau — sudah di-set oleh initPort()!
}

fn getCommandTable(port_idx: usize, slot: u5) u64 {
    _ = slot; // We only use slot 0, CT is at ct_phys[0]
    return hhdm_offset + ports[port_idx].ct_phys[0];
}

fn setupFisH2D(ct_virt: u64, command: u8, lba: u64, count: u16) void {
    const fis: *volatile FisRegH2D = @ptrFromInt(ct_virt);

    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.flags = 0x80; // C bit = 1 (command)
    fis.command = command;
    fis.featurel = 0;

    fis.lba0 = @intCast(lba & 0xFF);
    fis.lba1 = @intCast((lba >> 8) & 0xFF);
    fis.lba2 = @intCast((lba >> 16) & 0xFF);
    fis.device = 1 << 6; // LBA mode

    fis.lba3 = @intCast((lba >> 24) & 0xFF);
    fis.lba4 = @intCast((lba >> 32) & 0xFF);
    fis.lba5 = @intCast((lba >> 40) & 0xFF);
    fis.featureh = 0;

    fis.countl = @intCast(count & 0xFF);
    fis.counth = @intCast((count >> 8) & 0xFF);
    fis.icc = 0;
    fis.control = 0;
    fis.reserved = [_]u8{0} ** 4;
}

fn setupPrdt(ct_virt: u64, data_phys: u64, byte_count: u32) void {
    // PRDT starts at offset 0x80 in command table
    const prdt_addr = ct_virt + 0x80;
    const prdt: *volatile PrdtEntry = @ptrFromInt(prdt_addr);

    prdt.dba = @intCast(data_phys & 0xFFFFFFFF);
    prdt.dbau = @intCast((data_phys >> 32) & 0xFFFFFFFF);
    prdt.reserved = 0;
    prdt.dbc_i = (byte_count - 1) | (1 << 31); // IOC bit set
}

// =============================================================================
// IDENTIFY Device
// =============================================================================

fn identifyDrive(port_idx: usize) bool {
    const slot: u5 = 0;
    const ct_virt = getCommandTable(port_idx, slot);

    // Clear command table area
    const ct_ptr: [*]volatile u8 = @ptrFromInt(ct_virt);
    for (0..256) |i| {
        ct_ptr[i] = 0;
    }

    // Setup FIS: IDENTIFY command
    setupFisH2D(ct_virt, ATA_CMD_IDENTIFY, 0, 0);

    // Setup PRDT: read 512 bytes into DMA buffer
    setupPrdt(ct_virt, dma_buffer_phys, 512);

    // Setup command header
    setupCommandHeader(port_idx, slot, false, 1, 5); // 5 DWORDs FIS, 1 PRDT entry

    // Issue
    if (!issueCommand(port_idx, slot)) {
        return false;
    }

    // Parse IDENTIFY data from DMA buffer
    const data: [*]volatile u16 = @ptrFromInt(dma_buffer_virt);

    // LBA48 support: bit 10 of word 83
    ports[port_idx].lba48 = (data[83] & (1 << 10)) != 0;

    // Total sectors
    if (ports[port_idx].lba48) {
        ports[port_idx].sectors = @as(u64, data[100]) |
            (@as(u64, data[101]) << 16) |
            (@as(u64, data[102]) << 32) |
            (@as(u64, data[103]) << 48);
    } else {
        ports[port_idx].sectors = @as(u64, data[60]) | (@as(u64, data[61]) << 16);
    }

    ports[port_idx].size_mb = @intCast((ports[port_idx].sectors * 512) / (1024 * 1024));

    // Model string (words 27-46, byte-swapped)
    for (0..20) |i| {
        const word = data[27 + i];
        ports[port_idx].model[i * 2] = @intCast((word >> 8) & 0xFF);
        ports[port_idx].model[i * 2 + 1] = @intCast(word & 0xFF);
    }
    ports[port_idx].model[40] = 0;
    trimTrailingSpaces(&ports[port_idx].model);

    // Serial number (words 10-19, byte-swapped)
    for (0..10) |i| {
        const word = data[10 + i];
        ports[port_idx].serial_str[i * 2] = @intCast((word >> 8) & 0xFF);
        ports[port_idx].serial_str[i * 2 + 1] = @intCast(word & 0xFF);
    }
    ports[port_idx].serial_str[20] = 0;
    trimTrailingSpaces(&ports[port_idx].serial_str);

    return true;
}

// =============================================================================
// Public Read/Write API
// =============================================================================

pub const AhciError = error{
    NoDrive,
    NotReady,
    ReadError,
    WriteError,
    InvalidLBA,
    Timeout,
    NotInitialized,
};

/// Read a single sector via DMA
pub fn readSector(drive_idx: usize, lba: u64, buffer: *[512]u8) AhciError!void {
    if (!ahci_initialized) return AhciError.NotInitialized;
    if (drive_idx >= port_count) return AhciError.NoDrive;

    const port_idx = drive_idx;
    const pnum: u32 = ports[port_idx].port_num;
    const slot: u5 = 0;
    const ct_virt = getCommandTable(port_idx, slot);

    if (!waitPortReady(pnum)) return AhciError.NotReady;

    // Clear command table
    const ct_ptr: [*]volatile u8 = @ptrFromInt(ct_virt);
    for (0..256) |i| ct_ptr[i] = 0;

    setupFisH2D(ct_virt, ATA_CMD_READ_DMA_EX, lba, 1);
    setupPrdt(ct_virt, dma_buffer_phys, 512);
    setupCommandHeader(port_idx, slot, false, 1, 5);

    // Clear all errors before issuing
    portWrite32(pnum, PORT_SERR, 0xFFFFFFFF);
    portWrite32(pnum, PORT_IS, 0xFFFFFFFF);

    asm volatile ("mfence" ::: .{ .memory = true });

    if (!issueCommand(port_idx, slot)) return AhciError.ReadError;

    const src: [*]volatile u8 = @ptrFromInt(dma_buffer_virt);
    for (0..512) |i| {
        buffer[i] = src[i];
    }
}

/// Write a single sector via DMA (with retry for QEMU cold-start quirk)
pub fn writeSector(drive_idx: usize, lba: u64, buffer: *const [512]u8) AhciError!void {
    if (!ahci_initialized) return AhciError.NotInitialized;
    if (drive_idx >= port_count) return AhciError.NoDrive;

    const port_idx = drive_idx;
    const pnum: u32 = ports[port_idx].port_num;
    const slot: u5 = 0;
    const ct_virt = getCommandTable(port_idx, slot);

    // Retry up to 3 times — QEMU AHCI may reject first write after init
    var attempt: u32 = 0;
    while (attempt < 3) : (attempt += 1) {
        if (!waitPortReady(pnum)) return AhciError.NotReady;

        // Copy data to DMA buffer
        const dst: [*]volatile u8 = @ptrFromInt(dma_buffer_virt);
        for (0..512) |i| {
            dst[i] = buffer[i];
        }

        // Ensure DMA buffer is visible to hardware
        asm volatile ("mfence" ::: .{ .memory = true });

        // Clear command table
        const ct_ptr: [*]volatile u8 = @ptrFromInt(ct_virt);
        for (0..256) |i| ct_ptr[i] = 0;

        setupFisH2D(ct_virt, ATA_CMD_WRITE_DMA_EX, lba, 1);
        setupPrdt(ct_virt, dma_buffer_phys, 512);
        setupCommandHeader(port_idx, slot, true, 1, 5);

        // Clear ALL errors and status before issuing
        portWrite32(pnum, PORT_SERR, 0xFFFFFFFF);
        portWrite32(pnum, PORT_IS, 0xFFFFFFFF);

        // Final barrier before command issue
        asm volatile ("mfence" ::: .{ .memory = true });

        if (issueCommand(port_idx, slot)) {
            return; // Success
        }

        // Failed — recover port for retry
        portWrite32(pnum, PORT_SERR, 0xFFFFFFFF);
        portWrite32(pnum, PORT_IS, 0xFFFFFFFF);

        // Small delay before retry
        var delay: u32 = 0;
        while (delay < 100000) : (delay += 1) {
            asm volatile ("pause");
        }
    }

    return AhciError.WriteError;
}

/// Read multiple sectors
pub fn readSectors(drive_idx: usize, lba: u64, count: u8, buffer: []u8) AhciError!void {
    if (!ahci_initialized) return AhciError.NotInitialized;
    if (drive_idx >= port_count) return AhciError.NoDrive;
    if (buffer.len < @as(usize, count) * 512) return AhciError.InvalidLBA;

    // Read sector by sector using the single DMA buffer
    var i: u8 = 0;
    while (i < count) : (i += 1) {
        var sector_buf: [512]u8 = undefined;
        try readSector(drive_idx, lba + i, &sector_buf);

        const offset = @as(usize, i) * 512;
        for (0..512) |j| {
            buffer[offset + j] = sector_buf[j];
        }
    }
}

/// Write multiple sectors
pub fn writeSectors(drive_idx: usize, lba: u64, count: u8, buffer: []const u8) AhciError!void {
    if (!ahci_initialized) return AhciError.NotInitialized;
    if (drive_idx >= port_count) return AhciError.NoDrive;
    if (buffer.len < @as(usize, count) * 512) return AhciError.InvalidLBA;

    var i: u8 = 0;
    while (i < count) : (i += 1) {
        var sector_buf: [512]u8 = undefined;
        const offset = @as(usize, i) * 512;
        for (0..512) |j| {
            sector_buf[j] = buffer[offset + j];
        }
        try writeSector(drive_idx, lba + i, &sector_buf);
    }
}

// =============================================================================
// Query API
// =============================================================================

pub fn isInitialized() bool {
    return ahci_initialized;
}

pub fn isDetected() bool {
    return ahci_detected;
}

pub fn getDriveCount() usize {
    return port_count;
}

pub fn getDriveModel(idx: usize) []const u8 {
    if (idx >= port_count) return "Unknown";
    var len: usize = 0;
    for (ports[idx].model) |c| {
        if (c == 0) break;
        len += 1;
    }
    return ports[idx].model[0..len];
}

pub fn getDriveSizeMB(idx: usize) u32 {
    if (idx >= port_count) return 0;
    return ports[idx].size_mb;
}

pub fn getDriveSectors(idx: usize) u64 {
    if (idx >= port_count) return 0;
    return ports[idx].sectors;
}

pub fn getDriveLba48(idx: usize) bool {
    if (idx >= port_count) return false;
    return ports[idx].lba48;
}

pub fn getIrq() u8 {
    return pci_irq;
}

// =============================================================================
// IRQ Handler (called from IDT)
// =============================================================================

pub fn handleInterrupt() void {
    if (!ahci_initialized) return;

    // Read global interrupt status
    const is = mmioRead32(HBA_IS);

    // Clear each port's interrupt status
    var port_num: u32 = 0;
    while (port_num < 32) : (port_num += 1) {
        if ((is & (@as(u32, 1) << @intCast(port_num))) != 0) {
            const port_is = portRead32(port_num, PORT_IS);
            portWrite32(port_num, PORT_IS, port_is); // Clear by writing back
        }
    }

    // Clear global IS
    mmioWrite32(HBA_IS, is);
}

// =============================================================================
// Utility
// =============================================================================

fn trimTrailingSpaces(s: []u8) void {
    var i: usize = s.len;
    while (i > 0) {
        i -= 1;
        if (s[i] != ' ' and s[i] != 0) {
            if (i + 1 < s.len) s[i + 1] = 0;
            break;
        }
        s[i] = 0;
    }
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printU64(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    var i: u5 = 28;
    while (true) : (i -= 4) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
    }
}

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) : (i -= 4) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
    }
}
