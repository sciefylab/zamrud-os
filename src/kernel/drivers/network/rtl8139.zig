//! Zamrud OS - Realtek RTL8139 Network Driver
//! 10/100 Mbps Fast Ethernet for QEMU/legacy hardware
//!
//! RTL8139 uses I/O port-based access (unlike E1000's MMIO)
//! Features: Simple ring buffer TX, single RX buffer with wrap

const serial = @import("../serial/serial.zig");
const network = @import("network.zig");
const pci = @import("../pci/pci.zig");
const pmm = @import("../../mm/pmm.zig");

// =============================================================================
// Constants
// =============================================================================

// PCI IDs
pub const REALTEK_VENDOR_ID: u16 = 0x10EC;
pub const RTL8139_DEVICE_ID: u16 = 0x8139;
pub const RTL8139_DEVICE_ID_ALT: u16 = 0x8138; // RTL8139B

// RTL8139 Register Offsets (I/O Port based)
pub const REG_IDR0: u16 = 0x00; // MAC address bytes 0-3
pub const REG_IDR4: u16 = 0x04; // MAC address bytes 4-5
pub const REG_MAR0: u16 = 0x08; // Multicast filter 0-3
pub const REG_MAR4: u16 = 0x0C; // Multicast filter 4-7
pub const REG_TSD0: u16 = 0x10; // TX status descriptor 0
pub const REG_TSD1: u16 = 0x14; // TX status descriptor 1
pub const REG_TSD2: u16 = 0x18; // TX status descriptor 2
pub const REG_TSD3: u16 = 0x1C; // TX status descriptor 3
pub const REG_TSAD0: u16 = 0x20; // TX start address 0
pub const REG_TSAD1: u16 = 0x24; // TX start address 1
pub const REG_TSAD2: u16 = 0x28; // TX start address 2
pub const REG_TSAD3: u16 = 0x2C; // TX start address 3
pub const REG_RBSTART: u16 = 0x30; // RX buffer start address
pub const REG_ERBCR: u16 = 0x34; // Early RX byte count
pub const REG_ERSR: u16 = 0x36; // Early RX status
pub const REG_CR: u16 = 0x37; // Command register
pub const REG_CAPR: u16 = 0x38; // Current address of packet read
pub const REG_CBR: u16 = 0x3A; // Current buffer address
pub const REG_IMR: u16 = 0x3C; // Interrupt mask register
pub const REG_ISR: u16 = 0x3E; // Interrupt status register
pub const REG_TCR: u16 = 0x40; // TX configuration
pub const REG_RCR: u16 = 0x44; // RX configuration
pub const REG_TCTR: u16 = 0x48; // Timer count register
pub const REG_MPC: u16 = 0x4C; // Missed packet counter
pub const REG_9346CR: u16 = 0x50; // 93C46 command register
pub const REG_CONFIG0: u16 = 0x51; // Configuration register 0
pub const REG_CONFIG1: u16 = 0x52; // Configuration register 1
pub const REG_TIMERINT: u16 = 0x54; // Timer interrupt register
pub const REG_MSR: u16 = 0x58; // Media status register
pub const REG_CONFIG3: u16 = 0x59; // Configuration register 3
pub const REG_CONFIG4: u16 = 0x5A; // Configuration register 4
pub const REG_MULINT: u16 = 0x5C; // Multiple interrupt select
pub const REG_RERID: u16 = 0x5E; // PCI revision ID
pub const REG_TSAD: u16 = 0x60; // TX status of all descriptors
pub const REG_BMCR: u16 = 0x62; // Basic mode control register
pub const REG_BMSR: u16 = 0x64; // Basic mode status register
pub const REG_ANAR: u16 = 0x66; // Auto-negotiation advertisement
pub const REG_ANLPAR: u16 = 0x68; // Auto-negotiation link partner
pub const REG_ANER: u16 = 0x6A; // Auto-negotiation expansion
pub const REG_DIS: u16 = 0x6C; // Disconnect counter
pub const REG_FCSC: u16 = 0x6E; // False carrier sense counter
pub const REG_NWAYTR: u16 = 0x70; // N-way test register
pub const REG_REC: u16 = 0x72; // RX error counter
pub const REG_CSCR: u16 = 0x74; // CS configuration register
pub const REG_PHY1_PARM: u16 = 0x78; // PHY parameter 1
pub const REG_TW_PARM: u16 = 0x7C; // Twister parameter
pub const REG_PHY2_PARM: u16 = 0x80; // PHY parameter 2
pub const REG_CRC0: u16 = 0x84; // Power management CRC 0-3
pub const REG_CRC4: u16 = 0x88; // Power management CRC 4-7
pub const REG_WAKEMASK0: u16 = 0x8C; // Wakeup mask bytes

// Command Register bits
pub const CR_RST: u8 = 0x10; // Reset
pub const CR_RE: u8 = 0x08; // Receiver enable
pub const CR_TE: u8 = 0x04; // Transmitter enable
pub const CR_BUFE: u8 = 0x01; // Buffer empty

// Interrupt bits
pub const INT_ROK: u16 = 0x0001; // Receive OK
pub const INT_RER: u16 = 0x0002; // Receive error
pub const INT_TOK: u16 = 0x0004; // Transmit OK
pub const INT_TER: u16 = 0x0008; // Transmit error
pub const INT_RXOVW: u16 = 0x0010; // RX buffer overflow
pub const INT_PUN: u16 = 0x0020; // Packet underrun / link change
pub const INT_FOVW: u16 = 0x0040; // RX FIFO overflow
pub const INT_LENCHG: u16 = 0x2000; // Cable length change
pub const INT_TIMEOUT: u16 = 0x4000; // Time out
pub const INT_SERR: u16 = 0x8000; // System error

// TX Status bits
pub const TSD_OWN: u32 = 0x00002000; // DMA operation completed
pub const TSD_TUN: u32 = 0x00004000; // TX FIFO underrun
pub const TSD_TOK: u32 = 0x00008000; // TX OK
pub const TSD_ERTXTH_SHIFT: u5 = 16; // Early TX threshold
pub const TSD_SIZE_MASK: u32 = 0x00001FFF; // Packet size mask

// RX Configuration bits
pub const RCR_AAP: u32 = 0x00000001; // Accept all packets
pub const RCR_APM: u32 = 0x00000002; // Accept physical match
pub const RCR_AM: u32 = 0x00000004; // Accept multicast
pub const RCR_AB: u32 = 0x00000008; // Accept broadcast
pub const RCR_AR: u32 = 0x00000010; // Accept runt
pub const RCR_AER: u32 = 0x00000020; // Accept error packets
pub const RCR_WRAP: u32 = 0x00000080; // Wrap mode (no wrap = ring)
pub const RCR_RBLEN_8K: u32 = 0x00000000; // 8K + 16 bytes
pub const RCR_RBLEN_16K: u32 = 0x00000800; // 16K + 16 bytes
pub const RCR_RBLEN_32K: u32 = 0x00001000; // 32K + 16 bytes
pub const RCR_RBLEN_64K: u32 = 0x00001800; // 64K + 16 bytes
pub const RCR_MXDMA_UNLIMITED: u32 = 0x00000700; // Unlimited DMA burst

// TX Configuration bits
pub const TCR_MXDMA_2048: u32 = 0x00000700; // 2048 bytes max DMA burst
pub const TCR_IFG_NORMAL: u32 = 0x03000000; // Normal interframe gap

// RX packet header status bits
pub const RX_ROK: u16 = 0x0001; // Receive OK
pub const RX_FAE: u16 = 0x0002; // Frame alignment error
pub const RX_CRC: u16 = 0x0004; // CRC error
pub const RX_LONG: u16 = 0x0008; // Long packet (>4K)
pub const RX_RUNT: u16 = 0x0010; // Runt packet (<64 bytes)
pub const RX_ISE: u16 = 0x0020; // Invalid symbol error
pub const RX_BAR: u16 = 0x2000; // Broadcast address
pub const RX_PAM: u16 = 0x4000; // Physical address match
pub const RX_MAR: u16 = 0x8000; // Multicast address

// Buffer sizes
pub const RX_BUFFER_SIZE: usize = 8192 + 16 + 1500; // 8K + 16 header + 1500 wrap
pub const TX_BUFFER_SIZE: usize = 1536; // Max ethernet frame + padding
pub const NUM_TX_DESC: usize = 4; // RTL8139 has exactly 4 TX descriptors

// =============================================================================
// Types
// =============================================================================

pub const DriverStats = struct {
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_errors: u64,
    rx_errors: u64,
    rx_crc_errors: u64,
    rx_frame_errors: u64,
    rx_missed: u64,
    rx_overruns: u64,
    tx_underruns: u64,
    collisions: u64,
    link_changes: u64,
};

pub const LinkSpeed = enum {
    speed_10,
    speed_100,
    unknown,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var detected: bool = false;
var io_base: u16 = 0;
var irq_line: u8 = 0;
var hhdm_offset: u64 = 0;

// MAC address
var mac_address: network.MacAddress = [_]u8{0} ** 6;

// RX buffer (single large buffer with wrap)
var rx_buffer_phys: u64 = 0;
var rx_buffer: ?[*]volatile u8 = null;
var rx_cur: u16 = 0; // Current read position (CAPR + 16)

// TX buffers (4 descriptors)
var tx_buffers_phys: [NUM_TX_DESC]u64 = [_]u64{0} ** NUM_TX_DESC;
var tx_buffers: [NUM_TX_DESC]?[*]volatile u8 = [_]?[*]volatile u8{null} ** NUM_TX_DESC;
var tx_cur: usize = 0; // Current TX descriptor

// Statistics
var driver_stats: DriverStats = .{
    .tx_packets = 0,
    .rx_packets = 0,
    .tx_bytes = 0,
    .rx_bytes = 0,
    .tx_errors = 0,
    .rx_errors = 0,
    .rx_crc_errors = 0,
    .rx_frame_errors = 0,
    .rx_missed = 0,
    .rx_overruns = 0,
    .tx_underruns = 0,
    .collisions = 0,
    .link_changes = 0,
};

var dma_initialized: bool = false;
var managed_iface: ?*network.NetworkInterface = null;

// =============================================================================
// Physical/Virtual Address Conversion
// =============================================================================

inline fn physToVirt(phys: u64) u64 {
    return hhdm_offset + phys;
}

inline fn virtToPhys(virt: u64) u64 {
    if (virt >= hhdm_offset) {
        return virt - hhdm_offset;
    }
    return virt;
}

// =============================================================================
// I/O Port Access
// =============================================================================

inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

inline fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "N{dx}" (port),
    );
}

inline fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "N{dx}" (port),
    );
}

inline fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

inline fn outw(port: u16, value: u16) void {
    asm volatile ("outw %[value], %[port]"
        :
        : [value] "{ax}" (value),
          [port] "N{dx}" (port),
    );
}

inline fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "N{dx}" (port),
    );
}

// Register access helpers
inline fn readReg8(reg: u16) u8 {
    return inb(io_base + reg);
}

inline fn readReg16(reg: u16) u16 {
    return inw(io_base + reg);
}

inline fn readReg32(reg: u16) u32 {
    return inl(io_base + reg);
}

inline fn writeReg8(reg: u16, value: u8) void {
    outb(io_base + reg, value);
}

inline fn writeReg16(reg: u16, value: u16) void {
    outw(io_base + reg, value);
}

inline fn writeReg32(reg: u16, value: u32) void {
    outl(io_base + reg, value);
}

// =============================================================================
// DMA Buffer Allocation
// =============================================================================

fn allocateDmaBuffers() bool {
    serial.writeString("[RTL8139] Allocating DMA buffers...\n");

    hhdm_offset = pmm.getHhdmOffset();

    // Allocate RX buffer (need ~10KB, allocate 3 pages = 12KB)
    // RTL8139 RX buffer must be contiguous and 32-bit aligned
    const rx_pages = (RX_BUFFER_SIZE + 4095) / 4096;
    rx_buffer_phys = pmm.allocPages(rx_pages) orelse {
        serial.writeString("[RTL8139] Failed to allocate RX buffer!\n");
        return false;
    };
    rx_buffer = @ptrFromInt(physToVirt(rx_buffer_phys));

    // Clear RX buffer
    const rx_ptr = rx_buffer.?;
    for (0..RX_BUFFER_SIZE) |i| {
        rx_ptr[i] = 0;
    }

    serial.writeString("[RTL8139] RX buffer at phys 0x");
    printHex32(@truncate(rx_buffer_phys));
    serial.writeString("\n");

    // Allocate TX buffers (4 x 1 page each)
    for (0..NUM_TX_DESC) |i| {
        tx_buffers_phys[i] = pmm.allocPage() orelse {
            serial.writeString("[RTL8139] Failed to allocate TX buffer!\n");
            freeDmaBuffers();
            return false;
        };
        tx_buffers[i] = @ptrFromInt(physToVirt(tx_buffers_phys[i]));

        // Clear TX buffer
        const tx_ptr = tx_buffers[i].?;
        for (0..TX_BUFFER_SIZE) |j| {
            tx_ptr[j] = 0;
        }
    }

    dma_initialized = true;
    serial.writeString("[RTL8139] DMA buffers allocated\n");
    return true;
}

fn freeDmaBuffers() void {
    if (rx_buffer_phys != 0) {
        const rx_pages = (RX_BUFFER_SIZE + 4095) / 4096;
        pmm.freePages(rx_buffer_phys, rx_pages);
        rx_buffer_phys = 0;
        rx_buffer = null;
    }

    for (0..NUM_TX_DESC) |i| {
        if (tx_buffers_phys[i] != 0) {
            pmm.freePage(tx_buffers_phys[i]);
            tx_buffers_phys[i] = 0;
            tx_buffers[i] = null;
        }
    }

    dma_initialized = false;
}

// =============================================================================
// Probe & Init
// =============================================================================

pub fn probe() bool {
    if (!pci.isInitialized()) {
        return false;
    }

    const device_ids = [_]u16{ RTL8139_DEVICE_ID, RTL8139_DEVICE_ID_ALT };

    for (device_ids) |dev_id| {
        if (pci.findDevice(REALTEK_VENDOR_ID, dev_id)) |dev| {
            // RTL8139 uses I/O ports (BAR0 bit 0 = 1)
            if ((dev.bar0 & 0x01) != 0) {
                io_base = @truncate(dev.bar0 & 0xFFFC);
                irq_line = dev.irq_line;
                detected = true;

                // Enable bus master and I/O space
                pci.enableBusMaster(dev);
                pci.enableIoSpace(dev);

                serial.writeString("[RTL8139] Device found at I/O 0x");
                printHex16(io_base);
                serial.writeString(" IRQ ");
                printU8(irq_line);
                serial.writeString("\n");

                return true;
            } else {
                serial.writeString("[RTL8139] BAR0 is MMIO, expected I/O!\n");
            }
        }
    }

    return false;
}

pub fn init() void {
    if (!detected) {
        if (!probe()) {
            serial.writeString("[RTL8139] No RTL8139 device found\n");
            return;
        }
    }

    serial.writeString("[RTL8139] Initializing...\n");

    // Allocate DMA buffers
    if (!allocateDmaBuffers()) {
        serial.writeString("[RTL8139] DMA allocation failed, using fallback\n");
        mac_address = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 };
        initialized = true;
        return;
    }

    initHardware();

    initialized = true;
    serial.writeString("[RTL8139] Initialized, MAC: ");
    printMac(mac_address);
    serial.writeString("\n");
}

fn initHardware() void {
    if (io_base == 0) {
        mac_address = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 };
        serial.writeString("[RTL8139] No I/O base, using fallback\n");
        return;
    }

    // Step 1: Power on the device
    writeReg8(REG_CONFIG1, 0x00);
    busyWait(10000);

    // Step 2: Software reset
    serial.writeString("[RTL8139] Resetting device...\n");
    writeReg8(REG_CR, CR_RST);

    // Wait for reset to complete (RST bit auto-clears)
    var timeout: u32 = 0;
    while (timeout < 1000) : (timeout += 1) {
        if ((readReg8(REG_CR) & CR_RST) == 0) break;
        busyWait(1000);
    }

    if (timeout >= 1000) {
        serial.writeString("[RTL8139] Reset timeout!\n");
    }

    // Step 3: Read MAC address from IDR registers
    readMacAddress();

    // Step 4: Enable TX and RX
    writeReg8(REG_CR, CR_TE | CR_RE);

    // Step 5: Configure RX buffer
    // Set RX buffer address (must be physical address, 32-bit)
    writeReg32(REG_RBSTART, @truncate(rx_buffer_phys));

    // Step 6: Configure TX descriptors
    // Set TX buffer addresses
    for (0..NUM_TX_DESC) |i| {
        const tsad_reg: u16 = REG_TSAD0 + @as(u16, @intCast(i)) * 4;
        writeReg32(tsad_reg, @truncate(tx_buffers_phys[i]));
    }

    // Step 7: Set interrupt mask (enable common interrupts)
    writeReg16(REG_IMR, INT_ROK | INT_TOK | INT_RER | INT_TER | INT_RXOVW);

    // Step 8: Configure RX
    // Accept broadcast, physical match, multicast
    // 8K buffer, no wrap, unlimited DMA burst
    const rcr: u32 = RCR_APM | RCR_AB | RCR_AM | RCR_RBLEN_8K | RCR_MXDMA_UNLIMITED;
    writeReg32(REG_RCR, rcr);

    // Step 9: Configure TX
    // Normal interframe gap, 2048 byte DMA burst
    const tcr: u32 = TCR_IFG_NORMAL | TCR_MXDMA_2048;
    writeReg32(REG_TCR, tcr);

    // Step 10: Clear any pending interrupts
    _ = readReg16(REG_ISR);

    // Step 11: Initialize CAPR (read pointer)
    writeReg16(REG_CAPR, 0xFFF0); // Initial value per datasheet
    rx_cur = 0;
    tx_cur = 0;

    serial.writeString("[RTL8139] Hardware ready\n");
}

fn readMacAddress() void {
    // Read MAC from IDR0-IDR5 registers
    const mac_low = readReg32(REG_IDR0);
    const mac_high = readReg16(REG_IDR4);

    mac_address[0] = @intCast(mac_low & 0xFF);
    mac_address[1] = @intCast((mac_low >> 8) & 0xFF);
    mac_address[2] = @intCast((mac_low >> 16) & 0xFF);
    mac_address[3] = @intCast((mac_low >> 24) & 0xFF);
    mac_address[4] = @intCast(mac_high & 0xFF);
    mac_address[5] = @intCast((mac_high >> 8) & 0xFF);

    // Check for invalid MAC
    var all_zero = true;
    var all_ones = true;
    for (mac_address) |b| {
        if (b != 0) all_zero = false;
        if (b != 0xFF) all_ones = false;
    }

    if (all_zero or all_ones) {
        // Use fallback MAC
        mac_address = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 };
        serial.writeString("[RTL8139] Invalid MAC, using fallback\n");
    }
}

// =============================================================================
// Send/Receive
// =============================================================================

pub fn sendPacket(iface: *network.NetworkInterface, data: []const u8) bool {
    _ = iface;

    if (!initialized) return false;

    if (data.len > 1514 or data.len < 14) {
        driver_stats.tx_errors += 1;
        return false;
    }

    if (io_base == 0 or !dma_initialized) {
        // Simulated mode
        driver_stats.tx_packets += 1;
        driver_stats.tx_bytes += data.len;
        return true;
    }

    const cur = tx_cur;

    // Check if descriptor is available (OWN bit should be set after TX complete)
    const tsd_reg: u16 = REG_TSD0 + @as(u16, @intCast(cur)) * 4;
    var tsd = readReg32(tsd_reg);

    // For first use or after completion, OWN bit will be set
    // Wait for previous transmission to complete
    var timeout: u32 = 0;
    while ((tsd & TSD_OWN) == 0 and timeout < 10000) : (timeout += 1) {
        tsd = readReg32(tsd_reg);
        busyWait(10);
    }

    if (timeout >= 10000) {
        driver_stats.tx_errors += 1;
        return false;
    }

    // Check for previous errors
    if ((tsd & TSD_TUN) != 0) {
        driver_stats.tx_underruns += 1;
    }

    // Copy data to TX buffer
    const buffer = tx_buffers[cur] orelse return false;
    for (data, 0..) |byte, i| {
        buffer[i] = byte;
    }

    // Memory barrier
    asm volatile ("mfence" ::: .{ .memory = true });

    // Write TX status: clear OWN, set size, early TX threshold = 256 bytes
    // FIX: Cast data.len to u32
    const new_tsd: u32 = (@as(u32, @intCast(data.len)) & TSD_SIZE_MASK) |
        (@as(u32, 8) << TSD_ERTXTH_SHIFT); // 8 * 32 = 256 bytes threshold
    writeReg32(tsd_reg, new_tsd);

    // Advance to next descriptor
    tx_cur = (cur + 1) % NUM_TX_DESC;

    driver_stats.tx_packets += 1;
    driver_stats.tx_bytes += data.len;

    return true;
}
pub fn recvPacket(iface: *network.NetworkInterface, buffer: []u8) isize {
    _ = iface;

    if (!initialized or io_base == 0 or !dma_initialized) return 0;

    // Check command register for buffer empty flag
    const cmd = readReg8(REG_CR);
    if ((cmd & CR_BUFE) != 0) {
        // Buffer is empty
        return 0;
    }

    const rx_buf = rx_buffer orelse return 0;

    // Read packet header at current position
    // Header format: [status:16][length:16][data...]
    const header_offset = rx_cur;

    // Ensure we don't read beyond buffer
    if (header_offset >= RX_BUFFER_SIZE - 4) {
        return 0;
    }

    // Read status and length (little-endian)
    const status: u16 = @as(u16, rx_buf[header_offset]) |
        (@as(u16, rx_buf[header_offset + 1]) << 8);
    const pkt_len: u16 = @as(u16, rx_buf[header_offset + 2]) |
        (@as(u16, rx_buf[header_offset + 3]) << 8);

    // Check for valid packet
    if ((status & RX_ROK) == 0) {
        // Error packet
        if ((status & RX_CRC) != 0) driver_stats.rx_crc_errors += 1;
        if ((status & RX_FAE) != 0) driver_stats.rx_frame_errors += 1;
        driver_stats.rx_errors += 1;

        // Skip this packet
        updateRxPointer(pkt_len);
        return -1;
    }

    // Validate length
    if (pkt_len < 14 or pkt_len > 1518) {
        updateRxPointer(pkt_len);
        return 0;
    }

    // Calculate actual data length (packet length includes CRC)
    const data_len = pkt_len - 4; // Remove 4-byte CRC
    if (data_len > buffer.len) {
        updateRxPointer(pkt_len);
        return 0;
    }

    // Copy packet data (skip 4-byte header)
    const data_offset = header_offset + 4;
    for (0..data_len) |i| {
        const src_idx = (data_offset + i) % (RX_BUFFER_SIZE - 1500); // Wrap within valid region
        buffer[i] = rx_buf[src_idx];
    }

    driver_stats.rx_packets += 1;
    driver_stats.rx_bytes += data_len;

    // Update RX pointer
    updateRxPointer(pkt_len);

    return @intCast(data_len);
}

fn updateRxPointer(pkt_len: u16) void {
    // Packet length + 4 byte header, aligned to 4 bytes
    const total_len = pkt_len + 4;
    const aligned_len: u16 = (total_len + 3) & ~@as(u16, 3);

    // FIX: Proper casting
    const new_rx_cur = (@as(u32, rx_cur) + @as(u32, aligned_len)) % @as(u32, RX_BUFFER_SIZE - 1500);
    rx_cur = @intCast(new_rx_cur);

    // Update CAPR (subtract 16 as per datasheet quirk)
    const new_capr = rx_cur -% 16;
    writeReg16(REG_CAPR, new_capr);
}

/// Poll for received packets
pub fn poll() void {
    if (!initialized or io_base == 0 or !dma_initialized) return;

    const iface = managed_iface orelse return;

    // Check for pending interrupts
    const isr = readReg16(REG_ISR);

    if ((isr & INT_RXOVW) != 0) {
        driver_stats.rx_overruns += 1;
        // Clear overflow - need to reset RX
        writeReg8(REG_CR, readReg8(REG_CR) & ~CR_RE);
        writeReg8(REG_CR, readReg8(REG_CR) | CR_RE);
    }

    // Acknowledge interrupts
    if (isr != 0) {
        writeReg16(REG_ISR, isr);
    }

    // Try to receive packets
    var buffer: [2048]u8 = undefined;
    var max_packets: u32 = 0;

    while (max_packets < 32) : (max_packets += 1) {
        const len = recvPacket(iface, &buffer);
        if (len <= 0) break;

        network.handleRxPacket(iface, buffer[0..@intCast(len)]);
    }
}

// =============================================================================
// Interface Management
// =============================================================================

pub fn setManagedInterface(iface: *network.NetworkInterface) void {
    managed_iface = iface;

    iface.mac = mac_address;
    iface.send_fn = sendPacket;
    iface.recv_fn = recvPacket;
    iface.interface_type = .ethernet; // RTL8139 is ethernet type
    iface.mtu = 1500;
    iface.driver_data = @intCast(io_base);

    if (io_base != 0) {
        iface.state = .up;
    }

    serial.writeString("[RTL8139] Managed interface set\n");
}

pub fn getMac() network.MacAddress {
    return mac_address;
}

pub fn getInterface() ?*network.NetworkInterface {
    return managed_iface;
}

pub fn getInterfaceConst() network.NetworkInterface {
    if (managed_iface) |iface| {
        return iface.*;
    }

    var fallback = network.NetworkInterface{
        .id = 0,
        .name = [_]u8{0} ** 16,
        .name_len = 0,
        .interface_type = .ethernet,
        .state = .down,
        .mac = mac_address,
        .ip_addr = 0,
        .netmask = 0,
        .gateway = 0,
        .mtu = 1500,
        .rx_packets = driver_stats.rx_packets,
        .tx_packets = driver_stats.tx_packets,
        .rx_bytes = driver_stats.rx_bytes,
        .tx_bytes = driver_stats.tx_bytes,
        .rx_errors = driver_stats.rx_errors,
        .tx_errors = driver_stats.tx_errors,
        .rx_dropped = 0,
        .tx_dropped = 0,
        .driver_data = @intCast(io_base),
        .send_fn = sendPacket,
        .recv_fn = recvPacket,
    };
    fallback.setName("eth1");
    return fallback;
}

// =============================================================================
// Control Functions
// =============================================================================

pub fn deinit() void {
    if (io_base != 0) {
        // Disable RX and TX
        writeReg8(REG_CR, 0);

        // Disable interrupts
        writeReg16(REG_IMR, 0);

        // Clear pending interrupts
        writeReg16(REG_ISR, 0xFFFF);
    }

    freeDmaBuffers();
    initialized = false;
    detected = false;
    managed_iface = null;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn isDetected() bool {
    return detected;
}

pub fn getIoBase() u16 {
    return io_base;
}

pub fn getIrq() u8 {
    return irq_line;
}

pub fn getStats() DriverStats {
    // Update missed packet count from hardware
    if (io_base != 0) {
        driver_stats.rx_missed = readReg32(REG_MPC);
    }
    return driver_stats;
}

pub fn isLinkUp() bool {
    if (io_base == 0) return true;

    // Check BMSR for link status
    const bmsr = readReg16(REG_BMSR);
    return (bmsr & 0x0004) != 0; // Link status bit
}

pub fn getLinkSpeed() LinkSpeed {
    if (io_base == 0) return .speed_100;

    // Check MSR for speed
    const msr = readReg8(REG_MSR);
    if ((msr & 0x08) != 0) {
        return .speed_10;
    } else {
        return .speed_100;
    }
}

pub fn getMtu() u16 {
    return 1500;
}

// =============================================================================
// Interrupt Handling
// =============================================================================

pub fn handleInterrupt() void {
    if (io_base == 0) return;

    const isr = readReg16(REG_ISR);

    if ((isr & INT_ROK) != 0) {
        poll();
    }

    if ((isr & INT_TOK) != 0) {
        // TX complete - nothing to do
    }

    if ((isr & INT_RER) != 0) {
        driver_stats.rx_errors += 1;
    }

    if ((isr & INT_TER) != 0) {
        driver_stats.tx_errors += 1;
    }

    if ((isr & INT_RXOVW) != 0) {
        driver_stats.rx_overruns += 1;
    }

    if ((isr & INT_PUN) != 0) {
        driver_stats.link_changes += 1;
    }

    // Acknowledge all interrupts
    writeReg16(REG_ISR, isr);
}

pub fn enableInterrupts() void {
    if (io_base == 0) return;
    writeReg16(REG_IMR, INT_ROK | INT_TOK | INT_RER | INT_TER | INT_RXOVW | INT_PUN);
}

pub fn disableInterrupts() void {
    if (io_base == 0) return;
    writeReg16(REG_IMR, 0);
}

// =============================================================================
// Configuration
// =============================================================================

pub fn setPromiscuous(enable: bool) void {
    if (io_base == 0) return;

    var rcr = readReg32(REG_RCR);
    if (enable) {
        rcr |= RCR_AAP;
    } else {
        rcr &= ~RCR_AAP;
    }
    writeReg32(REG_RCR, rcr);
}

pub fn setMulticast(enable: bool) void {
    if (io_base == 0) return;

    var rcr = readReg32(REG_RCR);
    if (enable) {
        rcr |= RCR_AM;
        // Accept all multicast - set MAR to all 1s
        writeReg32(REG_MAR0, 0xFFFFFFFF);
        writeReg32(REG_MAR4, 0xFFFFFFFF);
    } else {
        rcr &= ~RCR_AM;
        writeReg32(REG_MAR0, 0);
        writeReg32(REG_MAR4, 0);
    }
    writeReg32(REG_RCR, rcr);
}

// =============================================================================
// Transmit/Receive Convenience
// =============================================================================

pub fn transmit(data: []const u8) bool {
    if (managed_iface) |iface| {
        return sendPacket(iface, data);
    }
    return false;
}

pub fn receive(buffer: []u8) isize {
    if (managed_iface) |iface| {
        return recvPacket(iface, buffer);
    }
    return 0;
}

// =============================================================================
// Debug
// =============================================================================

pub fn debugDump() void {
    serial.writeString("\n=== RTL8139 Debug ===\n");
    serial.writeString("I/O Base: 0x");
    printHex16(io_base);
    serial.writeString("\nIRQ: ");
    printU8(irq_line);
    serial.writeString("\nInitialized: ");
    if (initialized) serial.writeString("yes") else serial.writeString("no");
    serial.writeString("\nDMA: ");
    if (dma_initialized) serial.writeString("yes") else serial.writeString("no");
    serial.writeString("\nMAC: ");
    printMac(mac_address);
    serial.writeString("\nLink: ");
    if (isLinkUp()) serial.writeString("UP") else serial.writeString("DOWN");
    serial.writeString(" @ ");
    switch (getLinkSpeed()) {
        .speed_10 => serial.writeString("10 Mbps"),
        .speed_100 => serial.writeString("100 Mbps"),
        .unknown => serial.writeString("Unknown"),
    }
    serial.writeString("\nTX: ");
    printDec64(driver_stats.tx_packets);
    serial.writeString(" pkts, RX: ");
    printDec64(driver_stats.rx_packets);
    serial.writeString(" pkts\n");
    serial.writeString("TX cur: ");
    printU8(@intCast(tx_cur));
    serial.writeString(", RX cur: ");
    printU16(rx_cur);
    serial.writeString("\n");

    if (io_base != 0) {
        serial.writeString("CR: 0x");
        printHex8(readReg8(REG_CR));
        serial.writeString(" ISR: 0x");
        printHex16(readReg16(REG_ISR));
        serial.writeString(" IMR: 0x");
        printHex16(readReg16(REG_IMR));
        serial.writeString("\n");
    }

    serial.writeString("=====================\n\n");
}

// =============================================================================
// Utilities
// =============================================================================

fn busyWait(cycles: u32) void {
    var i: u32 = 0;
    while (i < cycles) : (i += 1) {
        asm volatile ("pause");
    }
}

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[val >> 4]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 12) & 0xF]);
    serial.writeChar(hex[(val >> 8) & 0xF]);
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    var i: u5 = 28;
    while (true) : (i -= 4) {
        const nibble: u4 = @intCast((val >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
    }
}

fn printMac(mac: network.MacAddress) void {
    const hex = "0123456789abcdef";
    for (mac, 0..) |b, i| {
        serial.writeChar(hex[b >> 4]);
        serial.writeChar(hex[b & 0xF]);
        if (i < 5) serial.writeChar(':');
    }
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

fn printU16(val: u16) void {
    if (val >= 10000) serial.writeChar('0' + @as(u8, @intCast(val / 10000)));
    if (val >= 1000) serial.writeChar('0' + @as(u8, @intCast((val / 1000) % 10)));
    if (val >= 100) serial.writeChar('0' + @as(u8, @intCast((val / 100) % 10)));
    if (val >= 10) serial.writeChar('0' + @as(u8, @intCast((val / 10) % 10)));
    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
}

fn printDec64(val: u64) void {
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
