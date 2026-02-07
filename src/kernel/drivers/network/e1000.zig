//! Zamrud OS - Intel E1000 Network Driver
//! For Intel Gigabit Ethernet adapters (QEMU e1000)
//! Fixed: Physical address handling for DMA operations

const serial = @import("../serial/serial.zig");
const network = @import("network.zig");
const pci = @import("../pci/pci.zig");
const pmm = @import("../../mm/pmm.zig");

// =============================================================================
// Constants (Public)
// =============================================================================

pub const INTEL_VENDOR_ID: u16 = 0x8086;
pub const E1000_DEV_ID: u16 = 0x100E; // 82540EM (QEMU)
pub const E1000E_DEV_ID: u16 = 0x10D3; // 82574L
pub const E1000_82545EM: u16 = 0x100F;
pub const E1000_82546EB: u16 = 0x1010;

// E1000 Register Offsets
pub const E1000_CTRL: u32 = 0x0000;
pub const E1000_STATUS: u32 = 0x0008;
pub const E1000_EECD: u32 = 0x0010;
pub const E1000_EERD: u32 = 0x0014;
pub const E1000_CTRL_EXT: u32 = 0x0018;
pub const E1000_ICR: u32 = 0x00C0;
pub const E1000_ITR: u32 = 0x00C4;
pub const E1000_ICS: u32 = 0x00C8;
pub const E1000_IMS: u32 = 0x00D0;
pub const E1000_IMC: u32 = 0x00D8;
pub const E1000_RCTL: u32 = 0x0100;
pub const E1000_RDBAL: u32 = 0x2800;
pub const E1000_RDBAH: u32 = 0x2804;
pub const E1000_RDLEN: u32 = 0x2808;
pub const E1000_RDH: u32 = 0x2810;
pub const E1000_RDT: u32 = 0x2818;
pub const E1000_TCTL: u32 = 0x0400;
pub const E1000_TDBAL: u32 = 0x3800;
pub const E1000_TDBAH: u32 = 0x3804;
pub const E1000_TDLEN: u32 = 0x3808;
pub const E1000_TDH: u32 = 0x3810;
pub const E1000_TDT: u32 = 0x3818;
pub const E1000_MTA: u32 = 0x5200;
pub const E1000_RAL: u32 = 0x5400;
pub const E1000_RAH: u32 = 0x5404;

// CTRL Register Bits
pub const E1000_CTRL_FD: u32 = 0x00000001;
pub const E1000_CTRL_LRST: u32 = 0x00000008;
pub const E1000_CTRL_ASDE: u32 = 0x00000020;
pub const E1000_CTRL_SLU: u32 = 0x00000040;
pub const E1000_CTRL_ILOS: u32 = 0x00000080;
pub const E1000_CTRL_RST: u32 = 0x04000000;
pub const E1000_CTRL_VME: u32 = 0x40000000;
pub const E1000_CTRL_PHY_RST: u32 = 0x80000000;

// STATUS Register Bits
pub const E1000_STATUS_FD: u32 = 0x00000001;
pub const E1000_STATUS_LU: u32 = 0x00000002;
pub const E1000_STATUS_SPEED_MASK: u32 = 0x000000C0;
pub const E1000_STATUS_SPEED_10: u32 = 0x00000000;
pub const E1000_STATUS_SPEED_100: u32 = 0x00000040;
pub const E1000_STATUS_SPEED_1000: u32 = 0x00000080;

// RCTL Register Bits
pub const E1000_RCTL_EN: u32 = 0x00000002;
pub const E1000_RCTL_SBP: u32 = 0x00000004;
pub const E1000_RCTL_UPE: u32 = 0x00000008;
pub const E1000_RCTL_MPE: u32 = 0x00000010;
pub const E1000_RCTL_LPE: u32 = 0x00000020;
pub const E1000_RCTL_BAM: u32 = 0x00008000;
pub const E1000_RCTL_BSIZE_256: u32 = 0x00030000;
pub const E1000_RCTL_BSIZE_512: u32 = 0x00020000;
pub const E1000_RCTL_BSIZE_1024: u32 = 0x00010000;
pub const E1000_RCTL_BSIZE_2048: u32 = 0x00000000;
pub const E1000_RCTL_SECRC: u32 = 0x04000000;

// TCTL Register Bits
pub const E1000_TCTL_EN: u32 = 0x00000002;
pub const E1000_TCTL_PSP: u32 = 0x00000008;
pub const E1000_TCTL_CT_SHIFT: u5 = 4;
pub const E1000_TCTL_COLD_SHIFT: u5 = 12;

// Interrupt Bits
pub const E1000_ICR_TXDW: u32 = 0x00000001;
pub const E1000_ICR_TXQE: u32 = 0x00000002;
pub const E1000_ICR_LSC: u32 = 0x00000004;
pub const E1000_ICR_RXDMT0: u32 = 0x00000010;
pub const E1000_ICR_RXO: u32 = 0x00000040;
pub const E1000_ICR_RXT0: u32 = 0x00000080;

// Descriptor counts
pub const NUM_RX_DESC: usize = 32;
pub const NUM_TX_DESC: usize = 32;
pub const RX_BUFFER_SIZE: usize = 2048;
pub const TX_BUFFER_SIZE: usize = 2048;

// =============================================================================
// Types
// =============================================================================

pub const E1000RxDesc = extern struct {
    buffer_addr: u64 align(1),
    length: u16 align(1),
    checksum: u16 align(1),
    status: u8 align(1),
    errors: u8 align(1),
    special: u16 align(1),
};

pub const E1000TxDesc = extern struct {
    buffer_addr: u64 align(1),
    length: u16 align(1),
    cso: u8 align(1),
    cmd: u8 align(1),
    status: u8 align(1),
    css: u8 align(1),
    special: u16 align(1),
};

pub const DriverStats = struct {
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_errors: u64,
    rx_errors: u64,
    rx_crc_errors: u64,
    rx_missed: u64,
    collisions: u64,
    link_changes: u64,
};

pub const LinkSpeed = enum {
    speed_10,
    speed_100,
    speed_1000,
    unknown,
};

// =============================================================================
// DMA Memory Management
// =============================================================================

// Physical addresses for DMA buffers
var tx_desc_ring_phys: u64 = 0;
var rx_desc_ring_phys: u64 = 0;
var tx_buffers_phys: [NUM_TX_DESC]u64 = [_]u64{0} ** NUM_TX_DESC;
var rx_buffers_phys: [NUM_RX_DESC]u64 = [_]u64{0} ** NUM_RX_DESC;

// Virtual addresses (via HHDM) for CPU access
var tx_desc_ring: ?[*]volatile E1000TxDesc = null;
var rx_desc_ring: ?[*]volatile E1000RxDesc = null;
var tx_buffers: [NUM_TX_DESC]?[*]volatile u8 = [_]?[*]volatile u8{null} ** NUM_TX_DESC;
var rx_buffers: [NUM_RX_DESC]?[*]volatile u8 = [_]?[*]volatile u8{null} ** NUM_RX_DESC;

var tx_cur: usize = 0;
var rx_cur: usize = 0;

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var detected: bool = false;
var mmio_base: usize = 0;
var hhdm_offset: u64 = 0;

// MAC address storage
var mac_address: network.MacAddress = [_]u8{0} ** 6;

var driver_stats: DriverStats = .{
    .tx_packets = 0,
    .rx_packets = 0,
    .tx_bytes = 0,
    .rx_bytes = 0,
    .tx_errors = 0,
    .rx_errors = 0,
    .rx_crc_errors = 0,
    .rx_missed = 0,
    .collisions = 0,
    .link_changes = 0,
};
var eeprom_exists: bool = false;
var dma_initialized: bool = false;

// Pointer to the interface managed by network.zig
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
// DMA Buffer Allocation
// =============================================================================

fn allocateDmaBuffers() bool {
    serial.writeString("[E1000] Allocating DMA buffers...\n");

    hhdm_offset = pmm.getHhdmOffset();

    // Allocate TX descriptor ring
    tx_desc_ring_phys = pmm.allocPage() orelse {
        serial.writeString("[E1000] Failed to allocate TX descriptor ring!\n");
        return false;
    };
    tx_desc_ring = @ptrFromInt(physToVirt(tx_desc_ring_phys));

    // Allocate RX descriptor ring
    rx_desc_ring_phys = pmm.allocPage() orelse {
        serial.writeString("[E1000] Failed to allocate RX descriptor ring!\n");
        pmm.freePage(tx_desc_ring_phys);
        return false;
    };
    rx_desc_ring = @ptrFromInt(physToVirt(rx_desc_ring_phys));

    // Allocate TX buffers
    for (0..NUM_TX_DESC) |i| {
        tx_buffers_phys[i] = pmm.allocPage() orelse {
            serial.writeString("[E1000] Failed to allocate TX buffer!\n");
            freeDmaBuffers();
            return false;
        };
        tx_buffers[i] = @ptrFromInt(physToVirt(tx_buffers_phys[i]));
    }

    // Allocate RX buffers
    for (0..NUM_RX_DESC) |i| {
        rx_buffers_phys[i] = pmm.allocPage() orelse {
            serial.writeString("[E1000] Failed to allocate RX buffer!\n");
            freeDmaBuffers();
            return false;
        };
        rx_buffers[i] = @ptrFromInt(physToVirt(rx_buffers_phys[i]));
    }

    dma_initialized = true;
    serial.writeString("[E1000] DMA buffers allocated\n");
    return true;
}

fn freeDmaBuffers() void {
    if (tx_desc_ring_phys != 0) {
        pmm.freePage(tx_desc_ring_phys);
        tx_desc_ring_phys = 0;
        tx_desc_ring = null;
    }
    if (rx_desc_ring_phys != 0) {
        pmm.freePage(rx_desc_ring_phys);
        rx_desc_ring_phys = 0;
        rx_desc_ring = null;
    }
    for (0..NUM_TX_DESC) |i| {
        if (tx_buffers_phys[i] != 0) {
            pmm.freePage(tx_buffers_phys[i]);
            tx_buffers_phys[i] = 0;
            tx_buffers[i] = null;
        }
    }
    for (0..NUM_RX_DESC) |i| {
        if (rx_buffers_phys[i] != 0) {
            pmm.freePage(rx_buffers_phys[i]);
            rx_buffers_phys[i] = 0;
            rx_buffers[i] = null;
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

    const device_ids = [_]u16{ E1000_DEV_ID, E1000E_DEV_ID, E1000_82545EM, E1000_82546EB };

    for (device_ids) |dev_id| {
        if (pci.findDevice(INTEL_VENDOR_ID, dev_id)) |dev| {
            mmio_base = dev.bar0 & 0xFFFFFFF0;
            detected = true;

            pci.enableBusMaster(dev);
            pci.enableMemorySpace(dev);

            serial.writeString("[E1000] Device found at MMIO 0x");
            printHex64(@intCast(mmio_base));
            serial.writeString("\n");

            return true;
        }
    }

    return false;
}

pub fn init() void {
    if (!detected) {
        if (!probe()) {
            serial.writeString("[E1000] No E1000 device found\n");
            return;
        }
    }

    serial.writeString("[E1000] Initializing...\n");

    // Allocate DMA buffers
    if (!allocateDmaBuffers()) {
        serial.writeString("[E1000] DMA allocation failed, using fallback\n");
        mac_address = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
        initialized = true;
        return;
    }

    initHardware();

    initialized = true;
    serial.writeString("[E1000] Initialized, MAC: ");
    printMac(mac_address);
    serial.writeString("\n");
}

fn initHardware() void {
    if (mmio_base == 0) {
        mac_address = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
        serial.writeString("[E1000] No MMIO, using fallback\n");
        return;
    }

    serial.writeString("[E1000] Resetting device...\n");

    // Reset
    writeReg(E1000_CTRL, E1000_CTRL_RST);
    busyWait(100000);

    var timeout: u32 = 0;
    while (timeout < 1000) : (timeout += 1) {
        if ((readReg(E1000_CTRL) & E1000_CTRL_RST) == 0) break;
        busyWait(1000);
    }

    // Disable interrupts
    writeReg(E1000_IMC, 0xFFFFFFFF);
    _ = readReg(E1000_ICR);

    // Detect EEPROM and read MAC
    detectEeprom();
    readMacAddress();

    // Set link up
    var ctrl = readReg(E1000_CTRL);
    ctrl |= E1000_CTRL_SLU | E1000_CTRL_ASDE | E1000_CTRL_FD;
    ctrl &= ~(E1000_CTRL_LRST | E1000_CTRL_ILOS | E1000_CTRL_PHY_RST);
    writeReg(E1000_CTRL, ctrl);

    busyWait(100000);

    // Clear multicast table
    for (0..128) |j| {
        writeReg(E1000_MTA + @as(u32, @intCast(j)) * 4, 0);
    }

    // Initialize rings
    initTxRing();
    initRxRing();

    serial.writeString("[E1000] Hardware ready\n");
}

fn initTxRing() void {
    if (tx_desc_ring == null) return;

    const ring = tx_desc_ring.?;

    for (0..NUM_TX_DESC) |i| {
        ring[i].buffer_addr = tx_buffers_phys[i];
        ring[i].length = 0;
        ring[i].cso = 0;
        ring[i].cmd = 0;
        ring[i].status = 1; // DD bit set = available
        ring[i].css = 0;
        ring[i].special = 0;
    }

    asm volatile ("mfence" ::: .{ .memory = true });

    writeReg(E1000_TDBAL, @truncate(tx_desc_ring_phys & 0xFFFFFFFF));
    writeReg(E1000_TDBAH, @truncate((tx_desc_ring_phys >> 32) & 0xFFFFFFFF));
    writeReg(E1000_TDLEN, @intCast(NUM_TX_DESC * @sizeOf(E1000TxDesc)));
    writeReg(E1000_TDH, 0);
    writeReg(E1000_TDT, 0);
    tx_cur = 0;

    const tctl: u32 = E1000_TCTL_EN | E1000_TCTL_PSP |
        (@as(u32, 15) << E1000_TCTL_CT_SHIFT) |
        (@as(u32, 64) << E1000_TCTL_COLD_SHIFT);
    writeReg(E1000_TCTL, tctl);
}

fn initRxRing() void {
    if (rx_desc_ring == null) return;

    const ring = rx_desc_ring.?;

    for (0..NUM_RX_DESC) |i| {
        ring[i].buffer_addr = rx_buffers_phys[i];
        ring[i].length = 0;
        ring[i].checksum = 0;
        ring[i].status = 0;
        ring[i].errors = 0;
        ring[i].special = 0;
    }

    asm volatile ("mfence" ::: .{ .memory = true });

    writeReg(E1000_RDBAL, @truncate(rx_desc_ring_phys & 0xFFFFFFFF));
    writeReg(E1000_RDBAH, @truncate((rx_desc_ring_phys >> 32) & 0xFFFFFFFF));
    writeReg(E1000_RDLEN, @intCast(NUM_RX_DESC * @sizeOf(E1000RxDesc)));
    writeReg(E1000_RDH, 0);
    writeReg(E1000_RDT, @intCast(NUM_RX_DESC - 1));
    rx_cur = 0;

    const rctl: u32 = E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_BSIZE_2048 | E1000_RCTL_SECRC;
    writeReg(E1000_RCTL, rctl);
}

fn detectEeprom() void {
    writeReg(E1000_EERD, 0x01);

    for (0..1000) |_| {
        const val = readReg(E1000_EERD);
        if ((val & 0x10) != 0) {
            eeprom_exists = true;
            return;
        }
        busyWait(100);
    }
    eeprom_exists = false;
}

fn readEeprom(addr: u8) u16 {
    if (!eeprom_exists) return 0;

    writeReg(E1000_EERD, (@as(u32, addr) << 8) | 0x01);

    for (0..1000) |_| {
        const val = readReg(E1000_EERD);
        if ((val & 0x10) != 0) {
            return @intCast((val >> 16) & 0xFFFF);
        }
        busyWait(100);
    }
    return 0;
}

fn readMacAddress() void {
    if (eeprom_exists) {
        const mac_low = readEeprom(0);
        const mac_mid = readEeprom(1);
        const mac_high = readEeprom(2);

        mac_address[0] = @intCast(mac_low & 0xFF);
        mac_address[1] = @intCast((mac_low >> 8) & 0xFF);
        mac_address[2] = @intCast(mac_mid & 0xFF);
        mac_address[3] = @intCast((mac_mid >> 8) & 0xFF);
        mac_address[4] = @intCast(mac_high & 0xFF);
        mac_address[5] = @intCast((mac_high >> 8) & 0xFF);
    } else {
        const ral = readReg(E1000_RAL);
        const rah = readReg(E1000_RAH);

        mac_address[0] = @intCast(ral & 0xFF);
        mac_address[1] = @intCast((ral >> 8) & 0xFF);
        mac_address[2] = @intCast((ral >> 16) & 0xFF);
        mac_address[3] = @intCast((ral >> 24) & 0xFF);
        mac_address[4] = @intCast(rah & 0xFF);
        mac_address[5] = @intCast((rah >> 8) & 0xFF);
    }

    // Check for invalid MAC
    var all_zero = true;
    var all_ones = true;
    for (mac_address) |b| {
        if (b != 0) all_zero = false;
        if (b != 0xFF) all_ones = false;
    }

    if (all_zero or all_ones) {
        mac_address = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
    }

    // Write to RAL/RAH
    const ral_val: u32 = @as(u32, mac_address[0]) |
        (@as(u32, mac_address[1]) << 8) |
        (@as(u32, mac_address[2]) << 16) |
        (@as(u32, mac_address[3]) << 24);
    const rah_val: u32 = @as(u32, mac_address[4]) |
        (@as(u32, mac_address[5]) << 8) |
        0x80000000;

    writeReg(E1000_RAL, ral_val);
    writeReg(E1000_RAH, rah_val);
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

    if (mmio_base == 0 or !dma_initialized) {
        driver_stats.tx_packets += 1;
        driver_stats.tx_bytes += data.len;
        return true;
    }

    const ring = tx_desc_ring orelse return false;
    const cur = tx_cur;

    // Wait for descriptor
    var timeout: u32 = 0;
    while ((ring[cur].status & 1) == 0) {
        timeout += 1;
        if (timeout > 100000) {
            driver_stats.tx_errors += 1;
            return false;
        }
        busyWait(10);
    }

    // Copy data
    const buffer = tx_buffers[cur] orelse return false;
    for (data, 0..) |byte, i| {
        buffer[i] = byte;
    }

    asm volatile ("mfence" ::: .{ .memory = true });

    // Setup descriptor
    ring[cur].buffer_addr = tx_buffers_phys[cur];
    ring[cur].length = @intCast(data.len);
    ring[cur].cmd = 0x0B; // RS | IFCS | EOP
    ring[cur].status = 0;

    asm volatile ("mfence" ::: .{ .memory = true });

    // Advance tail
    tx_cur = (cur + 1) % NUM_TX_DESC;
    writeReg(E1000_TDT, @intCast(tx_cur));

    driver_stats.tx_packets += 1;
    driver_stats.tx_bytes += data.len;

    return true;
}

pub fn recvPacket(iface: *network.NetworkInterface, buffer: []u8) isize {
    _ = iface;

    if (!initialized or mmio_base == 0 or !dma_initialized) return 0;

    const ring = rx_desc_ring orelse return 0;
    const cur = rx_cur;

    if ((ring[cur].status & 1) == 0) return 0;

    if (ring[cur].errors != 0) {
        driver_stats.rx_errors += 1;
        ring[cur].status = 0;
        rx_cur = (cur + 1) % NUM_RX_DESC;
        writeReg(E1000_RDT, @intCast(cur));
        return -1;
    }

    const pkt_len = ring[cur].length;
    if (pkt_len == 0 or pkt_len > buffer.len) {
        ring[cur].status = 0;
        rx_cur = (cur + 1) % NUM_RX_DESC;
        writeReg(E1000_RDT, @intCast(cur));
        return 0;
    }

    const rx_buf = rx_buffers[cur] orelse return 0;
    for (0..pkt_len) |i| {
        buffer[i] = rx_buf[i];
    }

    driver_stats.rx_packets += 1;
    driver_stats.rx_bytes += pkt_len;

    ring[cur].status = 0;
    ring[cur].length = 0;

    const old_cur = cur;
    rx_cur = (cur + 1) % NUM_RX_DESC;
    writeReg(E1000_RDT, @intCast(old_cur));

    return @intCast(pkt_len);
}

/// Poll for received packets - uses managed interface
pub fn poll() void {
    if (!initialized or mmio_base == 0 or !dma_initialized) return;

    // Use the managed interface from network.zig
    const iface = managed_iface orelse return;

    var buffer: [2048]u8 = undefined;
    const len = recvPacket(iface, &buffer);

    if (len > 0) {
        network.handleRxPacket(iface, buffer[0..@intCast(len)]);
    }
}

// =============================================================================
// Interface Management
// =============================================================================

/// Set the managed interface pointer (called by network.zig)
pub fn setManagedInterface(iface: *network.NetworkInterface) void {
    managed_iface = iface;

    // Copy our MAC to the interface
    iface.mac = mac_address;
    iface.send_fn = sendPacket;
    iface.recv_fn = recvPacket;
    iface.interface_type = .e1000;
    iface.mtu = 1500;
    iface.driver_data = mmio_base;

    if (mmio_base != 0) {
        iface.state = .up;
    }

    serial.writeString("[E1000] Managed interface set, IP: ");
    printIp(iface.ip_addr);
    serial.writeString("\n");
}

pub fn getMac() network.MacAddress {
    return mac_address;
}

// =============================================================================
// Public Interface
// =============================================================================

/// Get managed interface pointer (for compatibility with other modules)
pub fn getInterface() ?*network.NetworkInterface {
    return managed_iface;
}

/// Get interface data as const copy (for read-only access)
pub fn getInterfaceConst() network.NetworkInterface {
    if (managed_iface) |iface| {
        return iface.*;
    }
    // Return fallback interface if not initialized
    var fallback = network.NetworkInterface{
        .id = 0,
        .name = [_]u8{0} ** 16,
        .name_len = 0,
        .interface_type = .e1000,
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
        .driver_data = mmio_base,
        .send_fn = sendPacket,
        .recv_fn = recvPacket,
    };
    fallback.setName("eth0");
    return fallback;
}

pub fn deinit() void {
    if (mmio_base != 0) {
        writeReg(E1000_RCTL, 0);
        writeReg(E1000_TCTL, 0);
        writeReg(E1000_IMC, 0xFFFFFFFF);
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

pub fn getMmioBase() usize {
    return mmio_base;
}

pub fn getStats() DriverStats {
    return driver_stats;
}

pub fn hasEeprom() bool {
    return eeprom_exists;
}

pub fn isLinkUp() bool {
    if (mmio_base == 0) return true;
    return (readReg(E1000_STATUS) & E1000_STATUS_LU) != 0;
}

pub fn getLinkSpeed() LinkSpeed {
    if (mmio_base == 0) return .speed_1000;

    const status = readReg(E1000_STATUS);
    const speed = status & E1000_STATUS_SPEED_MASK;

    return switch (speed) {
        E1000_STATUS_SPEED_10 => .speed_10,
        E1000_STATUS_SPEED_100 => .speed_100,
        E1000_STATUS_SPEED_1000 => .speed_1000,
        else => .unknown,
    };
}

pub fn isFullDuplex() bool {
    if (mmio_base == 0) return true;
    return (readReg(E1000_STATUS) & E1000_STATUS_FD) != 0;
}

pub fn getMtu() u16 {
    return 1500;
}

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
// Interrupt Handling
// =============================================================================

pub fn handleInterrupt() void {
    if (mmio_base == 0) return;

    const icr = readReg(E1000_ICR);

    if ((icr & E1000_ICR_LSC) != 0) {
        driver_stats.link_changes += 1;
    }

    if ((icr & E1000_ICR_RXT0) != 0) {
        poll();
    }
}

pub fn enableInterrupts() void {
    if (mmio_base == 0) return;
    writeReg(E1000_IMS, E1000_ICR_LSC | E1000_ICR_RXT0 | E1000_ICR_TXDW);
}

pub fn disableInterrupts() void {
    if (mmio_base == 0) return;
    writeReg(E1000_IMC, 0xFFFFFFFF);
}

// =============================================================================
// Configuration
// =============================================================================

pub fn setPromiscuous(enable: bool) void {
    if (mmio_base == 0) return;

    var rctl = readReg(E1000_RCTL);
    if (enable) {
        rctl |= E1000_RCTL_UPE | E1000_RCTL_MPE;
    } else {
        rctl &= ~(E1000_RCTL_UPE | E1000_RCTL_MPE);
    }
    writeReg(E1000_RCTL, rctl);
}

pub fn setMulticast(enable: bool) void {
    if (mmio_base == 0) return;

    var rctl = readReg(E1000_RCTL);
    if (enable) {
        rctl |= E1000_RCTL_MPE;
    } else {
        rctl &= ~E1000_RCTL_MPE;
    }
    writeReg(E1000_RCTL, rctl);
}

// =============================================================================
// MMIO Access
// =============================================================================

fn readReg(reg: u32) u32 {
    if (mmio_base == 0) return 0;
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + reg);
    return ptr.*;
}

fn writeReg(reg: u32, value: u32) void {
    if (mmio_base == 0) return;
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + reg);
    ptr.* = value;
}

pub fn readRegister(reg: u32) u32 {
    return readReg(reg);
}

pub fn writeRegister(reg: u32, value: u32) void {
    writeReg(reg, value);
}

// =============================================================================
// Debug
// =============================================================================

pub fn debugDump() void {
    serial.writeString("\n=== E1000 Debug ===\n");
    serial.writeString("MMIO: 0x");
    printHex64(@intCast(mmio_base));
    serial.writeString("\nInitialized: ");
    if (initialized) serial.writeString("yes") else serial.writeString("no");
    serial.writeString("\nDMA: ");
    if (dma_initialized) serial.writeString("yes") else serial.writeString("no");
    serial.writeString("\nMAC: ");
    printMac(mac_address);
    serial.writeString("\nTX: ");
    printDec64(driver_stats.tx_packets);
    serial.writeString(" pkts, RX: ");
    printDec64(driver_stats.rx_packets);
    serial.writeString(" pkts\n");
    if (managed_iface) |iface| {
        serial.writeString("Managed IP: ");
        printIp(iface.ip_addr);
        serial.writeString("\n");
    }
    serial.writeString("===================\n\n");
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

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
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

fn printIp(addr: u32) void {
    printU8(@intCast((addr >> 24) & 0xFF));
    serial.writeChar('.');
    printU8(@intCast((addr >> 16) & 0xFF));
    serial.writeChar('.');
    printU8(@intCast((addr >> 8) & 0xFF));
    serial.writeChar('.');
    printU8(@intCast(addr & 0xFF));
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
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
