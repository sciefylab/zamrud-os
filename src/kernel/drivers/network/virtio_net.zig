//! Zamrud OS - VirtIO Network Driver
//! For QEMU/KVM virtual machines

const serial = @import("../serial/serial.zig");
const network = @import("network.zig");
const pci = @import("../pci/pci.zig");

// =============================================================================
// Constants (Public)
// =============================================================================

pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_NET_DEVICE_ID: u16 = 0x1000;
pub const VIRTIO_NET_MODERN_ID: u16 = 0x1041;

// VirtIO registers (legacy)
pub const VIRTIO_REG_DEVICE_FEATURES: u16 = 0x00;
pub const VIRTIO_REG_GUEST_FEATURES: u16 = 0x04;
pub const VIRTIO_REG_QUEUE_ADDR: u16 = 0x08;
pub const VIRTIO_REG_QUEUE_SIZE: u16 = 0x0C;
pub const VIRTIO_REG_QUEUE_SELECT: u16 = 0x0E;
pub const VIRTIO_REG_QUEUE_NOTIFY: u16 = 0x10;
pub const VIRTIO_REG_DEVICE_STATUS: u16 = 0x12;
pub const VIRTIO_REG_ISR_STATUS: u16 = 0x13;
pub const VIRTIO_REG_MAC: u16 = 0x14;

// Device status bits
pub const VIRTIO_STATUS_RESET: u8 = 0;
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

// VirtIO Feature Bits (Network)
pub const VIRTIO_NET_F_CSUM: u32 = 1 << 0;
pub const VIRTIO_NET_F_GUEST_CSUM: u32 = 1 << 1;
pub const VIRTIO_NET_F_MAC: u32 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;

// Queue indices
pub const VIRTIO_NET_QUEUE_RX: u16 = 0;
pub const VIRTIO_NET_QUEUE_TX: u16 = 1;
pub const VIRTIO_NET_QUEUE_CTRL: u16 = 2;

// =============================================================================
// Types
// =============================================================================

pub const VirtioNetHeader = extern struct {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
};

pub const VirtqDesc = extern struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

pub const VirtqAvail = extern struct {
    flags: u16,
    idx: u16,
    ring: [256]u16,
    used_event: u16,
};

pub const VirtqUsedElem = extern struct {
    id: u32,
    len: u32,
};

pub const DriverStats = struct {
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_errors: u64,
    rx_errors: u64,
    interrupts: u64,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var detected: bool = false;
var io_base: u16 = 0;
var virtio_interface: network.NetworkInterface = undefined;
var driver_stats: DriverStats = .{
    .tx_packets = 0,
    .rx_packets = 0,
    .tx_bytes = 0,
    .rx_bytes = 0,
    .tx_errors = 0,
    .rx_errors = 0,
    .interrupts = 0,
};
var device_features: u32 = 0;
var negotiated_features: u32 = 0;

// =============================================================================
// Probe & Init
// =============================================================================

pub fn probe() bool {
    if (!pci.isInitialized()) {
        return false;
    }

    // Look for VirtIO network device (legacy)
    if (pci.findDevice(VIRTIO_VENDOR_ID, VIRTIO_NET_DEVICE_ID)) |dev| {
        io_base = @intCast(dev.bar0 & 0xFFFC);
        detected = true;
        return true;
    }

    // Look for VirtIO network device (modern)
    if (pci.findDevice(VIRTIO_VENDOR_ID, VIRTIO_NET_MODERN_ID)) |dev| {
        io_base = @intCast(dev.bar0 & 0xFFFC);
        detected = true;
        return true;
    }

    return false;
}

pub fn init() void {
    if (!detected) {
        // Auto-probe if not already detected
        if (!probe()) return;
    }

    serial.writeString("[VIRTIO-NET] Initializing...\n");

    virtio_interface = network.NetworkInterface{
        .id = 0,
        .name = [_]u8{0} ** 16,
        .name_len = 4,
        .interface_type = .virtio,
        .state = .down,
        .mac = [_]u8{0} ** network.MAC_SIZE,
        .ip_addr = 0,
        .netmask = 0,
        .gateway = 0,
        .mtu = 1500,
        .rx_packets = 0,
        .tx_packets = 0,
        .rx_bytes = 0,
        .tx_bytes = 0,
        .rx_errors = 0,
        .tx_errors = 0,
        .rx_dropped = 0,
        .tx_dropped = 0,
        .driver_data = io_base,
        .send_fn = send,
        .recv_fn = recv,
    };

    // Set name "eth0"
    virtio_interface.name[0] = 'e';
    virtio_interface.name[1] = 't';
    virtio_interface.name[2] = 'h';
    virtio_interface.name[3] = '0';

    readMacAddress();
    initDevice();

    initialized = true;
    serial.writeString("[VIRTIO-NET] Initialized, MAC: ");
    network.printMac(virtio_interface.mac);
    serial.writeString("\n");
}

fn readMacAddress() void {
    if (io_base == 0) {
        // Generate random MAC for testing (52:54:00 is QEMU's OUI)
        virtio_interface.mac = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
        return;
    }

    for (0..6) |i| {
        virtio_interface.mac[i] = inb(io_base + VIRTIO_REG_MAC + @as(u16, @intCast(i)));
    }
}

fn initDevice() void {
    if (io_base == 0) {
        virtio_interface.state = .up;
        return;
    }

    // Reset device
    outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_RESET);

    // Acknowledge device
    outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

    // Driver loaded
    outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    // Read device features
    device_features = inl(io_base + VIRTIO_REG_DEVICE_FEATURES);

    // Negotiate features (accept MAC and status)
    negotiated_features = device_features & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
    outl(io_base + VIRTIO_REG_GUEST_FEATURES, negotiated_features);

    // Features OK
    outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);

    // Check if features were accepted
    const status = inb(io_base + VIRTIO_REG_DEVICE_STATUS);
    if ((status & VIRTIO_STATUS_FEATURES_OK) == 0) {
        serial.writeString("[VIRTIO-NET] Feature negotiation failed\n");
        return;
    }

    // Driver OK - device is now live
    outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

    virtio_interface.state = .up;
}

pub fn deinit() void {
    if (io_base != 0) {
        outb(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_RESET);
    }
    initialized = false;
    detected = false;
    virtio_interface.state = .down;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn isDetected() bool {
    return detected;
}

pub fn getInterface() *network.NetworkInterface {
    return &virtio_interface;
}

pub fn getInterfaceConst() network.NetworkInterface {
    return virtio_interface;
}

pub fn getIoBase() u16 {
    return io_base;
}

pub fn getDeviceFeatures() u32 {
    return device_features;
}

pub fn getNegotiatedFeatures() u32 {
    return negotiated_features;
}

pub fn getStats() DriverStats {
    return driver_stats;
}

pub fn hasFeature(feature: u32) bool {
    return (negotiated_features & feature) != 0;
}

// =============================================================================
// Send/Receive
// =============================================================================

fn send(iface: *network.NetworkInterface, data: []const u8) bool {
    _ = iface;

    if (!initialized) return false;
    if (data.len > 1514) return false; // Max ethernet frame

    driver_stats.tx_packets += 1;
    driver_stats.tx_bytes += data.len;

    // In a real implementation, this would:
    // 1. Allocate a descriptor in the TX virtqueue
    // 2. Copy data with VirtIO header prepended
    // 3. Notify the device

    return true;
}

fn recv(iface: *network.NetworkInterface, buffer: []u8) isize {
    _ = iface;
    _ = buffer;

    // In a real implementation, this would:
    // 1. Check the used ring for completed RX descriptors
    // 2. Copy data from the buffer (minus VirtIO header)
    // 3. Replenish the available ring

    return 0;
}

pub fn transmit(data: []const u8) bool {
    return send(&virtio_interface, data);
}

pub fn receive(buffer: []u8) isize {
    return recv(&virtio_interface, buffer);
}

// =============================================================================
// Polling
// =============================================================================

pub fn poll() void {
    if (!initialized) return;
    if (io_base == 0) return;

    // Check ISR status for pending work
    const isr = inb(io_base + VIRTIO_REG_ISR_STATUS);
    if (isr != 0) {
        driver_stats.interrupts += 1;

        // In a full implementation, this would:
        // 1. Check RX used ring for received packets
        // 2. Process each received packet
        // 3. Replenish RX available ring with new buffers
        // 4. Check TX used ring for completed transmissions
    }
}

// =============================================================================
// Interrupt Handling
// =============================================================================

pub fn handleInterrupt() void {
    if (io_base == 0) return;

    // Read and acknowledge ISR
    const isr = inb(io_base + VIRTIO_REG_ISR_STATUS);
    _ = isr;

    driver_stats.interrupts += 1;

    // Process RX queue
    // Process TX completions
}

// =============================================================================
// Status Queries
// =============================================================================

pub fn isLinkUp() bool {
    if (!initialized) return false;
    return virtio_interface.state == .up;
}

pub fn getMtu() u16 {
    return virtio_interface.mtu;
}

pub fn getMac() network.MacAddress {
    return virtio_interface.mac;
}

pub fn getDeviceStatus() u8 {
    if (io_base == 0) return 0;
    return inb(io_base + VIRTIO_REG_DEVICE_STATUS);
}

// =============================================================================
// Port I/O
// =============================================================================

fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "N{dx}" (port),
    );
}

fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "N{dx}" (port),
    );
}
