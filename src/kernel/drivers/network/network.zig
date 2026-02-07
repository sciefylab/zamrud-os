//! Zamrud OS - Network Driver Interface
//! Abstraction layer for network hardware

const serial = @import("../serial/serial.zig");
const ethernet = @import("ethernet.zig");

// Import protocol handlers
const ip = @import("../../net/ip.zig");
const arp = @import("../../net/arp.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_PACKET_SIZE: usize = 1522;
pub const MAC_SIZE: usize = 6;
pub const MAX_INTERFACES: usize = 8;

// QEMU SLIRP default addresses
pub const QEMU_SLIRP_IP: u32 = ipToU32(10, 0, 2, 15);
pub const QEMU_SLIRP_GATEWAY: u32 = ipToU32(10, 0, 2, 2);
pub const QEMU_SLIRP_DNS: u32 = ipToU32(10, 0, 2, 3);
pub const QEMU_SLIRP_NETMASK: u32 = ipToU32(255, 255, 255, 0);

// =============================================================================
// Types
// =============================================================================

pub const MacAddress = [MAC_SIZE]u8;

pub const PacketBuffer = struct {
    data: [MAX_PACKET_SIZE]u8,
    len: usize,
    interface_id: u8,
    timestamp: u64,

    pub fn init() PacketBuffer {
        return .{
            .data = [_]u8{0} ** MAX_PACKET_SIZE,
            .len = 0,
            .interface_id = 0,
            .timestamp = 0,
        };
    }

    pub fn getSlice(self: *PacketBuffer) []u8 {
        return self.data[0..self.len];
    }

    pub fn getConstSlice(self: *const PacketBuffer) []const u8 {
        return self.data[0..self.len];
    }

    pub fn clear(self: *PacketBuffer) void {
        self.len = 0;
    }
};

pub const InterfaceType = enum {
    loopback,
    ethernet,
    virtio,
    e1000,
    unknown,
};

pub const InterfaceState = enum {
    down,
    up,
    error_state,
};

pub const NetworkInterface = struct {
    id: u8,
    name: [16]u8,
    name_len: usize,
    interface_type: InterfaceType,
    state: InterfaceState,
    mac: MacAddress,
    ip_addr: u32,
    netmask: u32,
    gateway: u32,
    mtu: u16,

    // Statistics
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,

    // Driver-specific data
    driver_data: usize,

    // Driver callbacks
    send_fn: ?*const fn (*NetworkInterface, []const u8) bool,
    recv_fn: ?*const fn (*NetworkInterface, []u8) isize,

    pub fn getName(self: *const NetworkInterface) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setName(self: *NetworkInterface, new_name: []const u8) void {
        const len = @min(new_name.len, 15);
        for (0..len) |i| {
            self.name[i] = new_name[i];
        }
        self.name_len = len;
    }

    pub fn send(self: *NetworkInterface, data: []const u8) bool {
        if (self.state != .up) {
            self.tx_dropped += 1;
            return false;
        }

        if (data.len > MAX_PACKET_SIZE) {
            self.tx_errors += 1;
            return false;
        }

        if (self.send_fn) |send_func| {
            const result = send_func(self, data);
            if (result) {
                self.tx_packets += 1;
                self.tx_bytes += data.len;
            } else {
                self.tx_errors += 1;
            }
            return result;
        }

        self.tx_dropped += 1;
        return false;
    }

    pub fn receive(self: *NetworkInterface, buffer: []u8) isize {
        if (self.state != .up) return -1;

        if (self.recv_fn) |recv_func| {
            const len = recv_func(self, buffer);
            if (len > 0) {
                self.rx_packets += 1;
                self.rx_bytes += @intCast(len);
            } else if (len < 0) {
                self.rx_errors += 1;
            }
            return len;
        }

        return -1;
    }

    pub fn recordRx(self: *NetworkInterface, len: usize, success: bool) void {
        if (success) {
            self.rx_packets += 1;
            self.rx_bytes += len;
        } else {
            self.rx_errors += 1;
        }
    }

    pub fn isUp(self: *const NetworkInterface) bool {
        return self.state == .up;
    }

    pub fn isLoopbackType(self: *const NetworkInterface) bool {
        return self.interface_type == .loopback;
    }
};

// =============================================================================
// State
// =============================================================================

var interfaces: [MAX_INTERFACES]NetworkInterface = undefined;
var interface_count: usize = 0;
var initialized: bool = false;

var rx_callback: ?*const fn (*NetworkInterface, []const u8) void = null;

// Loopback
var loopback_buffer: [MAX_PACKET_SIZE]u8 = undefined;
var loopback_pending: bool = false;
var loopback_len: usize = 0;
var loopback_iface_ptr: ?*NetworkInterface = null;

// E1000
var e1000_iface_ptr: ?*NetworkInterface = null;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[NET-DRV] Initializing network drivers...\n");

    interface_count = 0;
    loopback_pending = false;
    loopback_len = 0;
    loopback_iface_ptr = null;
    e1000_iface_ptr = null;
    rx_callback = null;

    for (&interfaces) |*iface| {
        iface.* = emptyInterface();
    }

    // Create loopback
    createLoopback();

    initialized = true;
    serial.writeString("[NET-DRV] Network drivers ready\n");
}

/// Late initialization - register hardware NICs
pub fn initHardware() void {
    const e1000 = @import("e1000.zig");

    if (e1000.probe()) {
        e1000.init();

        if (e1000.isInitialized()) {
            if (interface_count < MAX_INTERFACES) {
                // Get pointer to our interface slot
                var iface = &interfaces[interface_count];

                // Initialize interface
                iface.id = @intCast(interface_count);
                iface.setName("eth0");
                iface.interface_type = .e1000;
                iface.state = .up;
                iface.mtu = 1500;

                // Set IP configuration FIRST
                iface.ip_addr = QEMU_SLIRP_IP;
                iface.netmask = QEMU_SLIRP_NETMASK;
                iface.gateway = QEMU_SLIRP_GATEWAY;

                // Reset stats
                iface.rx_packets = 0;
                iface.tx_packets = 0;
                iface.rx_bytes = 0;
                iface.tx_bytes = 0;
                iface.rx_errors = 0;
                iface.tx_errors = 0;
                iface.rx_dropped = 0;
                iface.tx_dropped = 0;

                // Tell E1000 to use this interface
                e1000.setManagedInterface(iface);

                e1000_iface_ptr = iface;
                interface_count += 1;

                serial.writeString("[NET-DRV] E1000 registered:\n");
                serial.writeString("[NET-DRV]   IP:      ");
                printIp(iface.ip_addr);
                serial.writeString("\n[NET-DRV]   Netmask: ");
                printIp(iface.netmask);
                serial.writeString("\n[NET-DRV]   Gateway: ");
                printIp(iface.gateway);
                serial.writeString("\n[NET-DRV]   MAC:     ");
                printMac(iface.mac);
                serial.writeString("\n");
            }
        }
    } else {
        serial.writeString("[NET-DRV] No E1000 device found\n");
    }
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyInterface() NetworkInterface {
    return .{
        .id = 0,
        .name = [_]u8{0} ** 16,
        .name_len = 0,
        .interface_type = .unknown,
        .state = .down,
        .mac = [_]u8{0} ** MAC_SIZE,
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
        .driver_data = 0,
        .send_fn = null,
        .recv_fn = null,
    };
}

fn createLoopback() void {
    if (interface_count >= MAX_INTERFACES) return;

    var lo = &interfaces[interface_count];
    lo.id = @intCast(interface_count);
    lo.setName("lo");
    lo.interface_type = .loopback;
    lo.state = .up;
    lo.mac = [_]u8{0} ** MAC_SIZE;
    lo.ip_addr = ipToU32(127, 0, 0, 1);
    lo.netmask = ipToU32(255, 0, 0, 0);
    lo.gateway = 0;
    lo.mtu = 65535;
    lo.send_fn = loopbackSend;
    lo.recv_fn = loopbackRecv;

    loopback_iface_ptr = lo;
    interface_count += 1;
    serial.writeString("[NET-DRV] Loopback created (127.0.0.1)\n");
}

fn loopbackSend(iface: *NetworkInterface, data: []const u8) bool {
    if (data.len > loopback_buffer.len) return false;

    @memcpy(loopback_buffer[0..data.len], data);
    loopback_len = data.len;
    loopback_iface_ptr = iface;
    loopback_pending = true;

    iface.rx_packets += 1;
    iface.rx_bytes += data.len;

    // Process immediately
    ip.handlePacket(iface, loopback_buffer[0..loopback_len]);

    loopback_pending = false;
    loopback_len = 0;
    return true;
}

fn loopbackRecv(iface: *NetworkInterface, buffer: []u8) isize {
    _ = iface;

    if (!loopback_pending or loopback_len == 0) return 0;

    const copy_len = @min(loopback_len, buffer.len);
    @memcpy(buffer[0..copy_len], loopback_buffer[0..copy_len]);

    loopback_pending = false;
    const len = loopback_len;
    loopback_len = 0;

    return @intCast(len);
}

// =============================================================================
// Interface Management
// =============================================================================

pub fn getInterface(index: usize) ?*NetworkInterface {
    if (index >= interface_count) return null;
    return &interfaces[index];
}

pub fn getInterfaceByName(name: []const u8) ?*NetworkInterface {
    for (interfaces[0..interface_count]) |*iface| {
        if (strEqual(iface.getName(), name)) {
            return iface;
        }
    }
    return null;
}

pub fn getInterfaceCount() usize {
    return interface_count;
}

pub fn getAllInterfaces() []NetworkInterface {
    return interfaces[0..interface_count];
}

pub fn getDefaultInterface() ?*NetworkInterface {
    // Non-loopback UP with gateway
    for (interfaces[0..interface_count]) |*iface| {
        if (iface.interface_type != .loopback and iface.state == .up and iface.gateway != 0) {
            return iface;
        }
    }
    // Any non-loopback UP
    for (interfaces[0..interface_count]) |*iface| {
        if (iface.interface_type != .loopback and iface.state == .up) {
            return iface;
        }
    }
    // Loopback
    for (interfaces[0..interface_count]) |*iface| {
        if (iface.interface_type == .loopback and iface.state == .up) {
            return iface;
        }
    }
    return null;
}

pub fn getE1000Interface() ?*NetworkInterface {
    return e1000_iface_ptr;
}

// =============================================================================
// Interface Configuration
// =============================================================================

pub fn setIpAddress(iface: *NetworkInterface, ip_addr: u32, netmask: u32, gateway: u32) void {
    iface.ip_addr = ip_addr;
    iface.netmask = netmask;
    iface.gateway = gateway;
}

pub fn configureInterface(iface: *NetworkInterface, ip_addr: u32, netmask: u32, gateway: u32) void {
    setIpAddress(iface, ip_addr, netmask, gateway);
}

pub fn setInterfaceUp(iface: *NetworkInterface) void {
    iface.state = .up;
}

pub fn setInterfaceDown(iface: *NetworkInterface) void {
    iface.state = .down;
}

pub fn bringUp(iface: *NetworkInterface) bool {
    if (iface.state == .up) return true;
    setInterfaceUp(iface);
    return true;
}

pub fn bringDown(iface: *NetworkInterface) bool {
    if (iface.state == .down) return true;
    setInterfaceDown(iface);
    return true;
}

// =============================================================================
// Packet Handling
// =============================================================================

pub fn setRxCallback(callback: *const fn (*NetworkInterface, []const u8) void) void {
    rx_callback = callback;
}

/// Handle received packet - parse and route to protocol handlers
pub fn handleRxPacket(iface: *NetworkInterface, data: []const u8) void {
    // Validate
    if (data.len < 14) {
        iface.rx_errors += 1;
        return;
    }

    // For loopback, data is IP packet directly
    if (iface.interface_type == .loopback) {
        ip.handlePacket(iface, data);
        return;
    }

    // Parse ethernet frame
    const frame = ethernet.parse(data) orelse {
        iface.rx_errors += 1;
        return;
    };

    // Debug
    serial.writeString("[NET] handleRxPacket: len=");
    printDec(@intCast(data.len));
    serial.writeString(" iface=");
    serial.writeString(iface.getName());
    serial.writeString("\n[NET] ETH: src=");
    printMac(frame.header.src_mac);
    serial.writeString(" dst=");
    printMac(frame.header.dest_mac);
    serial.writeString(" type=0x");
    printHex16(frame.header.ethertype);
    serial.writeString("\n");

    // Route by ethertype
    switch (frame.header.ethertype) {
        ethernet.ETHERTYPE_IPV4 => {
            serial.writeString("[NET] -> IPv4 handler\n");
            ip.handlePacket(iface, frame.payload);
        },
        ethernet.ETHERTYPE_ARP => {
            serial.writeString("[NET] -> ARP handler\n");
            arp.handlePacket(iface, frame.payload);
        },
        else => {
            serial.writeString("[NET] Unknown ethertype\n");
        },
    }

    if (rx_callback) |callback| {
        callback(iface, data);
    }
}

pub fn sendPacket(iface: *NetworkInterface, data: []const u8) bool {
    return iface.send(data);
}

pub fn receivePacket(iface: *NetworkInterface, buffer: []u8) isize {
    return iface.receive(buffer);
}

// =============================================================================
// Polling
// =============================================================================

pub fn pollAll() void {
    const e1000 = @import("e1000.zig");

    if (e1000.isInitialized()) {
        e1000.poll();
    }
}

// =============================================================================
// Statistics
// =============================================================================

pub const NetworkStats = struct {
    total_rx_packets: u64,
    total_tx_packets: u64,
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    total_errors: u64,
    total_dropped: u64,
};

pub fn getStats() NetworkStats {
    var stats = NetworkStats{
        .total_rx_packets = 0,
        .total_tx_packets = 0,
        .total_rx_bytes = 0,
        .total_tx_bytes = 0,
        .total_errors = 0,
        .total_dropped = 0,
    };

    for (interfaces[0..interface_count]) |iface| {
        stats.total_rx_packets += iface.rx_packets;
        stats.total_tx_packets += iface.tx_packets;
        stats.total_rx_bytes += iface.rx_bytes;
        stats.total_tx_bytes += iface.tx_bytes;
        stats.total_errors += iface.rx_errors + iface.tx_errors;
        stats.total_dropped += iface.rx_dropped + iface.tx_dropped;
    }

    return stats;
}

pub fn resetStats() void {
    for (&interfaces) |*iface| {
        iface.rx_packets = 0;
        iface.tx_packets = 0;
        iface.rx_bytes = 0;
        iface.tx_bytes = 0;
        iface.rx_errors = 0;
        iface.tx_errors = 0;
        iface.rx_dropped = 0;
        iface.tx_dropped = 0;
    }
}

// =============================================================================
// Helpers
// =============================================================================

pub fn isLoopback(iface: *const NetworkInterface) bool {
    return iface.interface_type == .loopback;
}

pub fn getLoopbackInterface() ?*NetworkInterface {
    return loopback_iface_ptr;
}

// =============================================================================
// Utilities
// =============================================================================

pub fn ipToU32(a: u8, b: u8, c: u8, d: u8) u32 {
    return (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d);
}

pub fn u32ToIp(addr: u32) struct { a: u8, b: u8, c: u8, d: u8 } {
    return .{
        .a = @intCast((addr >> 24) & 0xFF),
        .b = @intCast((addr >> 16) & 0xFF),
        .c = @intCast((addr >> 8) & 0xFF),
        .d = @intCast(addr & 0xFF),
    };
}

pub fn ipInSameSubnet(ip1: u32, ip2: u32, netmask: u32) bool {
    return (ip1 & netmask) == (ip2 & netmask);
}

pub fn printIp(addr: u32) void {
    const parts = u32ToIp(addr);
    printU8(parts.a);
    serial.writeChar('.');
    printU8(parts.b);
    serial.writeChar('.');
    printU8(parts.c);
    serial.writeChar('.');
    printU8(parts.d);
}

pub fn printMac(mac: MacAddress) void {
    const hex = "0123456789abcdef";
    for (mac, 0..) |b, i| {
        serial.writeChar(hex[b >> 4]);
        serial.writeChar(hex[b & 0xF]);
        if (i < 5) serial.writeChar(':');
    }
}

pub fn macToString(mac: MacAddress) [17]u8 {
    const hex = "0123456789ABCDEF";
    var result: [17]u8 = undefined;
    var idx: usize = 0;

    for (mac, 0..) |byte, i| {
        result[idx] = hex[byte >> 4];
        result[idx + 1] = hex[byte & 0x0F];
        idx += 2;
        if (i < 5) {
            result[idx] = ':';
            idx += 1;
        }
    }

    return result;
}

pub fn compareMac(a: MacAddress, b: MacAddress) bool {
    for (a, b) |ba, bb| {
        if (ba != bb) return false;
    }
    return true;
}

pub fn isBroadcastMac(mac: MacAddress) bool {
    for (mac) |b| {
        if (b != 0xFF) return false;
    }
    return true;
}

pub fn isMulticastMac(mac: MacAddress) bool {
    return (mac[0] & 0x01) != 0;
}

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

fn printDec(val: u32) void {
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

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 12) & 0xF]);
    serial.writeChar(hex[(val >> 8) & 0xF]);
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

pub fn registerInterface(
    name: []const u8,
    iface_type: InterfaceType,
    mac: MacAddress,
    send_fn: ?*const fn (*NetworkInterface, []const u8) bool,
) ?*NetworkInterface {
    if (interface_count >= MAX_INTERFACES) return null;

    var iface = &interfaces[interface_count];
    iface.id = @intCast(interface_count);
    iface.setName(name);
    iface.interface_type = iface_type;
    iface.state = .down;
    iface.mac = mac;
    iface.mtu = 1500;
    iface.send_fn = send_fn;
    iface.recv_fn = null;

    interface_count += 1;
    return iface;
}

pub fn registerHardwareInterface(hw_iface: *NetworkInterface) bool {
    if (interface_count >= MAX_INTERFACES) return false;

    var iface = &interfaces[interface_count];
    iface.* = hw_iface.*;
    iface.id = @intCast(interface_count);

    interface_count += 1;
    return true;
}
