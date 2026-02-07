//! Zamrud OS - Network Stack

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const ethernet = @import("../drivers/network/ethernet.zig");
const arp = @import("arp.zig");
const ip = @import("ip.zig");
const icmp = @import("icmp.zig");
const udp = @import("udp.zig");
const tcp = @import("tcp.zig");
const checksum = @import("checksum.zig");
const socket = @import("socket.zig");
const dns = @import("dns.zig");
const dhcp = @import("dhcp.zig");
const firewall = @import("firewall.zig");
const arp_defense = @import("arp_defense.zig");
const pci = @import("../drivers/pci/pci.zig");
const virtio_net = @import("../drivers/network/virtio_net.zig");
const e1000 = @import("../drivers/network/e1000.zig");
const security = @import("../security/security.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const ConfigMode = enum { none, static, dhcp, qemu_slirp };

var config_mode: ConfigMode = .qemu_slirp;
var static_ip: u32 = 0;
var static_netmask: u32 = 0;
var static_gateway: u32 = 0;
var static_dns: u32 = 0;

const QEMU_IP: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 15;
const QEMU_NETMASK: u32 = (255 << 24) | (255 << 16) | (255 << 8) | 0;
const QEMU_GATEWAY: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 2;
const QEMU_DNS: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 3;

var initialized: bool = false;
var packets_received: u64 = 0;
var packets_sent: u64 = 0;
var packets_dropped: u64 = 0;
var primary_interface: ?*network.NetworkInterface = null;
var security_initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    printHeader("NETWORK STACK");

    if (!pci.isInitialized()) pci.init();

    network.init();
    initHardwareDrivers();
    ethernet.init();

    checksum.init();
    arp.init();
    ip.init();

    icmp.init();
    udp.init();
    tcp.init();

    socket.init();
    dns.init();
    dhcp.init();

    initSecurity();
    configureNetwork();

    initialized = true;
    printNetworkSummary();
}

fn printHeader(title: []const u8) void {
    serial.writeString("\n[");
    serial.writeString(title);
    serial.writeString("] ");
    var i: usize = 0;
    while (i < 40 - title.len) : (i += 1) serial.writeChar('-');
    serial.writeString("\n");
}

fn initSecurity() void {
    serial.writeString("[NET] Security init...\n");

    // Initialize security coordinator
    security.init();

    if (isQemuEnvironment()) {
        serial.writeString("[NET] QEMU mode - relaxed security\n");
        firewall.config.p2p_only_mode = false;
        firewall.config.block_icmp = false;
        arp_defense.config.require_signature = false;
        arp_defense.config.require_peer_binding = false;
    } else {
        serial.writeString("[NET] Bare metal - full security\n");
        firewall.config.p2p_only_mode = true;
        firewall.config.block_icmp = true;
        arp_defense.config.require_signature = true;
        arp_defense.config.require_peer_binding = true;
    }

    security_initialized = true;
}

fn isQemuEnvironment() bool {
    return virtio_net.isInitialized() or e1000.isInitialized();
}

fn initHardwareDrivers() void {
    if (virtio_net.probe()) {
        virtio_net.init();
        if (virtio_net.isInitialized()) {
            const viface = virtio_net.getInterface();
            _ = network.registerHardwareInterface(viface);
            serial.writeString("[NET] VirtIO registered\n");
            if (primary_interface == null) {
                primary_interface = network.getInterfaceByName("eth0");
            }
        }
    }

    network.initHardware();

    if (primary_interface == null) {
        primary_interface = network.getInterfaceByName("eth0") orelse
            network.getInterfaceByName("eth1");
    }

    serial.writeString("[NET] Interfaces: ");
    printNumber(network.getInterfaceCount());
    serial.writeString("\n");
}

fn configureNetwork() void {
    detectEnvironment();

    switch (config_mode) {
        .qemu_slirp => configureQemuSlirp(),
        .dhcp => configureDhcp(),
        .static => configureStatic(),
        .none => serial.writeString("[NET] No configuration\n"),
    }
}

fn detectEnvironment() void {
    if (virtio_net.isInitialized()) {
        config_mode = .qemu_slirp;
        serial.writeString("[NET] Detected: QEMU/VirtIO\n");
        return;
    }
    if (e1000.isInitialized()) {
        config_mode = .qemu_slirp;
        serial.writeString("[NET] Detected: QEMU/E1000\n");
        return;
    }
    config_mode = .dhcp;
    serial.writeString("[NET] Detected: Bare metal\n");
}

fn configureQemuSlirp() void {
    const iface = getPrimaryInterface() orelse {
        serial.writeString("[NET] No interface\n");
        return;
    };

    if (iface.ip_addr == 0) {
        iface.ip_addr = QEMU_IP;
        iface.netmask = QEMU_NETMASK;
        iface.gateway = QEMU_GATEWAY;
    }
    iface.state = .up;

    const gateway_mac: [6]u8 = .{ 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };
    arp.addEntry(QEMU_GATEWAY, gateway_mac);
    _ = arp_defense.createStaticBinding(gateway_mac, QEMU_GATEWAY, "QEMU GW");
    _ = dns.addServer(QEMU_DNS);
    _ = dns.addServer((8 << 24) | (8 << 16) | (8 << 8) | 8);

    serial.writeString("[NET] SLIRP configured\n");
}

fn configureDhcp() void {
    const iface = getPrimaryInterface() orelse return;
    iface.state = .up;

    if (dhcp.discover(iface)) {
        var timeout: u32 = 0;
        while (timeout < 50 and !dhcp.isBound()) : (timeout += 1) {
            pollNetwork();
            busyWait(100000);
        }

        if (dhcp.isBound()) {
            if (dhcp.getLease()) |lease| {
                iface.ip_addr = lease.ip_addr;
                iface.netmask = lease.subnet_mask;
                iface.gateway = lease.gateway;
                if (lease.dns_server != 0) _ = dns.addServer(lease.dns_server);
                serial.writeString("[NET] DHCP: ");
                printIp(lease.ip_addr);
                serial.writeString("\n");
            }
        } else {
            configureFallback(iface);
        }
    } else {
        configureFallback(iface);
    }
}

fn configureStatic() void {
    const iface = getPrimaryInterface() orelse return;

    if (static_ip != 0) {
        iface.ip_addr = static_ip;
        iface.netmask = static_netmask;
        iface.gateway = static_gateway;
        iface.state = .up;
        if (static_dns != 0) _ = dns.addServer(static_dns);
        serial.writeString("[NET] Static configured\n");
    } else {
        configureFallback(iface);
    }
}

fn configureFallback(iface: *network.NetworkInterface) void {
    if (e1000.isInitialized() or virtio_net.isInitialized()) {
        iface.ip_addr = QEMU_IP;
        iface.netmask = QEMU_NETMASK;
        iface.gateway = QEMU_GATEWAY;
        iface.state = .up;
        _ = dns.addServer(QEMU_DNS);
        serial.writeString("[NET] Fallback: SLIRP\n");
        return;
    }

    const mac = iface.mac;
    const local_ip: u32 = (169 << 24) | (254 << 16) | (@as(u32, mac[4]) << 8) | @as(u32, mac[5]);
    iface.ip_addr = local_ip;
    iface.netmask = (255 << 24) | (255 << 16) | 0 | 0;
    iface.gateway = 0;
    iface.state = .up;
    serial.writeString("[NET] Fallback: Link-local\n");
}

fn getPrimaryInterface() ?*network.NetworkInterface {
    if (primary_interface) |iface| return iface;

    var i: usize = 0;
    while (i < network.getInterfaceCount()) : (i += 1) {
        if (network.getInterface(i)) |iface| {
            if (iface.interface_type != .loopback) {
                primary_interface = iface;
                return iface;
            }
        }
    }
    return null;
}

fn pollNetwork() void {
    if (e1000.isInitialized()) e1000.poll();
    if (virtio_net.isInitialized()) virtio_net.poll();
}

fn busyWait(cycles: u32) void {
    var i: u32 = 0;
    while (i < cycles) : (i += 1) asm volatile ("pause");
}

fn printNetworkSummary() void {
    serial.writeString("\n[NETWORK READY] ");
    var i: usize = 0;
    while (i < 30) : (i += 1) serial.writeChar('-');
    serial.writeString("\n");

    serial.writeString("  Mode:     ");
    serial.writeString(switch (config_mode) {
        .qemu_slirp => "QEMU SLIRP",
        .dhcp => "DHCP",
        .static => "Static",
        .none => "None",
    });
    serial.writeString("\n");

    if (getPrimaryInterface()) |iface| {
        serial.writeString("  IP:       ");
        printIp(iface.ip_addr);
        serial.writeString("\n");
        serial.writeString("  Gateway:  ");
        printIp(iface.gateway);
        serial.writeString("\n");
    }

    serial.writeString("  Firewall: ");
    serial.writeString(switch (firewall.state) {
        .disabled => "OFF",
        .permissive => "PERMISSIVE",
        .enforcing => "ENFORCING",
        .lockdown => "LOCKDOWN",
    });
    serial.writeString("\n");

    serial.writeString("  ARP Def:  ");
    serial.writeString(if (arp.isSecurityEnabled()) "ON" else "OFF");
    serial.writeString("\n");

    i = 0;
    while (i < 45) : (i += 1) serial.writeChar('-');
    serial.writeString("\n\n");
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

fn printNumber(n: usize) void {
    if (n == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var num = n;
    while (num > 0) : (i += 1) {
        buf[i] = @intCast((num % 10) + '0');
        num /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

// =============================================================================
// Public API
// =============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn isSecurityEnabled() bool {
    return security_initialized and firewall.state != .disabled;
}

pub fn emergencyLockdown() void {
    serial.writeString("\n[!!!] NETWORK LOCKDOWN\n");
    firewall.setState(.lockdown);
}

pub fn disableLockdown() void {
    firewall.setState(.enforcing);
    serial.writeString("[NET] Lockdown disabled\n");
}

pub fn setConfigMode(mode: ConfigMode) void {
    config_mode = mode;
}

pub fn getConfigMode() ConfigMode {
    return config_mode;
}

pub fn setStaticConfig(ip_addr: u32, netmask: u32, gw: u32, dns_server: u32) void {
    static_ip = ip_addr;
    static_netmask = netmask;
    static_gateway = gw;
    static_dns = dns_server;
}

pub fn forceQemuMode() void {
    config_mode = .qemu_slirp;
    configureQemuSlirp();
}

pub fn forceDhcpMode() void {
    config_mode = .dhcp;
    configureDhcp();
}

pub fn reconfigure() void {
    configureNetwork();
}

pub fn shutdown() void {
    if (!initialized) return;
    serial.writeString("[NET] Shutdown...\n");
    socket.closeAll();
    if (e1000.isInitialized()) e1000.deinit();
    if (virtio_net.isInitialized()) virtio_net.deinit();
    packets_received = 0;
    packets_sent = 0;
    packets_dropped = 0;
    initialized = false;
}

pub fn incrementTxCounter() void {
    packets_sent += 1;
}

pub fn incrementDropCounter() void {
    packets_dropped += 1;
}

// Stats
pub const NetStats = struct {
    packets_received: u64,
    packets_sent: u64,
    packets_dropped: u64,
    interfaces: usize,
    sockets_active: usize,
    arp_entries: usize,
    pci_devices: usize,
    virtio_detected: bool,
    e1000_detected: bool,
    firewall_blocked: u64,
    firewall_allowed: u64,
    arp_spoofs_blocked: u64,
};

pub fn getStats() NetStats {
    const fw_stats = firewall.getStats();
    const arp_stats = arp.getSecurityStats();

    return .{
        .packets_received = packets_received,
        .packets_sent = packets_sent,
        .packets_dropped = packets_dropped,
        .interfaces = network.getInterfaceCount(),
        .sockets_active = socket.getSocketCount(),
        .arp_entries = arp.getCacheCount(),
        .pci_devices = pci.getDeviceCount(),
        .virtio_detected = virtio_net.isInitialized(),
        .e1000_detected = e1000.isInitialized(),
        .firewall_blocked = fw_stats.packets_dropped,
        .firewall_allowed = fw_stats.packets_allowed,
        .arp_spoofs_blocked = arp_stats.spoofs_blocked,
    };
}

pub fn resetStats() void {
    packets_received = 0;
    packets_sent = 0;
    packets_dropped = 0;
    firewall.resetStats();
}

// Interface access
pub fn getInterface(name: []const u8) ?*network.NetworkInterface {
    return network.getInterfaceByName(name);
}

pub fn getDefaultInterface() ?*network.NetworkInterface {
    return network.getDefaultInterface();
}

pub fn getInterfaceCount() usize {
    return network.getInterfaceCount();
}

pub fn getInterfaceByIndex(index: usize) ?*network.NetworkInterface {
    return network.getInterface(index);
}

// IP utils
pub fn ipToU32(a: u8, b: u8, c: u8, d: u8) u32 {
    return network.ipToU32(a, b, c, d);
}

pub fn u32ToIp(addr: u32) struct { a: u8, b: u8, c: u8, d: u8 } {
    return .{
        .a = @intCast((addr >> 24) & 0xFF),
        .b = @intCast((addr >> 16) & 0xFF),
        .c = @intCast((addr >> 8) & 0xFF),
        .d = @intCast(addr & 0xFF),
    };
}

pub fn ipToString(addr: u32, buffer: []u8) []const u8 {
    const octets = u32ToIp(addr);
    var pos: usize = 0;

    const vals = [_]u8{ octets.a, octets.b, octets.c, octets.d };
    for (vals, 0..) |v, i| {
        if (v >= 100) {
            buffer[pos] = '0' + v / 100;
            pos += 1;
        }
        if (v >= 10) {
            buffer[pos] = '0' + (v / 10) % 10;
            pos += 1;
        }
        buffer[pos] = '0' + v % 10;
        pos += 1;

        if (i < 3) {
            buffer[pos] = '.';
            pos += 1;
        }
    }

    return buffer[0..pos];
}

// High-level ops
pub fn ping(target_ip: u32) bool {
    const iface = getDefaultInterface() orelse return false;
    icmp.ping(iface, target_ip);
    return true;
}

pub fn resolve(hostname: []const u8) ?u32 {
    return dns.resolve(hostname);
}

pub fn dhcpDiscover() bool {
    const iface = getDefaultInterface() orelse return false;
    return dhcp.discover(iface);
}

pub fn hasDhcpLease() bool {
    return dhcp.isBound();
}

// Hardware status
pub fn isPciInitialized() bool {
    return pci.isInitialized();
}

pub fn isVirtioAvailable() bool {
    return virtio_net.isInitialized();
}

pub fn isE1000Available() bool {
    return e1000.isInitialized();
}

pub fn getVirtioInterface() ?*network.NetworkInterface {
    if (virtio_net.isInitialized()) return virtio_net.getInterface();
    return null;
}

pub fn getE1000Interface() ?*network.NetworkInterface {
    if (e1000.isInitialized()) return e1000.getInterface();
    return null;
}

// Socket re-exports
pub const SocketType = socket.SocketType;
pub const Socket = socket.Socket;

pub fn createSocket(sock_type: SocketType) ?*Socket {
    return socket.create(sock_type);
}

pub fn bindSocket(sock: *Socket, addr: u32, port: u16) bool {
    return socket.bind(sock, addr, port);
}

pub fn listenSocket(sock: *Socket, backlog: usize) bool {
    return socket.listen(sock, backlog);
}

pub fn connectSocket(sock: *Socket, addr: u32, port: u16) bool {
    return socket.connect(sock, addr, port);
}

pub fn sendSocket(sock: *Socket, data: []const u8) isize {
    return socket.send(sock, data);
}

pub fn recvSocket(sock: *Socket, buffer: []u8) isize {
    return socket.recv(sock, buffer);
}

pub fn closeSocket(sock: *Socket) void {
    socket.close(sock);
}

// Protocol access
pub fn getArpCache() []const arp.ArpEntry {
    return arp.getCache();
}

pub fn clearArpCache() void {
    arp.clearCache();
}

pub fn getDnsServers() []const u32 {
    return dns.getServers();
}

pub fn addDnsServer(ip_addr: u32) bool {
    return dns.addServer(ip_addr);
}

pub fn getIcmpStats() struct { sent: u64, received: u64 } {
    return icmp.getStats();
}

pub fn getUdpStats() struct { sent: u64, received: u64 } {
    return udp.getStats();
}

pub fn getTcpStats() struct { sent: u64, received: u64 } {
    return tcp.getStats();
}

// PCI access
pub fn getPciDeviceCount() usize {
    return pci.getDeviceCount();
}

pub fn listPciDevices() void {
    pci.listAllDevices();
}

pub fn findPciNetworkDevices() usize {
    var buffer: [8]?*const pci.PciDevice = undefined;
    return pci.findAllByClass(pci.CLASS_NETWORK, pci.SUBCLASS_ETHERNET, &buffer);
}

pub fn getFirewallStats() firewall.FirewallStats {
    return firewall.getStats();
}

pub fn getArpDefenseStats() arp_defense.ArpDefenseStats {
    return arp_defense.getStats();
}
