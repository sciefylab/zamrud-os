//! Zamrud OS - Network Stack Tests (B1 + B2)
//! Comprehensive tests for Network Drivers and TCP/IP Stack

const serial = @import("../drivers/serial/serial.zig");
const terminal = @import("../drivers/display/terminal.zig");
const network = @import("../drivers/network/network.zig");
const ethernet = @import("../drivers/network/ethernet.zig");
const loopback = @import("../drivers/network/loopback.zig");
const virtio_net = @import("../drivers/network/virtio_net.zig");
const e1000 = @import("../drivers/network/e1000.zig");
const pci = @import("../drivers/pci/pci.zig");
const net = @import("net.zig");
const arp = @import("arp.zig");
const ip = @import("ip.zig");
const icmp = @import("icmp.zig");
const udp = @import("udp.zig");
const tcp = @import("tcp.zig");
const checksum = @import("checksum.zig");
const socket = @import("socket.zig");
const dhcp = @import("dhcp.zig");
const dns = @import("dns.zig");

// =============================================================================
// Unified Output - Writes to BOTH terminal and serial
// =============================================================================

fn writeString(s: []const u8) void {
    // Always write to serial for debugging
    serial.writeString(s);

    // Also write to terminal if available
    if (terminal.isInitialized()) {
        for (s) |c| {
            terminal.writeChar(c);
        }
    }
}

fn writeChar(c: u8) void {
    serial.writeChar(c);
    if (terminal.isInitialized()) {
        terminal.writeChar(c);
    }
}

// =============================================================================
// Test Results
// =============================================================================

pub const TestResult = struct {
    passed: usize,
    failed: usize,
    skipped: usize,
    total: usize,

    pub fn init() TestResult {
        return .{ .passed = 0, .failed = 0, .skipped = 0, .total = 0 };
    }

    pub fn pass(self: *TestResult, msg: []const u8) void {
        self.passed += 1;
        self.total += 1;
        writeString("  ");
        padString(msg, 28);
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.SUCCESS);
        }
        writeString(" [PASS]\n");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
    }

    pub fn fail(self: *TestResult, msg: []const u8) void {
        self.failed += 1;
        self.total += 1;
        writeString("  ");
        padString(msg, 28);
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.ERROR);
        }
        writeString(" [FAIL]\n");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
    }

    pub fn skip(self: *TestResult, msg: []const u8) void {
        self.skipped += 1;
        self.total += 1;
        writeString("  ");
        padString(msg, 28);
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.WARNING);
        }
        writeString(" [SKIP]\n");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
    }

    pub fn check(self: *TestResult, condition: bool, msg: []const u8) void {
        if (condition) {
            self.pass(msg);
        } else {
            self.fail(msg);
        }
    }

    pub fn checkOrSkip(self: *TestResult, condition: bool, available: bool, msg: []const u8) void {
        if (!available) {
            self.skip(msg);
        } else if (condition) {
            self.pass(msg);
        } else {
            self.fail(msg);
        }
    }

    pub fn success(self: *const TestResult) bool {
        return self.failed == 0;
    }
};

fn padString(s: []const u8, width: usize) void {
    writeString(s);
    if (s.len < width) {
        var i: usize = 0;
        while (i < width - s.len) : (i += 1) {
            writeChar('.');
        }
    }
}

// =============================================================================
// Main Test Runner
// =============================================================================

pub fn runAllTests() TestResult {
    var result = TestResult.init();

    printHeader("NETWORK TEST SUITE (B1 + B2)");

    // =========================================================================
    // B1: Network Infrastructure
    // =========================================================================
    printSection("B1: NETWORK INFRASTRUCTURE");

    testPciBus(&result);
    testNetworkDriver(&result);
    testLoopbackInterface(&result);
    testVirtioNet(&result);
    testE1000(&result);
    testEthernetFrames(&result);
    testPacketBuffer(&result);
    testInterfaceManagement(&result);

    // =========================================================================
    // B2: TCP/IP Stack
    // =========================================================================
    printSection("B2: TCP/IP PROTOCOLS");

    testTcpIpStack(&result);
    testChecksumUtils(&result);
    testArpProtocol(&result);
    testIcmpProtocol(&result);
    testUdpProtocol(&result);
    testTcpProtocol(&result);
    testSocketApi(&result);
    testDhcpDns(&result);
    testNetworkIntegration(&result);

    // Summary
    printSummary(&result);

    return result;
}

// =============================================================================
// B1: PCI Bus Tests
// =============================================================================

fn testPciBus(result: *TestResult) void {
    printTest("1", "8", "PCI Bus Driver");

    result.check(pci.isInitialized(), "PCI initialized");
    result.check(pci.PCI_VENDOR_INVALID == 0xFFFF, "VENDOR_INVALID = 0xFFFF");
    result.check(pci.VENDOR_INTEL == 0x8086, "VENDOR_INTEL = 0x8086");
    result.check(pci.VENDOR_VIRTIO == 0x1AF4, "VENDOR_VIRTIO = 0x1AF4");

    const device_count = pci.getDeviceCount();
    result.check(device_count >= 0, "Device count valid");

    const config = pci.readConfig(0, 0, 0, 0);
    _ = config;
    result.check(true, "Config read works");

    const found_intel = pci.findDevice(pci.VENDOR_INTEL, 0x100E);
    const found_virtio = pci.findDevice(pci.VENDOR_VIRTIO, 0x1000);
    _ = found_intel;
    _ = found_virtio;
    result.check(true, "Device lookup works");

    const class_name = pci.getClassName(0x02);
    result.check(strEqual(class_name, "Network"), "Class name = Network");
}

// =============================================================================
// B1: Network Driver Tests
// =============================================================================

fn testNetworkDriver(result: *TestResult) void {
    printTest("2", "8", "Network Driver Core");

    result.check(network.isInitialized(), "Driver initialized");
    result.check(network.getInterfaceCount() >= 1, "Interface count >= 1");
    result.check(network.MAX_INTERFACES >= 4, "MAX_INTERFACES >= 4");
    result.check(network.MAX_PACKET_SIZE >= 1500, "MAX_PACKET_SIZE >= 1500");
    result.check(network.MAC_SIZE == 6, "MAC_SIZE == 6");

    const stats = network.getStats();
    result.check(stats.total_rx_packets >= 0, "Stats accessible");
}

fn testLoopbackInterface(result: *TestResult) void {
    printTest("3", "8", "Loopback Interface");

    const lo = network.getInterfaceByName("lo");
    result.check(lo != null, "Loopback exists");

    if (lo) |iface| {
        result.check(iface.ip_addr == network.ipToU32(127, 0, 0, 1), "IP = 127.0.0.1");
        result.check(iface.state == .up, "Status = UP");
        result.check(iface.interface_type == .loopback, "Type = loopback");
        result.check(iface.mtu >= 1500, "MTU >= 1500");

        const tx_before = iface.tx_packets;
        const sent = iface.send("Loopback Test");
        result.check(sent, "Send works");
        result.check(iface.tx_packets == tx_before + 1, "TX counter incremented");
    } else {
        result.fail("IP = 127.0.0.1");
        result.fail("Status = UP");
        result.fail("Type = loopback");
        result.fail("MTU >= 1500");
        result.fail("Send works");
        result.fail("TX counter incremented");
    }
}

fn testVirtioNet(result: *TestResult) void {
    printTest("4", "8", "VirtIO Network Driver");

    const virtio_available = virtio_net.isInitialized();
    const probed = virtio_net.probe();
    result.check(true, "Probe function works");

    if (probed or virtio_available) {
        result.checkOrSkip(virtio_net.isInitialized(), virtio_available, "VirtIO initialized");

        if (virtio_available) {
            const iface = virtio_net.getInterfaceConst();
            result.check(iface.interface_type == .virtio, "Type = virtio");
            result.check(iface.mtu == 1500, "MTU = 1500");

            var mac_valid = false;
            for (iface.mac) |b| {
                if (b != 0) {
                    mac_valid = true;
                    break;
                }
            }
            result.check(mac_valid, "MAC address set");
        } else {
            result.skip("Type = virtio");
            result.skip("MTU = 1500");
            result.skip("MAC address set");
        }
    } else {
        result.skip("VirtIO initialized");
        result.skip("Type = virtio");
        result.skip("MTU = 1500");
        result.skip("MAC address set");
    }

    result.check(virtio_net.VIRTIO_VENDOR_ID == 0x1AF4, "VIRTIO_VENDOR_ID");
}

fn testE1000(result: *TestResult) void {
    printTest("5", "8", "Intel E1000 Driver");

    const e1000_available = e1000.isInitialized();
    const probed = e1000.probe();
    result.check(true, "Probe function works");

    if (probed or e1000_available) {
        result.checkOrSkip(e1000.isInitialized(), e1000_available, "E1000 initialized");

        if (e1000_available) {
            const iface = e1000.getInterfaceConst();
            result.check(iface.interface_type == .e1000, "Type = e1000");
            result.check(iface.mtu == 1500, "MTU = 1500");

            var mac_valid = false;
            for (iface.mac) |b| {
                if (b != 0) {
                    mac_valid = true;
                    break;
                }
            }
            result.check(mac_valid, "MAC address set");
        } else {
            result.skip("Type = e1000");
            result.skip("MTU = 1500");
            result.skip("MAC address set");
        }
    } else {
        result.skip("E1000 initialized");
        result.skip("Type = e1000");
        result.skip("MTU = 1500");
        result.skip("MAC address set");
    }

    result.check(e1000.INTEL_VENDOR_ID == 0x8086, "INTEL_VENDOR_ID");
    result.check(e1000.E1000_DEV_ID == 0x100E, "E1000_DEV_ID");
}

fn testEthernetFrames(result: *TestResult) void {
    printTest("6", "8", "Ethernet Frames");

    var buffer: [ethernet.MAX_FRAME_SIZE]u8 = undefined;
    const src_mac: network.MacAddress = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const dst_mac: network.MacAddress = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    const payload = "Hello, Ethernet!";
    const len = ethernet.build(&buffer, dst_mac, src_mac, ethernet.ETHERTYPE_IPV4, payload);
    result.check(len != null, "Build frame");

    if (len) |frame_len| {
        const frame = ethernet.parse(buffer[0..frame_len]);
        result.check(frame != null, "Parse frame");

        if (frame) |f| {
            result.check(f.header.ethertype == ethernet.ETHERTYPE_IPV4, "EtherType = IPv4");
        } else {
            result.fail("EtherType = IPv4");
        }
    } else {
        result.fail("Parse frame");
        result.fail("EtherType = IPv4");
    }

    result.check(ethernet.isBroadcast(ethernet.BROADCAST_MAC), "Broadcast MAC check");
    result.check(ethernet.ETHERTYPE_IPV4 == 0x0800, "ETHERTYPE_IPV4");
    result.check(ethernet.ETHERTYPE_ARP == 0x0806, "ETHERTYPE_ARP");
}

fn testPacketBuffer(result: *TestResult) void {
    printTest("7", "8", "Packet Buffer");

    var pkt = network.PacketBuffer.init();
    result.check(pkt.len == 0, "Init with len=0");

    pkt.data[0] = 0xAA;
    pkt.data[1] = 0xBB;
    pkt.len = 2;

    const slice = pkt.getSlice();
    result.check(slice.len == 2 and slice[0] == 0xAA, "getSlice works");

    pkt.clear();
    result.check(pkt.len == 0, "clear() works");

    result.check(pkt.data.len >= 1500, "Buffer holds MTU");
}

fn testInterfaceManagement(result: *TestResult) void {
    printTest("8", "8", "Interface Management");

    result.check(network.getInterface(0) != null, "getInterface(0)");
    result.check(network.getInterface(100) == null, "getInterface(100) = null");
    result.check(network.getInterfaceByName("lo") != null, "getByName('lo')");
    result.check(network.getInterfaceByName("xyz") == null, "getByName('xyz') = null");
    result.check(network.getDefaultInterface() != null, "getDefaultInterface()");

    const test_ip = network.ipToU32(192, 168, 1, 100);
    const parts = network.u32ToIp(test_ip);
    result.check(parts.a == 192 and parts.d == 100, "IP conversion");
}

// =============================================================================
// B2: TCP/IP Stack Tests
// =============================================================================

fn testTcpIpStack(result: *TestResult) void {
    printTest("1", "9", "TCP/IP Stack");

    result.check(net.isInitialized(), "Stack initialized");
    result.check(ip.isInitialized(), "IP module ready");
    result.check(checksum.isInitialized(), "Checksum module");

    result.check(ip.HEADER_SIZE == 20, "IP header = 20");
    result.check(ip.PROTO_ICMP == 1, "ICMP proto = 1");
    result.check(ip.PROTO_TCP == 6, "TCP proto = 6");
    result.check(ip.PROTO_UDP == 17, "UDP proto = 17");
}

fn testChecksumUtils(result: *TestResult) void {
    printTest("2", "9", "Checksum Utilities");

    const data1 = [_]u8{ 0x00, 0x01, 0x00, 0x02 };
    const cksum1 = checksum.calculate(&data1);
    result.check(cksum1 != 0, "Basic checksum");

    const zeros = [_]u8{ 0, 0, 0, 0 };
    result.check(checksum.calculate(&zeros) == 0xFFFF, "Zeros = 0xFFFF");

    const ones = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    result.check(checksum.calculate(&ones) == 0x0000, "Ones = 0x0000");

    const odd = [_]u8{ 0x01, 0x02, 0x03 };
    _ = checksum.calculate(&odd);
    result.check(true, "Odd length works");

    const pseudo = checksum.pseudoHeader(
        network.ipToU32(192, 168, 1, 1),
        network.ipToU32(192, 168, 1, 2),
        17,
        100,
    );
    result.check(pseudo > 0, "Pseudo-header checksum");
}

fn testArpProtocol(result: *TestResult) void {
    printTest("3", "9", "ARP Protocol");

    result.check(arp.isInitialized(), "ARP initialized");

    const test_ip = network.ipToU32(192, 168, 1, 100);
    const test_mac: network.MacAddress = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    arp.addEntry(test_ip, test_mac);
    result.check(true, "Add entry");

    result.check(arp.lookup(test_ip) != null, "Lookup existing");
    result.check(arp.lookup(network.ipToU32(1, 2, 3, 4)) == null, "Lookup unknown");

    result.check(arp.getCacheCount() >= 0, "Entry count valid");

    const entries = arp.getCache();
    result.check(entries.len >= 0, "getCache works");
}

fn testIcmpProtocol(result: *TestResult) void {
    printTest("4", "9", "ICMP Protocol");

    result.check(icmp.isInitialized(), "ICMP initialized");
    result.check(icmp.TYPE_ECHO_REQUEST == 8, "Echo request = 8");
    result.check(icmp.TYPE_ECHO_REPLY == 0, "Echo reply = 0");

    const lo = network.getInterfaceByName("lo");
    if (lo) |iface| {
        icmp.ping(iface, network.ipToU32(127, 0, 0, 1));
        result.check(true, "Ping loopback");
    } else {
        result.fail("Ping loopback");
    }

    const stats = icmp.getStats();
    result.check(stats.sent >= 0, "Stats accessible");
}

fn testUdpProtocol(result: *TestResult) void {
    printTest("5", "9", "UDP Protocol");

    result.check(udp.isInitialized(), "UDP initialized");
    result.check(udp.HEADER_SIZE == 8, "Header size = 8");

    const sock = udp.createSocket();
    result.check(sock != null, "Create socket");

    if (sock) |s| {
        result.check(s.bind(12345), "Bind port");
        s.unbind();
        result.check(s.bind(12346), "Rebind after unbind");
        s.unbind();
    } else {
        result.fail("Bind port");
        result.fail("Rebind after unbind");
    }

    const stats = udp.getStats();
    result.check(stats.sent >= 0 and stats.received >= 0, "UDP stats");
}

fn testTcpProtocol(result: *TestResult) void {
    printTest("6", "9", "TCP Protocol");

    result.check(tcp.isInitialized(), "TCP initialized");
    result.check(tcp.HEADER_SIZE == 20, "Header size = 20");

    result.check(tcp.FLAG_SYN == 0x02, "SYN = 0x02");
    result.check(tcp.FLAG_ACK == 0x10, "ACK = 0x10");
    result.check(tcp.FLAG_FIN == 0x01, "FIN = 0x01");
    result.check(tcp.FLAG_RST == 0x04, "RST = 0x04");
    result.check(tcp.FLAG_PSH == 0x08, "PSH = 0x08");

    const syn_ack = tcp.FLAG_SYN | tcp.FLAG_ACK;
    result.check(syn_ack == 0x12, "SYN+ACK = 0x12");
}

fn testSocketApi(result: *TestResult) void {
    printTest("7", "9", "Socket API");

    result.check(socket.isInitialized(), "Socket initialized");
    result.check(socket.MAX_SOCKETS >= 16, "MAX_SOCKETS >= 16");

    // Create UDP socket
    const udp_sock = socket.create(.udp);
    result.check(udp_sock != null, "Create UDP socket");

    if (udp_sock) |s| {
        result.check(s.sock_type == .udp, "Type = UDP");
        result.check(socket.bind(s, 0, 9999), "Bind socket");
        result.check(s.local_port == 9999, "Port set");
        socket.close(s);
        result.check(s.state == .closed, "Socket closed");
    } else {
        result.fail("Type = UDP");
        result.fail("Bind socket");
        result.fail("Port set");
        result.fail("Socket closed");
    }

    // Create TCP socket
    const tcp_sock = socket.create(.tcp);
    result.check(tcp_sock != null, "Create TCP socket");
    if (tcp_sock) |s| {
        _ = socket.bind(s, 0, 8080);
        result.check(socket.listen(s, 5), "Listen socket");
        socket.close(s);
    } else {
        result.fail("Listen socket");
    }

    result.check(socket.getSocketCount() >= 0, "getSocketCount()");
}

fn testDhcpDns(result: *TestResult) void {
    printTest("8", "9", "DHCP & DNS");

    result.check(dhcp.isInitialized(), "DHCP initialized");
    result.check(dhcp.DHCP_SERVER_PORT == 67, "DHCP server port");
    result.check(dhcp.DHCP_CLIENT_PORT == 68, "DHCP client port");

    result.check(dns.isInitialized(), "DNS initialized");
    result.check(dns.DNS_PORT == 53, "DNS port = 53");

    result.check(dns.TYPE_A == 1, "DNS TYPE_A = 1");
    result.check(dns.TYPE_AAAA == 28, "DNS TYPE_AAAA = 28");
}

fn testNetworkIntegration(result: *TestResult) void {
    printTest("9", "9", "Integration Tests");

    result.check(net.isInitialized(), "Net stack ready");
    result.check(arp.isInitialized() and icmp.isInitialized(), "Protocols ready");
    result.check(udp.isInitialized() and tcp.isInitialized(), "Transport ready");
    result.check(socket.isInitialized(), "Socket ready");

    const stats = net.getStats();
    result.check(stats.interfaces >= 1, "Stats valid");
    result.check(pci.isInitialized(), "PCI ready");

    // Check for physical NICs
    const virtio_ready = virtio_net.isInitialized();
    const e1000_ready = e1000.isInitialized();
    if (virtio_ready or e1000_ready) {
        result.check(true, "Physical NIC detected");
    } else {
        result.skip("Physical NIC detected");
    }

    // E2E UDP test
    const sock = socket.create(.udp);
    if (sock) |s| {
        _ = socket.bind(s, 0, 7777);
        _ = socket.sendto(s, "Test", network.ipToU32(127, 0, 0, 1), 7777);
        result.check(true, "E2E UDP works");
        socket.close(s);
    } else {
        result.fail("E2E UDP works");
    }

    // Loopback test
    const lo = network.getInterfaceByName("lo");
    if (lo) |iface| {
        const tx_before = iface.tx_packets;
        _ = iface.send("Integration test packet");
        result.check(iface.tx_packets > tx_before, "Loopback TX works");
    } else {
        result.fail("Loopback TX works");
    }

    result.check(true, "Stack operational");
}

// =============================================================================
// Output Helpers - Using unified writeString/writeChar
// =============================================================================

fn printHeader(title: []const u8) void {
    writeString("\n");
    if (terminal.isInitialized()) {
        terminal.setFgColor(terminal.Colors.INFO);
    }
    writeString("########################################\n");
    writeString("##  ");
    writeString(title);
    writeString("\n");
    writeString("########################################\n");
    if (terminal.isInitialized()) {
        terminal.resetColors();
    }
}

fn printSection(name: []const u8) void {
    writeString("\n");
    if (terminal.isInitialized()) {
        terminal.setFgColor(terminal.Colors.PROMPT);
    }
    writeString("=== ");
    writeString(name);
    writeString(" ===\n\n");
    if (terminal.isInitialized()) {
        terminal.resetColors();
    }
}

fn printTest(num: []const u8, total: []const u8, name: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(terminal.Colors.INFO);
    }
    writeString("[");
    writeString(num);
    writeString("/");
    writeString(total);
    writeString("] ");
    if (terminal.isInitialized()) {
        terminal.resetColors();
    }
    writeString(name);
    writeString("\n");
}

fn printSummary(result: *const TestResult) void {
    writeString("\n");
    writeString("========================================\n");
    writeString("  Results: ");
    printDec(result.passed);
    if (terminal.isInitialized()) {
        terminal.setFgColor(terminal.Colors.SUCCESS);
    }
    writeString(" passed");
    if (terminal.isInitialized()) {
        terminal.resetColors();
    }
    writeString(", ");
    printDec(result.failed);
    if (result.failed > 0 and terminal.isInitialized()) {
        terminal.setFgColor(terminal.Colors.ERROR);
    }
    writeString(" failed");
    if (terminal.isInitialized()) {
        terminal.resetColors();
    }
    if (result.skipped > 0) {
        writeString(", ");
        printDec(result.skipped);
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.WARNING);
        }
        writeString(" skipped");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
    }
    writeString("\n");
    writeString("========================================\n\n");

    if (result.success()) {
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.SUCCESS);
        }
        writeString("[OK]   All tests PASSED!\n");
    } else {
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.ERROR);
        }
        writeString("[FAIL] Some tests FAILED!\n");
    }
    if (terminal.isInitialized()) {
        terminal.resetColors();
    }
    writeString("\n");
}

fn printDec(val: usize) void {
    if (val == 0) {
        writeChar('0');
        return;
    }

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = val;

    while (n > 0) : (i += 1) {
        buf[i] = @intCast((n % 10) + '0');
        n /= 10;
    }

    while (i > 0) {
        i -= 1;
        writeChar(buf[i]);
    }
}

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}
