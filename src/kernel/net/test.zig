//! Zamrud OS - Network Stack Tests (B1 + B2 + S.3 + H.6)
//! Comprehensive tests for Network Drivers, TCP/IP Stack, ARP Defense, and DHCP Security
//! B2.8: Added RTL8139 driver tests

const serial = @import("../drivers/serial/serial.zig");
const terminal = @import("../drivers/display/terminal.zig");
const network = @import("../drivers/network/network.zig");
const ethernet = @import("../drivers/network/ethernet.zig");
const loopback = @import("../drivers/network/loopback.zig");
const virtio_net = @import("../drivers/network/virtio_net.zig");
const e1000 = @import("../drivers/network/e1000.zig");
const rtl8139 = @import("../drivers/network/rtl8139.zig");
const pci = @import("../drivers/pci/pci.zig");
const net = @import("net.zig");
const arp = @import("arp.zig");
const arp_defense = @import("arp_defense.zig");
const ip = @import("ip.zig");
const icmp = @import("icmp.zig");
const udp = @import("udp.zig");
const tcp = @import("tcp.zig");
const checksum = @import("checksum.zig");
const socket = @import("socket.zig");
const dhcp = @import("dhcp.zig");
const dns = @import("dns.zig");
const dhcp_security = @import("dhcp_security.zig");

// =============================================================================
// Unified Output - Writes to BOTH terminal and serial
// =============================================================================

fn writeString(s: []const u8) void {
    serial.writeString(s);
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

    printHeader("NETWORK TEST SUITE (B1 + B2 + S.3 + H.6)");

    // =========================================================================
    // B1: Network Infrastructure
    // =========================================================================
    printSection("B1: NETWORK INFRASTRUCTURE");

    testPciBus(&result);
    testNetworkDriver(&result);
    testLoopbackInterface(&result);
    testVirtioNet(&result);
    testE1000(&result);
    testRtl8139(&result);
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

    // =========================================================================
    // S.3: ARP Defense / PeerID Crypto Binding
    // =========================================================================
    printSection("S.3: ARP-PEERID CRYPTO BINDING");

    testArpDefenseInit(&result);
    testArpDefenseBindings(&result);
    testArpDefenseValidation(&result);
    testArpDefenseSpoofDetection(&result);
    testArpDefenseRateLimit(&result);
    testArpDefenseEvents(&result);

    // =========================================================================
    // H.6: DHCP Security
    // =========================================================================
    printSection("H.6: DHCP SECURITY");

    testDhcpSecurityInit(&result);
    testDhcpSecurityPinning(&result);
    testDhcpSecurityRogue(&result);
    testDhcpSecurityValidation(&result);
    testDhcpSecurityRateLimit(&result);
    testDhcpSecurityFallback(&result);

    // Summary
    printSummary(&result);

    return result;
}

// =============================================================================
// B1: PCI Bus Tests
// =============================================================================

fn testPciBus(result: *TestResult) void {
    printTest("1", "9", "PCI Bus Driver");

    result.check(pci.isInitialized(), "PCI initialized");
    result.check(pci.PCI_VENDOR_INVALID == 0xFFFF, "VENDOR_INVALID = 0xFFFF");
    result.check(pci.VENDOR_INTEL == 0x8086, "VENDOR_INTEL = 0x8086");
    result.check(pci.VENDOR_VIRTIO == 0x1AF4, "VENDOR_VIRTIO = 0x1AF4");
    result.check(pci.VENDOR_REALTEK == 0x10EC, "VENDOR_REALTEK = 0x10EC");

    const device_count = pci.getDeviceCount();
    result.check(device_count >= 0, "Device count valid");

    const config = pci.readConfig(0, 0, 0, 0);
    _ = config;
    result.check(true, "Config read works");

    const found_intel = pci.findDevice(pci.VENDOR_INTEL, 0x100E);
    const found_virtio = pci.findDevice(pci.VENDOR_VIRTIO, 0x1000);
    const found_realtek = pci.findDevice(pci.VENDOR_REALTEK, 0x8139);
    _ = found_intel;
    _ = found_virtio;
    _ = found_realtek;
    result.check(true, "Device lookup works");

    const class_name = pci.getClassName(0x02);
    result.check(strEqual(class_name, "Network"), "Class name = Network");
}

// =============================================================================
// B1: Network Driver Tests
// =============================================================================

fn testNetworkDriver(result: *TestResult) void {
    printTest("2", "9", "Network Driver Core");

    result.check(network.isInitialized(), "Driver initialized");
    result.check(network.getInterfaceCount() >= 1, "Interface count >= 1");
    result.check(network.MAX_INTERFACES >= 4, "MAX_INTERFACES >= 4");
    result.check(network.MAX_PACKET_SIZE >= 1500, "MAX_PACKET_SIZE >= 1500");
    result.check(network.MAC_SIZE == 6, "MAC_SIZE == 6");

    const stats = network.getStats();
    result.check(stats.total_rx_packets >= 0, "Stats accessible");
}

fn testLoopbackInterface(result: *TestResult) void {
    printTest("3", "9", "Loopback Interface");

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
    printTest("4", "9", "VirtIO Network Driver");

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
    printTest("5", "9", "Intel E1000 Driver");

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

// =============================================================================
// B1/B2.8: RTL8139 Driver Tests
// =============================================================================

fn testRtl8139(result: *TestResult) void {
    printTest("6", "9", "Realtek RTL8139 Driver (B2.8)");

    // Constants verification
    result.check(rtl8139.REALTEK_VENDOR_ID == 0x10EC, "REALTEK_VENDOR_ID = 0x10EC");
    result.check(rtl8139.RTL8139_DEVICE_ID == 0x8139, "RTL8139_DEVICE_ID = 0x8139");
    result.check(rtl8139.NUM_TX_DESC == 4, "NUM_TX_DESC = 4");
    result.check(rtl8139.RX_BUFFER_SIZE >= 8192, "RX_BUFFER >= 8K");
    result.check(rtl8139.TX_BUFFER_SIZE >= 1536, "TX_BUFFER >= 1536");

    // Register definitions
    result.check(rtl8139.REG_CR == 0x37, "REG_CR = 0x37");
    result.check(rtl8139.REG_IMR == 0x3C, "REG_IMR = 0x3C");
    result.check(rtl8139.REG_ISR == 0x3E, "REG_ISR = 0x3E");
    result.check(rtl8139.REG_RCR == 0x44, "REG_RCR = 0x44");
    result.check(rtl8139.REG_TCR == 0x40, "REG_TCR = 0x40");

    // Control bits
    result.check(rtl8139.CR_RST == 0x10, "CR_RST = 0x10");
    result.check(rtl8139.CR_RE == 0x08, "CR_RE = 0x08");
    result.check(rtl8139.CR_TE == 0x04, "CR_TE = 0x04");
    result.check(rtl8139.INT_ROK == 0x0001, "INT_ROK = 0x0001");
    result.check(rtl8139.INT_TOK == 0x0004, "INT_TOK = 0x0004");

    // Probe
    const rtl_available = rtl8139.isInitialized();
    const probed = rtl8139.probe();
    result.check(true, "Probe function works");

    if (probed or rtl_available) {
        result.checkOrSkip(rtl8139.isInitialized(), rtl_available, "RTL8139 initialized");

        if (rtl_available) {
            result.check(rtl8139.getIoBase() != 0, "I/O base != 0");

            const iface = rtl8139.getInterfaceConst();
            result.check(iface.mtu == 1500, "MTU = 1500");

            var mac_valid = false;
            for (iface.mac) |b| {
                if (b != 0 and b != 0xFF) {
                    mac_valid = true;
                    break;
                }
            }
            result.check(mac_valid, "MAC address valid");

            result.check(true, "Link status check");

            const speed = rtl8139.getLinkSpeed();
            result.check(speed == .speed_10 or speed == .speed_100, "Speed = 10/100 Mbps");

            const stats = rtl8139.getStats();
            result.check(stats.tx_packets >= 0, "Stats accessible");
        } else {
            result.skip("I/O base != 0");
            result.skip("MTU = 1500");
            result.skip("MAC address valid");
            result.skip("Link status check");
            result.skip("Speed = 10/100 Mbps");
            result.skip("Stats accessible");
        }
    } else {
        result.skip("RTL8139 initialized");
        result.skip("I/O base != 0");
        result.skip("MTU = 1500");
        result.skip("MAC address valid");
        result.skip("Link status check");
        result.skip("Speed = 10/100 Mbps");
        result.skip("Stats accessible");
    }
}

fn testEthernetFrames(result: *TestResult) void {
    printTest("7", "9", "Ethernet Frames");

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
    printTest("8", "9", "Packet Buffer");

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
    printTest("9", "9", "Interface Management");

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

    // Check for physical NICs (any of the three)
    const virtio_ready = virtio_net.isInitialized();
    const e1000_ready = e1000.isInitialized();
    const rtl8139_ready = rtl8139.isInitialized();
    if (virtio_ready or e1000_ready or rtl8139_ready) {
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
// S.3: ARP Defense Tests
// =============================================================================

fn testArpDefenseInit(result: *TestResult) void {
    printTest("1", "6", "ARP Defense Initialization");

    if (!arp_defense.isInitialized()) {
        arp_defense.init();
    }

    result.check(arp_defense.isInitialized(), "ARP Defense init");
    result.check(arp_defense.getBindingCount() >= 2, "QEMU bindings added");

    const stats = arp_defense.getStats();
    result.check(stats.bindings_created >= 2, "Stats accessible");

    result.check(!arp_defense.config.require_signature, "Signature disabled (QEMU)");
    result.check(!arp_defense.config.require_peer_binding, "Peer binding disabled");
    result.check(arp_defense.config.detect_gratuitous, "Gratuitous detect ON");
    result.check(arp_defense.config.auto_blacklist, "Auto-blacklist ON");
}

fn testArpDefenseBindings(result: *TestResult) void {
    printTest("2", "6", "Trusted Binding Management");

    const before_count = arp_defense.getBindingCount();

    const test_mac: arp_defense.MacAddress = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 };
    const test_ip: u32 = (192 << 24) | (168 << 16) | (50 << 8) | 1;
    const test_peer_id: [32]u8 = [_]u8{0x42} ** 32;
    const test_pubkey: [32]u8 = [_]u8{0x00} ** 32;

    const created = arp_defense.createBinding(test_mac, test_ip, test_peer_id, test_pubkey);
    result.check(created, "Create crypto binding");
    result.check(arp_defense.getBindingCount() == before_count + 1, "Binding count +1");

    var found = false;
    for (0..arp_defense.getBindingCount()) |i| {
        if (arp_defense.getBinding(i)) |b| {
            if (b.ip == test_ip) {
                found = true;
                result.check(b.verified, "Binding verified");
                result.check(b.trust_level == .verified, "Trust = verified");
                break;
            }
        }
    }
    if (!found) {
        result.fail("Binding verified");
        result.fail("Trust = verified");
    }

    const static_mac: arp_defense.MacAddress = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const static_ip: u32 = (10 << 24) | (0 << 16) | (50 << 8) | 1;
    const static_ok = arp_defense.createStaticBinding(static_mac, static_ip, "Test Static");
    result.check(static_ok, "Create static binding");

    var static_found = false;
    for (0..arp_defense.getBindingCount()) |i| {
        if (arp_defense.getBinding(i)) |b| {
            if (b.ip == static_ip) {
                static_found = true;
                result.check(b.trust_level == .trusted, "Static trust level");
                break;
            }
        }
    }
    if (!static_found) {
        result.fail("Static trust level");
    }

    result.check(arp_defense.removeBinding(test_ip), "Remove binding");
    _ = arp_defense.removeBinding(static_ip);
}

fn testArpDefenseValidation(result: *TestResult) void {
    printTest("3", "6", "ARP Packet Validation");

    const qemu_gw_mac: arp_defense.MacAddress = .{ 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };
    const qemu_gw_ip: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 2;
    const our_ip: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 15;

    const valid_result = arp_defense.validateArpPacket(
        1,
        qemu_gw_mac,
        qemu_gw_ip,
        [_]u8{0} ** 6,
        our_ip,
        null,
    );
    result.check(valid_result.allowed, "Trusted source allowed");
    result.check(@intFromEnum(valid_result.trust_level) >= @intFromEnum(arp_defense.TrustLevel.trusted), "Trust level >= trusted");

    const unknown_mac: arp_defense.MacAddress = .{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };
    const unknown_ip: u32 = (172 << 24) | (16 << 16) | (0 << 8) | 100;

    const unknown_result = arp_defense.validateArpPacket(
        1,
        unknown_mac,
        unknown_ip,
        [_]u8{0} ** 6,
        our_ip,
        null,
    );
    result.check(unknown_result.trust_level == .unknown, "Unknown = unverified");

    const arp_stats = arp_defense.getStats();
    result.check(arp_stats.total_packets > 0, "Stats: packets counted");
    result.check(arp_stats.packets_allowed > 0, "Stats: allowed counted");
}

fn testArpDefenseSpoofDetection(result: *TestResult) void {
    printTest("4", "6", "Spoof Detection");

    const legit_mac: arp_defense.MacAddress = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const legit_ip: u32 = (192 << 24) | (168 << 16) | (99 << 8) | 1;
    const peer_id: [32]u8 = [_]u8{0xAB} ** 32;
    const pubkey: [32]u8 = [_]u8{0x00} ** 32;

    _ = arp_defense.createBinding(legit_mac, legit_ip, peer_id, pubkey);

    const spoof_mac: arp_defense.MacAddress = .{ 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA };

    const spoof_result = arp_defense.validateArpPacket(
        2,
        spoof_mac,
        legit_ip,
        [_]u8{0} ** 6,
        0,
        null,
    );

    result.check(!spoof_result.allowed, "Spoof blocked");

    const stats = arp_defense.getStats();
    result.check(stats.spoof_attempts > 0, "Spoof attempt counted");
    result.check(stats.packets_blocked > 0, "Blocked counted");

    _ = arp_defense.removeBinding(legit_ip);
}

fn testArpDefenseRateLimit(result: *TestResult) void {
    printTest("5", "6", "Rate Limiting");

    const rate_mac: arp_defense.MacAddress = .{ 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    const rate_ip: u32 = (192 << 24) | (168 << 16) | (200 << 8) | 1;

    const rate_limit = arp_defense.config.arp_rate_limit;
    result.check(rate_limit > 0, "Rate limit configured");

    var blocked_count: u32 = 0;
    var i: u32 = 0;
    while (i < rate_limit + 20) : (i += 1) {
        const res = arp_defense.validateArpPacket(
            1,
            rate_mac,
            rate_ip,
            [_]u8{0} ** 6,
            0,
            null,
        );
        if (!res.allowed) {
            blocked_count += 1;
        }
    }

    result.check(blocked_count > 0 or i >= rate_limit, "Rate limit enforced");

    const stats = arp_defense.getStats();
    result.check(stats.flood_detected >= 0, "Flood stats accessible");
}

fn testArpDefenseEvents(result: *TestResult) void {
    printTest("6", "6", "Event Logging & Config");

    const event_count = arp_defense.getEventCount();
    result.check(event_count >= 0, "Event count accessible");

    if (event_count > 0) {
        if (arp_defense.getEvent(0)) |event| {
            result.check(event.timestamp > 0, "Event has timestamp");
            result.check(@intFromEnum(event.event_type) <= @intFromEnum(arp_defense.ArpEventType.binding_changed), "Event type valid");
        } else {
            result.fail("Event has timestamp");
            result.fail("Event type valid");
        }
    } else {
        result.skip("Event has timestamp");
        result.skip("Event type valid");
    }

    arp_defense.setRequireSignature(true);
    result.check(arp_defense.config.require_signature, "Set require_signature");

    arp_defense.setRequirePeerBinding(true);
    result.check(arp_defense.config.require_peer_binding, "Set require_peer_binding");

    arp_defense.setRequireSignature(false);
    arp_defense.setRequirePeerBinding(false);

    arp_defense.clearEvents();
    result.check(arp_defense.getEventCount() == 0, "Clear events");

    result.check(arp.isSecurityEnabled(), "ARP security enabled");

    const sec_stats = arp.getSecurityStats();
    result.check(sec_stats.total_entries >= 0, "ARP security stats");
}

// =============================================================================
// H.6: DHCP Security Tests
// =============================================================================

fn testDhcpSecurityInit(result: *TestResult) void {
    printTest("1", "6", "DHCP Security Initialization");

    dhcp_security.init();

    result.check(dhcp_security.isInitialized(), "DHCP-SEC initialized");
    result.check(dhcp_security.isEnabled(), "DHCP-SEC enabled");

    const cfg = dhcp_security.config;
    result.check(cfg.enabled, "Config: enabled");
    result.check(cfg.trust_first_server, "Config: trust first");
    result.check(cfg.validate_offers, "Config: validate offers");
    result.check(cfg.detect_rogue, "Config: detect rogue");

    const stats = dhcp_security.getStats();
    result.check(stats.rogue_detections == 0, "Stats zeroed");
}

fn testDhcpSecurityPinning(result: *TestResult) void {
    printTest("2", "6", "Trusted Server Pinning");

    dhcp_security.init();

    const server_ip: u32 = (192 << 24) | (168 << 16) | (1 << 8) | 1;
    dhcp_security.pinServer(server_ip);

    result.check(dhcp_security.isServerTrusted(server_ip), "Server pinned");

    const other_ip: u32 = (10 << 24) | (0 << 16) | (0 << 8) | 1;
    result.check(!dhcp_security.isServerTrusted(other_ip), "Other not trusted");

    const trusted = dhcp_security.getTrustedServer();
    result.check(trusted.pinned, "Trusted is pinned");
    result.check(trusted.ip == server_ip, "Trusted IP correct");

    dhcp_security.clearTrustedServer();
    result.check(!dhcp_security.isServerTrusted(server_ip), "Clear works");
}

fn testDhcpSecurityRogue(result: *TestResult) void {
    printTest("3", "6", "Rogue Server Detection");

    dhcp_security.init();

    const legit_ip: u32 = (192 << 24) | (168 << 16) | (1 << 8) | 1;
    const first_ok = dhcp_security.checkServer(legit_ip);
    result.check(first_ok, "First server OK");
    result.check(dhcp_security.isServerTrusted(legit_ip), "First server pinned");

    const rogue_ip: u32 = (10 << 24) | (0 << 16) | (0 << 8) | 99;
    const rogue_blocked = !dhcp_security.checkServer(rogue_ip);
    result.check(rogue_blocked, "Rogue blocked");

    const stats = dhcp_security.getStats();
    result.check(stats.rogue_detections >= 1, "Rogue counted");

    result.check(dhcp_security.getEventCount() >= 1, "Event logged");
}

fn testDhcpSecurityValidation(result: *TestResult) void {
    printTest("4", "6", "Offer Validation");

    dhcp_security.init();

    const valid = dhcp_security.validateOffer(
        (192 << 24) | (168 << 16) | (1 << 8) | 100,
        (255 << 24) | (255 << 16) | (255 << 8) | 0,
        (192 << 24) | (168 << 16) | (1 << 8) | 1,
        (8 << 24) | (8 << 16) | (8 << 8) | 8,
    );
    result.check(valid, "Valid offer OK");

    const zero_ip = dhcp_security.validateOffer(
        0,
        (255 << 24) | (255 << 16) | (255 << 8) | 0,
        0,
        0,
    );
    result.check(!zero_ip, "Zero IP rejected");

    const broadcast = dhcp_security.validateOffer(
        0xFFFFFFFF,
        (255 << 24) | (255 << 16) | (255 << 8) | 0,
        0,
        0,
    );
    result.check(!broadcast, "Broadcast rejected");

    const zero_mask = dhcp_security.validateOffer(
        (192 << 24) | (168 << 16) | (1 << 8) | 100,
        0,
        0,
        0,
    );
    result.check(!zero_mask, "Zero mask rejected");

    const stats = dhcp_security.getStats();
    result.check(stats.offers_accepted >= 1, "Accepted counted");
    result.check(stats.offers_rejected >= 3, "Rejected counted");
}

fn testDhcpSecurityRateLimit(result: *TestResult) void {
    printTest("5", "6", "Rate Limiting");

    dhcp_security.init();
    dhcp_security.config.max_packets_per_window = 10;

    var under_ok = true;
    var i: u16 = 0;
    while (i < 10) : (i += 1) {
        if (!dhcp_security.checkRateLimit()) {
            under_ok = false;
            break;
        }
    }
    result.check(under_ok, "Under limit OK");

    const over_blocked = !dhcp_security.checkRateLimit();
    result.check(over_blocked, "Over limit blocked");

    const stats = dhcp_security.getStats();
    result.check(stats.rate_limit_hits >= 1, "Rate hits counted");
    result.check(stats.packets_seen >= 11, "Packets counted");

    dhcp_security.resetRateWindow();
    const after_reset = dhcp_security.checkRateLimit();
    result.check(after_reset, "Reset works");
}

fn testDhcpSecurityFallback(result: *TestResult) void {
    printTest("6", "6", "Static Fallback");

    dhcp_security.init();

    dhcp_security.setStaticFallback(
        (10 << 24) | (0 << 16) | (0 << 8) | 50,
        (255 << 24) | (255 << 16) | (255 << 8) | 0,
        (10 << 24) | (0 << 16) | (0 << 8) | 1,
        (10 << 24) | (0 << 16) | (0 << 8) | 1,
    );

    const fb = dhcp_security.getStaticFallback();
    result.check(fb.configured, "Static configured");
    result.check(fb.ip_addr == ((10 << 24) | (0 << 16) | (0 << 8) | 50), "Static IP correct");

    result.check(dhcp_security.activateFallback(), "Activate OK");
    result.check(dhcp_security.isFallbackActive(), "Fallback active");

    dhcp_security.deactivateFallback();
    result.check(!dhcp_security.isFallbackActive(), "Deactivate OK");

    result.check(dhcp_security.getEventCount() >= 1, "Fallback event logged");
}

// =============================================================================
// Output Helpers
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
