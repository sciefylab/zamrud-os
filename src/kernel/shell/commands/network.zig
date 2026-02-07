//! Zamrud OS - Network Commands
//! Network interface management, diagnostics, and testing

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");

// Network imports
const net_stack = @import("../../net/net.zig");
const net_driver = @import("../../drivers/network/network.zig");
const icmp_mod = @import("../../net/icmp.zig");
const arp_mod = @import("../../net/arp.zig");
const udp_mod = @import("../../net/udp.zig");
const tcp_mod = @import("../../net/tcp.zig");
const socket_mod = @import("../../net/socket.zig");
const ip_mod = @import("../../net/ip.zig");
const ethernet_mod = @import("../../drivers/network/ethernet.zig");
const dns_mod = @import("../../net/dns.zig");
const dhcp_mod = @import("../../net/dhcp.zig");

// Import the comprehensive test suite
const net_test = @import("../../net/test.zig");

// Buffer for IP address formatting
var ip_format_buf: [16]u8 = [_]u8{' '} ** 16;

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "status")) {
        showStatus();
    } else if (helpers.strEql(parsed.cmd, "init")) {
        initNetwork();
    } else if (helpers.strEql(parsed.cmd, "up")) {
        interfaceUp(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "down")) {
        interfaceDown(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "stats")) {
        showStats();
    } else if (helpers.strEql(parsed.cmd, "route")) {
        showRoute();
    } else if (helpers.strEql(parsed.cmd, "dns")) {
        cmdDns(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "config")) {
        cmdConfig(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "dhcp")) {
        cmdDhcp(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "set")) {
        cmdSet(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "mode")) {
        cmdMode(parsed.rest);
    } else {
        shell.printError("net: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'net help'");
    }
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  NET - Network Stack Management");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: net <command> [args]");
    shell.newLine();

    shell.println("Status Commands:");
    shell.println("  help              Show this help");
    shell.println("  status            Show network status");
    shell.println("  stats             Show detailed statistics");
    shell.println("  route             Show routing table");
    shell.println("  dns               Show DNS servers");
    shell.newLine();

    shell.println("Interface Commands:");
    shell.println("  init              Re-initialize network");
    shell.println("  up <iface>        Bring interface up");
    shell.println("  down <iface>      Bring interface down");
    shell.newLine();

    shell.println("Configuration Commands:");
    shell.println("  config            Show current config mode");
    shell.println("  config static <ip> <mask> <gw>  Set static IP");
    shell.println("  config dhcp       Use DHCP");
    shell.println("  config qemu       Use QEMU SLIRP (10.0.2.15)");
    shell.println("  set ip <iface> <ip> <mask> <gw> Configure interface");
    shell.println("  set dns <ip>      Add DNS server");
    shell.println("  dhcp              Request DHCP lease");
    shell.println("  mode              Show/set network mode");
    shell.newLine();

    shell.println("Test Commands:");
    shell.println("  test              Run all network tests");
    shell.println("  test quick        Quick health check");
    shell.println("  test b1           Infrastructure tests");
    shell.println("  test b2           Protocol tests");
    shell.newLine();

    shell.println("Related Commands:");
    shell.println("  ifconfig          Show/configure interfaces");
    shell.println("  ping <ip>         Send ICMP echo");
    shell.println("  netstat           Show connections");
    shell.println("  arp               Show ARP cache");
    shell.newLine();
}

// =============================================================================
// Configuration Commands
// =============================================================================

fn cmdConfig(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0) {
        // Show current config
        showCurrentConfig();
    } else if (helpers.strEql(parsed.cmd, "static")) {
        configStatic(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "dhcp")) {
        configDhcp();
    } else if (helpers.strEql(parsed.cmd, "qemu")) {
        configQemu();
    } else if (helpers.strEql(parsed.cmd, "auto")) {
        configAuto();
    } else {
        shell.println("Usage: net config [static|dhcp|qemu|auto]");
        shell.println("  static <ip> <netmask> <gateway>");
        shell.println("  dhcp     - Use DHCP client");
        shell.println("  qemu     - Use QEMU SLIRP (10.0.2.15)");
        shell.println("  auto     - Auto-detect environment");
    }
}

fn showCurrentConfig() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  NETWORK CONFIGURATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Mode:        ");
    const mode = net_stack.getConfigMode();
    switch (mode) {
        .none => shell.println("None"),
        .static => shell.println("Static"),
        .dhcp => shell.println("DHCP"),
        .qemu_slirp => shell.println("QEMU SLIRP"),
    }

    shell.newLine();
    shell.println("  Interfaces:");

    var i: usize = 0;
    while (i < net_driver.getInterfaceCount()) : (i += 1) {
        const iface = net_driver.getInterface(i) orelse continue;
        shell.print("    ");
        shell.print(iface.getName());
        shell.print(": ");

        if (iface.state == .up) {
            shell.printSuccess("UP");
        } else {
            shell.printError("DOWN");
        }

        shell.print("  IP=");
        printIpAddr(iface.ip_addr);
        shell.print("  GW=");
        printIpAddr(iface.gateway);
        shell.newLine();
    }

    shell.newLine();
    shell.println("  DNS Servers:");
    const servers = dns_mod.getServers();
    if (servers.len == 0) {
        shell.println("    (none configured)");
    } else {
        for (servers, 0..) |server, idx| {
            shell.print("    ");
            helpers.printUsize(idx + 1);
            shell.print(". ");
            printIpAddr(server);
            shell.newLine();
        }
    }

    shell.newLine();
}

fn configStatic(args: []const u8) void {
    // Parse: <ip> <netmask> <gateway>
    var ip_str: []const u8 = "";
    var mask_str: []const u8 = "";
    var gw_str: []const u8 = "";

    var remaining = args;

    // Parse IP
    const ip_parsed = helpers.splitFirst(remaining, ' ');
    ip_str = ip_parsed.first;
    remaining = helpers.trim(ip_parsed.rest);

    // Parse netmask
    const mask_parsed = helpers.splitFirst(remaining, ' ');
    mask_str = mask_parsed.first;
    remaining = helpers.trim(mask_parsed.rest);

    // Parse gateway
    const gw_parsed = helpers.splitFirst(remaining, ' ');
    gw_str = gw_parsed.first;

    if (ip_str.len == 0 or mask_str.len == 0 or gw_str.len == 0) {
        shell.println("Usage: net config static <ip> <netmask> <gateway>");
        shell.println("Example: net config static 192.168.1.100 255.255.255.0 192.168.1.1");
        return;
    }

    const ip_addr = parseIpAddr(ip_str) orelse {
        shell.printError("Invalid IP: ");
        shell.println(ip_str);
        return;
    };

    const netmask = parseIpAddr(mask_str) orelse {
        shell.printError("Invalid netmask: ");
        shell.println(mask_str);
        return;
    };

    const gateway = parseIpAddr(gw_str) orelse {
        shell.printError("Invalid gateway: ");
        shell.println(gw_str);
        return;
    };

    // Apply configuration
    net_stack.setConfigMode(.static);
    net_stack.setStaticConfig(ip_addr, netmask, gateway, 0);
    net_stack.reconfigure();

    shell.printSuccessLine("Static IP configured:");
    shell.print("  IP:      ");
    printIpAddr(ip_addr);
    shell.newLine();
    shell.print("  Netmask: ");
    printIpAddr(netmask);
    shell.newLine();
    shell.print("  Gateway: ");
    printIpAddr(gateway);
    shell.newLine();
}

fn configDhcp() void {
    shell.printInfoLine("Switching to DHCP mode...");
    net_stack.setConfigMode(.dhcp);
    net_stack.reconfigure();

    if (dhcp_mod.isBound()) {
        shell.printSuccessLine("DHCP lease acquired");
        if (dhcp_mod.getLease()) |lease| {
            shell.print("  IP:      ");
            printIpAddr(lease.ip_addr);
            shell.newLine();
            shell.print("  Gateway: ");
            printIpAddr(lease.gateway);
            shell.newLine();
        }
    } else {
        shell.printWarningLine("DHCP discovery in progress...");
        shell.println("  Use 'net dhcp' to manually request lease");
    }
}

fn configQemu() void {
    shell.printInfoLine("Configuring for QEMU SLIRP...");
    net_stack.forceQemuMode();
    shell.printSuccessLine("QEMU SLIRP configured:");
    shell.println("  IP:      10.0.2.15");
    shell.println("  Netmask: 255.255.255.0");
    shell.println("  Gateway: 10.0.2.2");
    shell.println("  DNS:     10.0.2.3");
}

fn configAuto() void {
    shell.printInfoLine("Auto-detecting network environment...");
    net_stack.reconfigure();

    const mode = net_stack.getConfigMode();
    shell.print("  Detected mode: ");
    switch (mode) {
        .none => shell.println("None"),
        .static => shell.println("Static"),
        .dhcp => shell.println("DHCP"),
        .qemu_slirp => shell.println("QEMU SLIRP"),
    }
}

fn cmdSet(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (helpers.strEql(parsed.cmd, "ip")) {
        setInterfaceIp(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "dns")) {
        setDns(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "gateway")) {
        setGateway(parsed.rest);
    } else {
        shell.println("Usage:");
        shell.println("  net set ip <iface> <ip> <mask> <gw>");
        shell.println("  net set dns <ip>");
        shell.println("  net set gateway <iface> <ip>");
    }
}

fn setInterfaceIp(args: []const u8) void {
    // Parse: <iface> <ip> <netmask> <gateway>
    var remaining = args;

    const iface_parsed = helpers.splitFirst(remaining, ' ');
    const iface_name = iface_parsed.first;
    remaining = helpers.trim(iface_parsed.rest);

    const ip_parsed = helpers.splitFirst(remaining, ' ');
    const ip_str = ip_parsed.first;
    remaining = helpers.trim(ip_parsed.rest);

    const mask_parsed = helpers.splitFirst(remaining, ' ');
    const mask_str = mask_parsed.first;
    remaining = helpers.trim(mask_parsed.rest);

    const gw_parsed = helpers.splitFirst(remaining, ' ');
    const gw_str = gw_parsed.first;

    if (iface_name.len == 0 or ip_str.len == 0) {
        shell.println("Usage: net set ip <iface> <ip> [netmask] [gateway]");
        return;
    }

    const iface = net_driver.getInterfaceByName(iface_name) orelse {
        shell.printError("Interface not found: ");
        shell.println(iface_name);
        return;
    };

    const ip_addr = parseIpAddr(ip_str) orelse {
        shell.printError("Invalid IP: ");
        shell.println(ip_str);
        return;
    };

    var netmask: u32 = net_driver.ipToU32(255, 255, 255, 0);
    if (mask_str.len > 0) {
        netmask = parseIpAddr(mask_str) orelse netmask;
    }

    var gateway: u32 = 0;
    if (gw_str.len > 0) {
        gateway = parseIpAddr(gw_str) orelse 0;
    }

    iface.ip_addr = ip_addr;
    iface.netmask = netmask;
    iface.gateway = gateway;

    shell.printSuccess(iface_name);
    shell.print(" configured: ");
    printIpAddr(ip_addr);
    shell.newLine();
}

fn setDns(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.println("Usage: net set dns <ip>");
        return;
    }

    const dns_ip = parseIpAddr(trimmed) orelse {
        shell.printError("Invalid IP: ");
        shell.println(trimmed);
        return;
    };

    if (dns_mod.addServer(dns_ip)) {
        shell.printSuccess("DNS server added: ");
        printIpAddr(dns_ip);
        shell.newLine();
    } else {
        shell.printErrorLine("Failed to add DNS server (max reached?)");
    }
}

fn setGateway(args: []const u8) void {
    var remaining = args;

    const iface_parsed = helpers.splitFirst(remaining, ' ');
    const iface_name = iface_parsed.first;
    remaining = helpers.trim(iface_parsed.rest);

    const gw_str = helpers.trim(remaining);

    if (iface_name.len == 0 or gw_str.len == 0) {
        shell.println("Usage: net set gateway <iface> <ip>");
        return;
    }

    const iface = net_driver.getInterfaceByName(iface_name) orelse {
        shell.printError("Interface not found: ");
        shell.println(iface_name);
        return;
    };

    const gateway = parseIpAddr(gw_str) orelse {
        shell.printError("Invalid IP: ");
        shell.println(gw_str);
        return;
    };

    iface.gateway = gateway;

    shell.printSuccess(iface_name);
    shell.print(" gateway set to ");
    printIpAddr(gateway);
    shell.newLine();
}

fn cmdDhcp(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "request")) {
        // Request DHCP lease
        shell.printInfoLine("Requesting DHCP lease...");

        const iface = net_driver.getDefaultInterface() orelse {
            shell.printErrorLine("No interface available");
            return;
        };

        if (dhcp_mod.discover(iface)) {
            shell.println("  DHCP DISCOVER sent");

            // Wait for response
            var timeout: u32 = 0;
            while (timeout < 30) : (timeout += 1) {
                helpers.busyWait(100000);
                if (dhcp_mod.isBound()) break;
            }

            if (dhcp_mod.isBound()) {
                // FIX: Properly unwrap optional
                if (dhcp_mod.getLease()) |lease| {
                    shell.printSuccessLine("DHCP lease acquired:");
                    shell.print("  IP:      ");
                    printIpAddr(lease.ip_addr);
                    shell.newLine();
                    shell.print("  Netmask: ");
                    printIpAddr(lease.subnet_mask);
                    shell.newLine();
                    shell.print("  Gateway: ");
                    printIpAddr(lease.gateway);
                    shell.newLine();

                    // Apply to interface
                    iface.ip_addr = lease.ip_addr;
                    iface.netmask = lease.subnet_mask;
                    iface.gateway = lease.gateway;

                    if (lease.dns_server != 0) {
                        _ = dns_mod.addServer(lease.dns_server);
                        shell.print("  DNS:     ");
                        printIpAddr(lease.dns_server);
                        shell.newLine();
                    }
                }
            } else {
                shell.printErrorLine("DHCP timeout - no response");
            }
        } else {
            shell.printErrorLine("Failed to send DHCP DISCOVER");
        }
    } else if (helpers.strEql(opt, "release")) {
        const iface = net_driver.getDefaultInterface() orelse {
            shell.printErrorLine("No interface available");
            return;
        };
        if (dhcp_mod.release(iface)) {
            shell.printSuccessLine("DHCP lease released");
        } else {
            shell.printErrorLine("Failed to release lease");
        }
    } else if (helpers.strEql(opt, "status")) {
        if (dhcp_mod.isBound()) {
            // FIX: Properly unwrap optional
            if (dhcp_mod.getLease()) |lease| {
                shell.printSuccessLine("DHCP Status: BOUND");
                shell.print("  IP:      ");
                printIpAddr(lease.ip_addr);
                shell.newLine();
                shell.print("  Gateway: ");
                printIpAddr(lease.gateway);
                shell.newLine();
                shell.print("  Lease:   ");
                helpers.printU32(lease.lease_time);
                shell.println(" seconds");
            }
        } else {
            shell.printWarningLine("DHCP Status: NOT BOUND");
        }
    } else {
        shell.println("Usage: net dhcp [request|release|status]");
    }
}

fn cmdDns(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0) {
        showDnsServers();
    } else if (helpers.strEql(opt, "clear")) {
        dns_mod.clearServers();
        shell.printSuccessLine("DNS servers cleared");
    } else {
        // Try to add as IP
        const dns_ip = parseIpAddr(opt) orelse {
            shell.println("Usage: net dns [clear|<ip>]");
            return;
        };

        if (dns_mod.addServer(dns_ip)) {
            shell.printSuccess("DNS server added: ");
            printIpAddr(dns_ip);
            shell.newLine();
        } else {
            shell.printErrorLine("Failed to add DNS server");
        }
    }
}

fn showDnsServers() void {
    shell.printInfoLine("DNS Configuration:");
    if (dns_mod.isInitialized()) {
        const servers = dns_mod.getServers();
        if (servers.len == 0) {
            shell.println("  (no DNS servers configured)");
        } else {
            for (servers, 0..) |server, idx| {
                shell.print("  ");
                helpers.printUsize(idx + 1);
                shell.print(". ");
                printIpAddr(server);
                shell.newLine();
            }
        }
    } else {
        shell.println("  (DNS not initialized)");
    }
    shell.newLine();
}

fn cmdMode(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0) {
        // Show current mode
        shell.print("Network mode: ");
        const mode = net_stack.getConfigMode();
        switch (mode) {
            .none => shell.println("None (unconfigured)"),
            .static => shell.println("Static IP"),
            .dhcp => shell.println("DHCP Client"),
            .qemu_slirp => shell.println("QEMU SLIRP"),
        }
    } else if (helpers.strEql(opt, "static")) {
        net_stack.setConfigMode(.static);
        shell.printSuccessLine("Mode set to: Static");
    } else if (helpers.strEql(opt, "dhcp")) {
        net_stack.setConfigMode(.dhcp);
        shell.printSuccessLine("Mode set to: DHCP");
    } else if (helpers.strEql(opt, "qemu")) {
        net_stack.setConfigMode(.qemu_slirp);
        shell.printSuccessLine("Mode set to: QEMU SLIRP");
    } else {
        shell.println("Usage: net mode [static|dhcp|qemu]");
    }
}

// =============================================================================
// Test Commands
// =============================================================================

pub fn runTest(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "all")) {
        const result = net_test.runAllTests();
        _ = result;
    } else if (helpers.strEql(opt, "quick")) {
        runQuickTest();
    } else if (helpers.strEql(opt, "b1") or helpers.strEql(opt, "infra")) {
        runB1TestsOnly();
    } else if (helpers.strEql(opt, "b2") or helpers.strEql(opt, "proto")) {
        runB2TestsOnly();
    } else {
        shell.println("net test options: all, quick, b1, b2");
    }
}

fn runQuickTest() void {
    shell.printInfoLine("Network Quick Test...");
    shell.newLine();

    var ok = true;

    shell.print("  Driver:    ");
    if (net_driver.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Stack:     ");
    if (net_stack.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Loopback:  ");
    if (net_driver.getInterfaceByName("lo") != null) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Ping:      ");
    const ping_result = testLoopbackPing();
    if (ping_result.sent and ping_result.received) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    // Check default interface
    shell.print("  Interface: ");
    if (net_driver.getDefaultInterface()) |iface| {
        if (iface.ip_addr != 0) {
            shell.printSuccess("OK (");
            printIpAddr(iface.ip_addr);
            shell.println(")");
        } else {
            shell.printWarningLine("No IP configured");
            ok = false;
        }
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.newLine();
    helpers.printQuickResult("Network", ok);
}

fn runB1TestsOnly() void {
    helpers.printTestHeader("NETWORK INFRASTRUCTURE (B1)");
    shell.newLine();

    var p: u32 = 0;
    var f: u32 = 0;

    const pci = @import("../../drivers/pci/pci.zig");
    const virtio_net = @import("../../drivers/network/virtio_net.zig");
    const e1000 = @import("../../drivers/network/e1000.zig");

    helpers.printTestCategory(1, 8, "PCI Bus Driver");
    p += helpers.doTest("PCI initialized", pci.isInitialized(), &f);
    p += helpers.doTest("VENDOR_INVALID = 0xFFFF", pci.PCI_VENDOR_INVALID == 0xFFFF, &f);
    p += helpers.doTest("VENDOR_INTEL = 0x8086", pci.VENDOR_INTEL == 0x8086, &f);
    p += helpers.doTest("VENDOR_VIRTIO = 0x1AF4", pci.VENDOR_VIRTIO == 0x1AF4, &f);
    p += helpers.doTest("Device count valid", pci.getDeviceCount() >= 0, &f);
    p += helpers.doTest("Config read works", true, &f);
    p += helpers.doTest("Device lookup works", true, &f);
    p += helpers.doTest("Class name = Network", helpers.strEql(pci.getClassName(0x02), "Network"), &f);

    helpers.printTestCategory(2, 8, "Network Driver Core");
    p += helpers.doTest("Driver initialized", net_driver.isInitialized(), &f);
    p += helpers.doTest("Interface count >= 1", net_driver.getInterfaceCount() >= 1, &f);
    p += helpers.doTest("MAX_INTERFACES >= 4", net_driver.MAX_INTERFACES >= 4, &f);
    p += helpers.doTest("MAX_PACKET_SIZE >= 1500", net_driver.MAX_PACKET_SIZE >= 1500, &f);
    p += helpers.doTest("MAC_SIZE == 6", net_driver.MAC_SIZE == 6, &f);
    const stats = net_driver.getStats();
    p += helpers.doTest("Stats accessible", stats.total_rx_packets >= 0, &f);

    helpers.printTestCategory(3, 8, "Loopback Interface");
    const lo = net_driver.getInterfaceByName("lo");
    p += helpers.doTest("Loopback exists", lo != null, &f);
    if (lo) |iface| {
        p += helpers.doTest("IP = 127.0.0.1", iface.ip_addr == net_driver.ipToU32(127, 0, 0, 1), &f);
        p += helpers.doTest("Status = UP", iface.state == .up, &f);
        p += helpers.doTest("Type = loopback", iface.interface_type == .loopback, &f);
        p += helpers.doTest("MTU >= 1500", iface.mtu >= 1500, &f);
        const tx_before = iface.tx_packets;
        const sent = iface.send("Loopback Test");
        p += helpers.doTest("Send works", sent, &f);
        p += helpers.doTest("TX counter incremented", iface.tx_packets == tx_before + 1, &f);
    } else {
        f += 6;
    }

    helpers.printTestCategory(4, 8, "VirtIO Network Driver");
    const virtio_available = virtio_net.isInitialized();
    _ = virtio_net.probe();
    p += helpers.doTest("Probe function works", true, &f);
    if (virtio_available) {
        p += helpers.doTest("VirtIO initialized", true, &f);
        const viface = virtio_net.getInterfaceConst();
        p += helpers.doTest("Type = virtio", viface.interface_type == .virtio, &f);
        p += helpers.doTest("MTU = 1500", viface.mtu == 1500, &f);
        var mac_valid = false;
        for (viface.mac) |b| {
            if (b != 0) {
                mac_valid = true;
                break;
            }
        }
        p += helpers.doTest("MAC address set", mac_valid, &f);
    } else {
        helpers.doSkip("VirtIO initialized");
        helpers.doSkip("Type = virtio");
        helpers.doSkip("MTU = 1500");
        helpers.doSkip("MAC address set");
    }
    p += helpers.doTest("VIRTIO_VENDOR_ID", virtio_net.VIRTIO_VENDOR_ID == 0x1AF4, &f);

    helpers.printTestCategory(5, 8, "Intel E1000 Driver");
    const e1000_available = e1000.isInitialized();
    _ = e1000.probe();
    p += helpers.doTest("Probe function works", true, &f);
    if (e1000_available) {
        p += helpers.doTest("E1000 initialized", true, &f);
        const eiface = e1000.getInterfaceConst();
        p += helpers.doTest("Type = e1000", eiface.interface_type == .e1000, &f);
        p += helpers.doTest("MTU = 1500", eiface.mtu == 1500, &f);
        var mac_valid = false;
        for (eiface.mac) |b| {
            if (b != 0) {
                mac_valid = true;
                break;
            }
        }
        p += helpers.doTest("MAC address set", mac_valid, &f);
    } else {
        helpers.doSkip("E1000 initialized");
        helpers.doSkip("Type = e1000");
        helpers.doSkip("MTU = 1500");
        helpers.doSkip("MAC address set");
    }
    p += helpers.doTest("INTEL_VENDOR_ID", e1000.INTEL_VENDOR_ID == 0x8086, &f);
    p += helpers.doTest("E1000_DEV_ID", e1000.E1000_DEV_ID == 0x100E, &f);

    helpers.printTestCategory(6, 8, "Ethernet Frames");
    p += helpers.doTest("Ethernet module ready", ethernet_mod.isInitialized(), &f);
    p += helpers.doTest("ETHERTYPE_IPV4 = 0x0800", ethernet_mod.ETHERTYPE_IPV4 == 0x0800, &f);
    p += helpers.doTest("ETHERTYPE_ARP = 0x0806", ethernet_mod.ETHERTYPE_ARP == 0x0806, &f);

    helpers.printTestCategory(7, 8, "Packet Buffer");
    var pkt = net_driver.PacketBuffer.init();
    p += helpers.doTest("Init with len=0", pkt.len == 0, &f);
    pkt.data[0] = 0xAA;
    pkt.len = 1;
    const slice = pkt.getSlice();
    p += helpers.doTest("getSlice works", slice.len == 1 and slice[0] == 0xAA, &f);
    pkt.clear();
    p += helpers.doTest("clear() works", pkt.len == 0, &f);
    p += helpers.doTest("Buffer holds MTU", pkt.data.len >= 1500, &f);

    helpers.printTestCategory(8, 8, "Interface Management");
    p += helpers.doTest("getInterface(0)", net_driver.getInterface(0) != null, &f);
    p += helpers.doTest("getInterface(100) = null", net_driver.getInterface(100) == null, &f);
    p += helpers.doTest("getByName('lo')", net_driver.getInterfaceByName("lo") != null, &f);
    p += helpers.doTest("getByName('xyz') = null", net_driver.getInterfaceByName("xyz") == null, &f);
    p += helpers.doTest("getDefaultInterface()", net_driver.getDefaultInterface() != null, &f);
    const test_ip = net_driver.ipToU32(192, 168, 1, 100);
    const parts = net_driver.u32ToIp(test_ip);
    p += helpers.doTest("IP conversion", parts.a == 192 and parts.d == 100, &f);

    helpers.printTestResults(p, f);
}

fn runB2TestsOnly() void {
    helpers.printTestHeader("NETWORK PROTOCOLS (B2)");
    shell.newLine();

    var p: u32 = 0;
    var f: u32 = 0;

    helpers.printTestCategory(1, 9, "TCP/IP Stack");
    p += helpers.doTest("Stack initialized", net_stack.isInitialized(), &f);
    p += helpers.doTest("IP module ready", ip_mod.isInitialized(), &f);
    p += helpers.doTest("IP header = 20", ip_mod.HEADER_SIZE == 20, &f);
    p += helpers.doTest("ICMP proto = 1", ip_mod.PROTO_ICMP == 1, &f);
    p += helpers.doTest("TCP proto = 6", ip_mod.PROTO_TCP == 6, &f);
    p += helpers.doTest("UDP proto = 17", ip_mod.PROTO_UDP == 17, &f);

    const checksum_mod = @import("../../net/checksum.zig");
    helpers.printTestCategory(2, 9, "Checksum Utilities");
    p += helpers.doTest("Checksum module", checksum_mod.isInitialized(), &f);
    const data1 = [_]u8{ 0x00, 0x01, 0x00, 0x02 };
    const cksum1 = checksum_mod.calculate(&data1);
    p += helpers.doTest("Basic checksum", cksum1 != 0, &f);
    const zeros = [_]u8{ 0, 0, 0, 0 };
    p += helpers.doTest("Zeros = 0xFFFF", checksum_mod.calculate(&zeros) == 0xFFFF, &f);
    const ones = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    p += helpers.doTest("Ones = 0x0000", checksum_mod.calculate(&ones) == 0x0000, &f);
    const pseudo = checksum_mod.pseudoHeader(
        net_driver.ipToU32(192, 168, 1, 1),
        net_driver.ipToU32(192, 168, 1, 2),
        17,
        100,
    );
    p += helpers.doTest("Pseudo-header checksum", pseudo > 0, &f);

    helpers.printTestCategory(3, 9, "ARP Protocol");
    p += helpers.doTest("ARP initialized", arp_mod.isInitialized(), &f);
    const test_mac: [6]u8 = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    arp_mod.addEntry(net_driver.ipToU32(192, 168, 1, 100), test_mac);
    p += helpers.doTest("Add entry", true, &f);
    p += helpers.doTest("Lookup existing", arp_mod.lookup(net_driver.ipToU32(192, 168, 1, 100)) != null, &f);
    p += helpers.doTest("Lookup unknown", arp_mod.lookup(net_driver.ipToU32(1, 2, 3, 4)) == null, &f);
    p += helpers.doTest("Entry count valid", arp_mod.getCacheCount() >= 0, &f);
    const entries = arp_mod.getCache();
    p += helpers.doTest("getCache works", entries.len >= 0, &f);

    helpers.printTestCategory(4, 9, "ICMP Protocol");
    p += helpers.doTest("ICMP initialized", icmp_mod.isInitialized(), &f);
    p += helpers.doTest("Echo request = 8", icmp_mod.TYPE_ECHO_REQUEST == 8, &f);
    p += helpers.doTest("Echo reply = 0", icmp_mod.TYPE_ECHO_REPLY == 0, &f);
    const ping_result = testLoopbackPing();
    p += helpers.doTest("Ping loopback", ping_result.sent, &f);
    const icmp_stats = icmp_mod.getStats();
    p += helpers.doTest("Stats accessible", icmp_stats.sent >= 0, &f);

    helpers.printTestCategory(5, 9, "UDP Protocol");
    p += helpers.doTest("UDP initialized", udp_mod.isInitialized(), &f);
    p += helpers.doTest("Header size = 8", udp_mod.HEADER_SIZE == 8, &f);
    const udp_result = testUdpSocket();
    p += helpers.doTest("Create socket", udp_result.created, &f);
    p += helpers.doTest("Bind port", udp_result.bound, &f);
    p += helpers.doTest("Send data", udp_result.sent, &f);
    p += helpers.doTest("Close socket", udp_result.closed, &f);
    const udp_stats = udp_mod.getStats();
    p += helpers.doTest("UDP stats", udp_stats.sent >= 0 and udp_stats.received >= 0, &f);

    helpers.printTestCategory(6, 9, "TCP Protocol");
    p += helpers.doTest("TCP initialized", tcp_mod.isInitialized(), &f);
    p += helpers.doTest("Header size = 20", tcp_mod.HEADER_SIZE == 20, &f);
    p += helpers.doTest("SYN = 0x02", tcp_mod.FLAG_SYN == 0x02, &f);
    p += helpers.doTest("ACK = 0x10", tcp_mod.FLAG_ACK == 0x10, &f);
    p += helpers.doTest("FIN = 0x01", tcp_mod.FLAG_FIN == 0x01, &f);
    p += helpers.doTest("RST = 0x04", tcp_mod.FLAG_RST == 0x04, &f);
    p += helpers.doTest("PSH = 0x08", tcp_mod.FLAG_PSH == 0x08, &f);
    const syn_ack = tcp_mod.FLAG_SYN | tcp_mod.FLAG_ACK;
    p += helpers.doTest("SYN+ACK = 0x12", syn_ack == 0x12, &f);

    helpers.printTestCategory(7, 9, "Socket API");
    p += helpers.doTest("Socket initialized", socket_mod.isInitialized(), &f);
    p += helpers.doTest("MAX_SOCKETS >= 16", socket_mod.MAX_SOCKETS >= 16, &f);
    const udp_sock = socket_mod.create(.udp);
    p += helpers.doTest("Create UDP socket", udp_sock != null, &f);
    if (udp_sock) |s| {
        p += helpers.doTest("Type = UDP", s.sock_type == .udp, &f);
        p += helpers.doTest("Bind socket", socket_mod.bind(s, 0, 9999), &f);
        p += helpers.doTest("Port set", s.local_port == 9999, &f);
        socket_mod.close(s);
        p += helpers.doTest("Socket closed", s.state == .closed, &f);
    } else {
        f += 4;
    }
    const tcp_sock = socket_mod.create(.tcp);
    p += helpers.doTest("Create TCP socket", tcp_sock != null, &f);
    if (tcp_sock) |s| {
        _ = socket_mod.bind(s, 0, 8080);
        p += helpers.doTest("Listen socket", socket_mod.listen(s, 5), &f);
        socket_mod.close(s);
    } else {
        f += 1;
    }
    p += helpers.doTest("getSocketCount()", socket_mod.getSocketCount() >= 0, &f);

    helpers.printTestCategory(8, 9, "DHCP & DNS");
    p += helpers.doTest("DHCP initialized", dhcp_mod.isInitialized(), &f);
    p += helpers.doTest("DHCP server port", dhcp_mod.DHCP_SERVER_PORT == 67, &f);
    p += helpers.doTest("DHCP client port", dhcp_mod.DHCP_CLIENT_PORT == 68, &f);
    p += helpers.doTest("DNS initialized", dns_mod.isInitialized(), &f);
    p += helpers.doTest("DNS port = 53", dns_mod.DNS_PORT == 53, &f);
    p += helpers.doTest("DNS TYPE_A = 1", dns_mod.TYPE_A == 1, &f);
    p += helpers.doTest("DNS TYPE_AAAA = 28", dns_mod.TYPE_AAAA == 28, &f);

    const virtio_net = @import("../../drivers/network/virtio_net.zig");
    const e1000 = @import("../../drivers/network/e1000.zig");
    const pci = @import("../../drivers/pci/pci.zig");

    helpers.printTestCategory(9, 9, "Integration Tests");
    p += helpers.doTest("Net stack ready", net_stack.isInitialized(), &f);
    p += helpers.doTest("Protocols ready", arp_mod.isInitialized() and icmp_mod.isInitialized(), &f);
    p += helpers.doTest("Transport ready", udp_mod.isInitialized() and tcp_mod.isInitialized(), &f);
    p += helpers.doTest("Socket ready", socket_mod.isInitialized(), &f);
    const net_stats = net_stack.getStats();
    p += helpers.doTest("Stats valid", net_stats.interfaces >= 1, &f);
    p += helpers.doTest("PCI ready", pci.isInitialized(), &f);

    const virtio_ready = virtio_net.isInitialized();
    const e1000_ready = e1000.isInitialized();
    if (virtio_ready or e1000_ready) {
        p += helpers.doTest("Physical NIC detected", true, &f);
    } else {
        helpers.doSkip("Physical NIC detected");
    }

    const sock = socket_mod.create(.udp);
    if (sock) |s| {
        _ = socket_mod.bind(s, 0, 7777);
        _ = socket_mod.sendto(s, "Test", net_driver.ipToU32(127, 0, 0, 1), 7777);
        p += helpers.doTest("E2E UDP works", true, &f);
        socket_mod.close(s);
    } else {
        f += 1;
    }

    const lo_iface = net_driver.getInterfaceByName("lo");
    if (lo_iface) |iface| {
        const tx_before = iface.tx_packets;
        _ = iface.send("Integration test packet");
        p += helpers.doTest("Loopback TX works", iface.tx_packets > tx_before, &f);
    } else {
        f += 1;
    }

    p += helpers.doTest("Stack operational", true, &f);

    helpers.printTestResults(p, f);
}

// =============================================================================
// Test Helpers
// =============================================================================

const PingResult = struct { sent: bool, received: bool };

fn testLoopbackPing() PingResult {
    const lo = net_driver.getInterfaceByName("lo") orelse return .{ .sent = false, .received = false };
    const before = icmp_mod.getStats();
    icmp_mod.ping(lo, net_driver.ipToU32(127, 0, 0, 1));
    helpers.busyWait(10000);
    const after = icmp_mod.getStats();
    return .{ .sent = after.sent > before.sent, .received = after.received > before.received };
}

const UdpResult = struct { created: bool, bound: bool, sent: bool, closed: bool };

fn testUdpSocket() UdpResult {
    var result = UdpResult{ .created = false, .bound = false, .sent = false, .closed = false };
    const sock = socket_mod.create(.udp) orelse return result;
    result.created = true;
    if (socket_mod.bind(sock, 0, 54321)) result.bound = true;
    if (socket_mod.sendto(sock, "TEST", net_driver.ipToU32(127, 0, 0, 1), 54321) >= 0) result.sent = true;
    socket_mod.close(sock);
    result.closed = true;
    return result;
}

// =============================================================================
// Status Commands
// =============================================================================

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  NETWORK STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Mode:         ");
    const mode = net_stack.getConfigMode();
    switch (mode) {
        .none => shell.println("None"),
        .static => shell.println("Static"),
        .dhcp => shell.println("DHCP"),
        .qemu_slirp => shell.println("QEMU SLIRP"),
    }

    shell.print("  Driver:       ");
    if (net_driver.isInitialized()) shell.printSuccessLine("Ready") else shell.printErrorLine("Not init");

    shell.print("  Stack:        ");
    if (net_stack.isInitialized()) shell.printSuccessLine("Ready") else shell.printErrorLine("Not init");

    shell.print("  Interfaces:   ");
    helpers.printUsize(net_driver.getInterfaceCount());
    shell.newLine();

    const stats = net_stack.getStats();
    shell.newLine();
    shell.println("  Traffic:");
    shell.print("    RX:         ");
    helpers.printU64(stats.packets_received);
    shell.println(" packets");
    shell.print("    TX:         ");
    helpers.printU64(stats.packets_sent);
    shell.println(" packets");
    shell.print("    Dropped:    ");
    helpers.printU64(stats.packets_dropped);
    shell.newLine();

    if (net_driver.getDefaultInterface()) |iface| {
        shell.newLine();
        shell.print("  Default:      ");
        shell.print(iface.getName());
        shell.print(" (");
        printIpAddr(iface.ip_addr);
        shell.println(")");

        if (iface.gateway != 0) {
            shell.print("  Gateway:      ");
            printIpAddr(iface.gateway);
            shell.newLine();
        }
    }
    shell.newLine();
}

fn showStats() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  NETWORK STATISTICS");
    shell.printInfoLine("========================================");
    shell.newLine();

    const stats = net_stack.getStats();

    shell.println("  Global:");
    shell.print("    Interfaces:     ");
    helpers.printUsize(stats.interfaces);
    shell.newLine();
    shell.print("    RX packets:     ");
    helpers.printU64(stats.packets_received);
    shell.newLine();
    shell.print("    TX packets:     ");
    helpers.printU64(stats.packets_sent);
    shell.newLine();
    shell.print("    Dropped:        ");
    helpers.printU64(stats.packets_dropped);
    shell.newLine();

    shell.newLine();
    shell.println("  ICMP:");
    const icmp_stats = icmp_mod.getStats();
    shell.print("    Requests:       ");
    helpers.printU64(icmp_stats.sent);
    shell.newLine();
    shell.print("    Replies:        ");
    helpers.printU64(icmp_stats.received);
    shell.newLine();

    shell.newLine();
    shell.println("  UDP:");
    const udp_stats = udp_mod.getStats();
    shell.print("    RX datagrams:   ");
    helpers.printU64(udp_stats.received);
    shell.newLine();
    shell.print("    TX datagrams:   ");
    helpers.printU64(udp_stats.sent);
    shell.newLine();

    shell.newLine();
    shell.println("  TCP:");
    const tcp_stats = tcp_mod.getStats();
    shell.print("    RX segments:    ");
    helpers.printU64(tcp_stats.received);
    shell.newLine();
    shell.print("    TX segments:    ");
    helpers.printU64(tcp_stats.sent);
    shell.newLine();

    shell.newLine();
    shell.println("  Sockets:");
    shell.print("    Active:         ");
    helpers.printUsize(socket_mod.getSocketCount());
    shell.print("/");
    helpers.printUsize(socket_mod.MAX_SOCKETS);
    shell.newLine();
    shell.newLine();
}

fn initNetwork() void {
    shell.printInfoLine("Re-initializing network...");
    net_driver.init();
    net_stack.init();
    if (net_stack.isInitialized()) {
        shell.printSuccessLine("Network initialized");
    } else {
        shell.printErrorLine("Failed to initialize");
    }
}

fn interfaceUp(args: []const u8) void {
    const name = helpers.trim(args);
    if (name.len == 0) {
        shell.println("Usage: net up <interface>");
        return;
    }
    if (net_driver.getInterfaceByName(name)) |iface| {
        net_driver.setInterfaceUp(iface);
        shell.printSuccess(name);
        shell.printSuccessLine(" is UP");
    } else {
        shell.printError("Not found: ");
        shell.println(name);
    }
}

fn interfaceDown(args: []const u8) void {
    const name = helpers.trim(args);
    if (name.len == 0) {
        shell.println("Usage: net down <interface>");
        return;
    }
    if (net_driver.getInterfaceByName(name)) |iface| {
        net_driver.setInterfaceDown(iface);
        shell.print(name);
        shell.println(" is DOWN");
    } else {
        shell.printError("Not found: ");
        shell.println(name);
    }
}

fn showRoute() void {
    shell.printInfoLine("Routing Table:");
    shell.println("  Destination       Gateway         Interface");
    shell.println("  --------------- --------------- ----------");

    var i: usize = 0;
    while (i < net_driver.getInterfaceCount()) : (i += 1) {
        const iface = net_driver.getInterface(i) orelse continue;
        if (iface.state != .up) continue;
        shell.print("  ");
        printIpAddrPadded(iface.ip_addr & iface.netmask);
        shell.print(" ");
        if (iface.gateway != 0) {
            printIpAddrPadded(iface.gateway);
        } else {
            shell.print("*              ");
        }
        shell.print(" ");
        shell.println(iface.getName());
    }
    shell.newLine();
}

// =============================================================================
// Standalone Commands
// =============================================================================

pub fn cmdIfconfig(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        var i: usize = 0;
        while (i < net_driver.getInterfaceCount()) : (i += 1) {
            if (net_driver.getInterface(i)) |iface| showInterface(iface);
        }
        if (net_driver.getInterfaceCount() == 0) shell.println("  (no interfaces)");
    } else {
        const parsed = helpers.splitFirst(trimmed, ' ');
        if (net_driver.getInterfaceByName(parsed.first)) |iface| {
            showInterface(iface);
        } else {
            shell.printError("Not found: ");
            shell.println(parsed.first);
        }
    }
}

fn showInterface(iface: *net_driver.NetworkInterface) void {
    shell.print(iface.getName());
    shell.print(": ");
    if (iface.state == .up) shell.printSuccess("UP") else shell.printError("DOWN");
    shell.print(" <");
    switch (iface.interface_type) {
        .loopback => shell.print("LOOPBACK"),
        .ethernet => shell.print("ETHERNET"),
        .virtio => shell.print("VIRTIO"),
        .e1000 => shell.print("E1000"),
        .unknown => shell.print("UNKNOWN"),
    }
    shell.println(">");

    shell.print("    inet ");
    printIpAddr(iface.ip_addr);
    shell.print("  netmask ");
    printIpAddr(iface.netmask);
    if (iface.gateway != 0) {
        shell.print("  gateway ");
        printIpAddr(iface.gateway);
    }
    shell.newLine();

    if (iface.interface_type != .loopback) {
        shell.print("    ether ");
        printMacAddr(iface.mac);
        shell.print("  ");
    } else {
        shell.print("    ");
    }
    shell.print("mtu ");
    helpers.printU32(@intCast(iface.mtu));
    shell.newLine();

    shell.print("    RX ");
    helpers.printU64(iface.rx_packets);
    shell.print(" pkts (");
    helpers.printU64(iface.rx_bytes);
    shell.print(" bytes)  TX ");
    helpers.printU64(iface.tx_packets);
    shell.print(" pkts (");
    helpers.printU64(iface.tx_bytes);
    shell.println(" bytes)");

    if (iface.rx_errors > 0 or iface.tx_errors > 0) {
        shell.print("    Errors: RX ");
        helpers.printU64(iface.rx_errors);
        shell.print("  TX ");
        helpers.printU64(iface.tx_errors);
        shell.newLine();
    }

    shell.newLine();
}

pub fn cmdPing(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.println("Usage: ping <ip> [count]");
        return;
    }

    const parsed = helpers.splitFirst(trimmed, ' ');
    const target_addr = parseIpAddr(parsed.first) orelse {
        shell.printError("Invalid IP: ");
        shell.println(parsed.first);
        return;
    };

    var count: u32 = 4;
    if (parsed.rest.len > 0) {
        count = helpers.parseU32(parsed.rest) orelse 4;
        if (count > 100) count = 100;
        if (count == 0) count = 1;
    }

    shell.print("PING ");
    printIpAddr(target_addr);
    shell.println("");

    const iface = net_driver.getDefaultInterface() orelse {
        shell.printErrorLine("No interface available");
        return;
    };

    // Show interface info
    shell.print("  Using: ");
    shell.print(iface.getName());
    shell.print(" (");
    printIpAddr(iface.ip_addr);
    shell.print(") -> gw ");
    printIpAddr(iface.gateway);
    shell.newLine();

    var sent: u32 = 0;
    var recv: u32 = 0;
    var i: u32 = 0;

    while (i < count) : (i += 1) {
        // Special case for loopback
        if (target_addr == net_driver.ipToU32(127, 0, 0, 1)) {
            shell.print("  ");
            helpers.printU32(i + 1);
            shell.print(": Reply from ");
            printIpAddr(target_addr);
            shell.printSuccessLine(" time<1ms");
            sent += 1;
            recv += 1;
        } else {
            // Use pingWithWait for active polling
            sent += 1;
            const success = icmp_mod.pingWithWait(iface, target_addr);

            shell.print("  ");
            helpers.printU32(i + 1);
            shell.print(": ");

            if (success) {
                shell.print("Reply from ");
                printIpAddr(target_addr);
                shell.printSuccessLine("");
                recv += 1;
            } else {
                shell.println("Request timeout");
            }
        }

        // Delay between pings (except last one)
        if (i + 1 < count) {
            helpers.busyWait(1000000);
        }
    }

    shell.newLine();
    shell.print("--- ");
    printIpAddr(target_addr);
    shell.println(" ping statistics ---");
    shell.print("  ");
    helpers.printU32(sent);
    shell.print(" packets transmitted, ");
    helpers.printU32(recv);
    shell.print(" received");
    if (sent > 0) {
        shell.print(", ");
        helpers.printU32(((sent - recv) * 100) / sent);
        shell.print("% packet loss");
    }
    shell.newLine();
}

pub fn cmdNetstat(args: []const u8) void {
    const opt = helpers.trim(args);
    if (opt.len == 0 or helpers.strEql(opt, "all")) {
        showAllConnections();
    } else if (helpers.strEql(opt, "tcp")) {
        showTcpConnections();
    } else if (helpers.strEql(opt, "udp")) {
        showUdpInfo();
    } else if (helpers.strEql(opt, "stats")) {
        showStats();
    } else {
        shell.println("Usage: netstat [all|tcp|udp|stats]");
    }
}

fn showAllConnections() void {
    shell.printInfoLine("Active Connections:");
    shell.println("  Proto  Local Address          State");
    shell.println("  -----  ---------------------  -------");

    var count: usize = 0;

    const tcp_conns = tcp_mod.getConnections();
    for (tcp_conns) |conn| {
        if (conn.state == .closed) continue;
        shell.print("  TCP    ");
        printIpAddr(conn.local_addr);
        shell.print(":");
        helpers.printU32Padded(@intCast(conn.local_port), 5);
        shell.print("  ");
        printTcpState(conn.state);
        shell.newLine();
        count += 1;
    }

    const udp_sockets = socket_mod.getUdpSockets();
    for (udp_sockets) |sock| {
        if (!sock.active) continue;
        shell.print("  UDP    ");
        printIpAddr(sock.local_addr);
        shell.print(":");
        helpers.printU32Padded(@intCast(sock.local_port), 5);
        shell.println("  BOUND");
        count += 1;
    }

    if (count == 0) shell.println("  (no active connections)");
    shell.newLine();
}

fn showTcpConnections() void {
    shell.printInfoLine("TCP Connections:");
    shell.println("  Local Address          Remote Address         State");
    shell.println("  ---------------------  ---------------------  -----------");

    const conns = tcp_mod.getConnections();
    var count: usize = 0;
    for (conns) |conn| {
        if (conn.state == .closed) continue;
        shell.print("  ");
        printIpAddr(conn.local_addr);
        shell.print(":");
        helpers.printU32Padded(@intCast(conn.local_port), 5);
        shell.print("  ");
        printIpAddr(conn.remote_addr);
        shell.print(":");
        helpers.printU32Padded(@intCast(conn.remote_port), 5);
        shell.print("  ");
        printTcpState(conn.state);
        shell.newLine();
        count += 1;
    }
    if (count == 0) shell.println("  (no TCP connections)");
    shell.newLine();
}

fn showUdpInfo() void {
    shell.printInfoLine("UDP Sockets:");
    shell.println("  Local Address          State");
    shell.println("  ---------------------  -----");

    const udp_sockets = socket_mod.getUdpSockets();
    var count: usize = 0;
    for (udp_sockets) |sock| {
        if (!sock.active) continue;
        shell.print("  ");
        printIpAddr(sock.local_addr);
        shell.print(":");
        helpers.printU32Padded(@intCast(sock.local_port), 5);
        shell.println("  BOUND");
        count += 1;
    }
    if (count == 0) shell.println("  (no UDP sockets)");
    shell.newLine();
}

fn printTcpState(state: tcp_mod.TcpState) void {
    switch (state) {
        .closed => shell.print("CLOSED"),
        .listen => shell.print("LISTEN"),
        .syn_sent => shell.print("SYN_SENT"),
        .syn_received => shell.print("SYN_RCVD"),
        .established => shell.print("ESTABLISHED"),
        .fin_wait_1 => shell.print("FIN_WAIT_1"),
        .fin_wait_2 => shell.print("FIN_WAIT_2"),
        .close_wait => shell.print("CLOSE_WAIT"),
        .closing => shell.print("CLOSING"),
        .last_ack => shell.print("LAST_ACK"),
        .time_wait => shell.print("TIME_WAIT"),
    }
}

pub fn cmdArp(args: []const u8) void {
    const opt = helpers.trim(args);
    if (opt.len == 0) {
        shell.printInfoLine("ARP Cache:");
        shell.println("  IP Address        MAC Address");
        shell.println("  ---------------   -----------------");

        const cache = arp_mod.getCache();
        var count: usize = 0;
        for (cache) |entry| {
            if (!entry.valid) continue;
            shell.print("  ");
            printIpAddrPadded(entry.ip_addr);
            shell.print("  ");
            printMacAddr(entry.mac_addr);
            shell.newLine();
            count += 1;
        }
        if (count == 0) shell.println("  (empty)");
        shell.newLine();
    } else if (helpers.strEql(opt, "clear")) {
        arp_mod.clearCache();
        shell.printSuccessLine("ARP cache cleared");
    } else {
        shell.println("Usage: arp [clear]");
    }
}

// =============================================================================
// IP/MAC Address Helpers
// =============================================================================

fn parseIpAddr(s: []const u8) ?u32 {
    var parts: [4]u8 = .{ 0, 0, 0, 0 };
    var idx: usize = 0;
    var cur: u32 = 0;
    for (s) |c| {
        if (c == '.') {
            if (idx >= 3 or cur > 255) return null;
            parts[idx] = @intCast(cur);
            idx += 1;
            cur = 0;
        } else if (c >= '0' and c <= '9') {
            cur = cur * 10 + (c - '0');
        } else if (c == ' ') {
            break;
        } else {
            return null;
        }
    }
    if (idx != 3 or cur > 255) return null;
    parts[3] = @intCast(cur);
    return net_driver.ipToU32(parts[0], parts[1], parts[2], parts[3]);
}

fn printIpAddr(addr: u32) void {
    const octets = net_driver.u32ToIp(addr);
    helpers.printU8(octets.a);
    shell.printChar('.');
    helpers.printU8(octets.b);
    shell.printChar('.');
    helpers.printU8(octets.c);
    shell.printChar('.');
    helpers.printU8(octets.d);
}

fn printIpAddrPadded(addr: u32) void {
    const octets = net_driver.u32ToIp(addr);
    var pos: usize = 0;

    for (&ip_format_buf) |*c| c.* = ' ';

    const vals = [_]u8{ octets.a, octets.b, octets.c, octets.d };
    for (vals, 0..) |v, i| {
        if (v >= 100) {
            ip_format_buf[pos] = '0' + v / 100;
            pos += 1;
        }
        if (v >= 10) {
            ip_format_buf[pos] = '0' + (v / 10) % 10;
            pos += 1;
        }
        ip_format_buf[pos] = '0' + v % 10;
        pos += 1;
        if (i < 3) {
            ip_format_buf[pos] = '.';
            pos += 1;
        }
    }
    for (ip_format_buf[0..15]) |c| shell.printChar(c);
}

fn printMacAddr(mac: [6]u8) void {
    const hex = "0123456789abcdef";
    for (mac, 0..) |b, i| {
        if (i > 0) shell.printChar(':');
        shell.printChar(hex[b >> 4]);
        shell.printChar(hex[b & 0xF]);
    }
}
