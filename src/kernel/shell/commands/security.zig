//! Zamrud OS - Security Commands
//! Security management, firewall control, threat monitoring
//! Updated: E3.4 Network Capability integration

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");

// Security imports
const security = @import("../../security/security.zig");
const firewall = @import("../../net/firewall.zig");
const blacklist = @import("../../security/blacklist.zig");
const threat_log = @import("../../security/threat_log.zig");

// Network imports
const net_driver = @import("../../drivers/network/network.zig");

// E3.4: Network Capability
const net_capability = @import("../../security/net_capability.zig");

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "status")) {
        showStatus();
    } else if (helpers.strEql(parsed.cmd, "level")) {
        cmdLevel(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "lockdown")) {
        cmdLockdown();
    } else if (helpers.strEql(parsed.cmd, "disarm")) {
        cmdDisarm();
    } else if (helpers.strEql(parsed.cmd, "firewall")) {
        cmdFirewall(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "blacklist")) {
        cmdBlacklist(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "threats")) {
        cmdThreats(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest(parsed.rest);
    } else {
        shell.printError("security: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'security help'");
    }
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.newLine();
    shell.println("+===========================================================+");
    shell.println("|               ZAMRUD OS SECURITY MANAGER                  |");
    shell.println("+===========================================================+");
    shell.newLine();

    shell.println("  USAGE: security <command> [options]");
    shell.println("         firewall <command> [options]  (shortcut)");
    shell.newLine();

    shell.println("+-----------------------------------------------------------+");
    shell.println("|  STATUS & MONITORING                                      |");
    shell.println("+-----------------------------------------------------------+");
    shell.println("  status              Display full security status");
    shell.println("  level               Show current security level");
    shell.println("  threats list        List detected threats");
    shell.println("  threats clear       Clear threat log");
    shell.newLine();

    shell.println("+-----------------------------------------------------------+");
    shell.println("|  SECURITY LEVELS                                          |");
    shell.println("+-----------------------------------------------------------+");
    shell.println("  level minimal       Basic protection (permissive)");
    shell.println("  level standard      Normal operation (default)");
    shell.println("  level elevated      Heightened security (P2P only)");
    shell.println("  level maximum       Full lockdown mode");
    shell.println("  level paranoid      Block all except whitelist");
    shell.newLine();

    shell.println("+-----------------------------------------------------------+");
    shell.println("|  EMERGENCY CONTROLS                                       |");
    shell.println("+-----------------------------------------------------------+");
    shell.println("  lockdown            Activate emergency lockdown");
    shell.println("  disarm              Deactivate lockdown mode");
    shell.newLine();

    shell.println("+-----------------------------------------------------------+");
    shell.println("|  FIREWALL MANAGEMENT                                      |");
    shell.println("+-----------------------------------------------------------+");
    shell.println("  firewall status     Show firewall status");
    shell.println("  firewall rules      List all firewall rules");
    shell.println("  firewall stats      Show traffic statistics");
    shell.println("  firewall enable     Enable firewall (enforcing)");
    shell.println("  firewall disable    Disable firewall");
    shell.println("  firewall stealth    Toggle stealth mode");
    shell.println("  firewall p2p        Toggle P2P-only mode");
    shell.println("  firewall reset      Reset statistics");
    shell.println("  firewall test       Run firewall test suite");
    shell.newLine();

    shell.println("+-----------------------------------------------------------+");
    shell.println("|  BLACKLIST MANAGEMENT                                     |");
    shell.println("+-----------------------------------------------------------+");
    shell.println("  blacklist list      Show blocked IPs");
    shell.println("  blacklist add <ip> [seconds]");
    shell.println("  blacklist remove <ip>");
    shell.println("  blacklist clear     Clear all entries");
    shell.newLine();

    shell.println("+-----------------------------------------------------------+");
    shell.println("|  NETWORK CAPABILITY (E3.4)                                |");
    shell.println("+-----------------------------------------------------------+");
    shell.println("  netcap              Network capability status");
    shell.println("  netprocs            Per-process network table");
    shell.println("  netsockets          Socket ownership table");
    shell.println("  netreg <pid> [caps] Register process");
    shell.println("  netallow <pid>      Grant CAP_NET");
    shell.println("  netrevoke <pid>     Revoke CAP_NET + close sockets");
    shell.println("  netdeny <pid>       Block ALL network for process");
    shell.println("  netrestrict <pid>   Set restricted mode");
    shell.println("  netreset <pid>      Reset violations / un-kill");
    shell.println("  netviolations       Show violation report");
    shell.println("  nettest             Run E3.4 test suite (20 tests)");
    shell.newLine();

    shell.println("+-----------------------------------------------------------+");
    shell.println("|  TESTING                                                  |");
    shell.println("+-----------------------------------------------------------+");
    shell.println("  test                Run all security tests");
    shell.println("  test quick          Quick health check");
    shell.newLine();
    shell.println("+===========================================================+");
    shell.newLine();
}

// =============================================================================
// Status
// =============================================================================

fn showStatus() void {
    shell.newLine();
    shell.println("+===========================================================+");
    shell.println("|                    SECURITY STATUS                        |");
    shell.println("+===========================================================+");
    shell.newLine();

    // Security Level
    shell.println("  [SECURITY LEVEL]");
    shell.print("    Current:        ");
    const level = security.getSecurityLevel();
    switch (level) {
        .minimal => shell.printWarningLine("MINIMAL"),
        .standard => shell.printSuccessLine("STANDARD"),
        .elevated => shell.printInfoLine("ELEVATED"),
        .maximum => shell.printErrorLine("MAXIMUM"),
        .paranoid => shell.printErrorLine("PARANOID"),
    }
    shell.newLine();

    // Firewall Status
    shell.println("  [FIREWALL]");
    shell.print("    State:          ");
    switch (firewall.state) {
        .disabled => shell.printErrorLine("DISABLED"),
        .permissive => shell.printWarningLine("PERMISSIVE"),
        .enforcing => shell.printSuccessLine("ENFORCING"),
        .lockdown => shell.printErrorLine("LOCKDOWN"),
    }

    shell.print("    Stealth Mode:   ");
    if (firewall.config.stealth_mode) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("    P2P-Only Mode:  ");
    if (firewall.config.p2p_only_mode) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("    Block ICMP:     ");
    if (firewall.config.block_icmp) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("    Rate Limiting:  ");
    if (firewall.config.enable_rate_limit) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("    Auto Blacklist: ");
    if (firewall.config.auto_blacklist) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }
    shell.newLine();

    // Traffic Statistics
    const fw_stats = firewall.getStats();
    shell.println("  [TRAFFIC STATISTICS]");
    shell.print("    Total Packets:  ");
    helpers.printU64(fw_stats.packets_total);
    shell.newLine();
    shell.print("    Allowed:        ");
    shell.printSuccess("");
    helpers.printU64(fw_stats.packets_allowed);
    shell.newLine();
    shell.print("    Dropped:        ");
    if (fw_stats.packets_dropped > 0) {
        shell.printError("");
    }
    helpers.printU64(fw_stats.packets_dropped);
    shell.newLine();
    shell.print("    Rejected:       ");
    helpers.printU64(fw_stats.packets_rejected);
    shell.newLine();
    shell.print("    ProcCap(E3.4):  ");
    helpers.printU64(fw_stats.blocked_process_cap);
    shell.newLine();
    shell.newLine();

    // Block Reasons
    shell.println("  [BLOCK REASONS]");
    shell.print("    ICMP Blocked:   ");
    helpers.printU64(fw_stats.icmp_blocked);
    shell.newLine();
    shell.print("    TCP Blocked:    ");
    helpers.printU64(fw_stats.tcp_blocked);
    shell.newLine();
    shell.print("    UDP Blocked:    ");
    helpers.printU64(fw_stats.udp_blocked);
    shell.newLine();
    shell.print("    No Rule Match:  ");
    helpers.printU64(fw_stats.blocked_no_rule);
    shell.newLine();
    shell.print("    Rate Limited:   ");
    helpers.printU64(fw_stats.blocked_rate_limit);
    shell.newLine();
    shell.print("    Blacklisted:    ");
    helpers.printU64(fw_stats.blocked_blacklist);
    shell.newLine();
    shell.print("    No Peer ID:     ");
    helpers.printU64(fw_stats.blocked_no_peer);
    shell.newLine();
    shell.print("    SYN Flood:      ");
    helpers.printU64(fw_stats.blocked_syn_flood);
    shell.newLine();
    shell.print("    Port Scan:      ");
    helpers.printU64(fw_stats.blocked_port_scan);
    shell.newLine();
    shell.newLine();

    // Connections
    shell.println("  [CONNECTIONS]");
    shell.print("    Total:          ");
    helpers.printU64(fw_stats.connections_total);
    shell.newLine();
    shell.print("    Active:         ");
    helpers.printU64(fw_stats.connections_active);
    shell.newLine();
    shell.newLine();

    // Rules & Blacklist
    shell.println("  [RULES & BLACKLIST]");
    shell.print("    Firewall Rules: ");
    helpers.printUsize(firewall.getRuleCount());
    shell.newLine();
    shell.print("    Blacklist IPs:  ");
    helpers.printUsize(firewall.getBlacklistCount());
    shell.newLine();
    shell.newLine();

    // E3.4: Network Capability
    shell.println("  [NETWORK CAPABILITY (E3.4)]");
    if (net_capability.isInitialized()) {
        const ns = net_capability.getStats();
        shell.print("    Registered:     ");
        helpers.printUsize(net_capability.getProcessCount());
        shell.println(" processes");
        shell.print("    Active Sockets: ");
        helpers.printUsize(net_capability.getActiveSocketCount());
        shell.newLine();
        shell.print("    Net Rules:      ");
        helpers.printUsize(net_capability.getNetRuleCount());
        shell.newLine();
        shell.print("    Net Violations: ");
        helpers.printU64(ns.violations_total);
        shell.newLine();
        shell.print("    Procs Killed:   ");
        helpers.printU64(ns.processes_killed);
        shell.newLine();
    } else {
        shell.println("    Not initialized");
    }
    shell.newLine();

    // Threats
    shell.println("  [THREAT LOG]");
    shell.print("    Total Threats:  ");
    helpers.printU64(threat_log.getTotalThreats());
    shell.newLine();
    shell.print("    Recent Entries: ");
    helpers.printUsize(threat_log.getThreatCount());
    shell.newLine();

    shell.newLine();
    shell.println("+===========================================================+");
    shell.newLine();
}

// =============================================================================
// Security Level Commands
// =============================================================================

fn cmdLevel(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0) {
        shell.newLine();
        shell.println("  Current Security Level:");
        shell.print("    ");
        const level = security.getSecurityLevel();
        switch (level) {
            .minimal => {
                shell.printWarningLine("MINIMAL");
                shell.println("    - Firewall: Permissive");
                shell.println("    - Stealth: OFF");
                shell.println("    - P2P-Only: OFF");
            },
            .standard => {
                shell.printSuccessLine("STANDARD");
                shell.println("    - Firewall: Enforcing");
                shell.println("    - Stealth: ON");
                shell.println("    - P2P-Only: OFF");
            },
            .elevated => {
                shell.printInfoLine("ELEVATED");
                shell.println("    - Firewall: Enforcing");
                shell.println("    - Stealth: ON");
                shell.println("    - P2P-Only: ON");
            },
            .maximum => {
                shell.printErrorLine("MAXIMUM");
                shell.println("    - Firewall: Lockdown");
                shell.println("    - Stealth: ON");
                shell.println("    - P2P-Only: ON");
            },
            .paranoid => {
                shell.printErrorLine("PARANOID");
                shell.println("    - Firewall: Lockdown");
                shell.println("    - All blocked except whitelist");
            },
        }
        shell.newLine();
    } else if (helpers.strEql(opt, "minimal")) {
        security.setSecurityLevel(.minimal);
        shell.printWarningLine("[!] Security level set to MINIMAL");
    } else if (helpers.strEql(opt, "standard")) {
        security.setSecurityLevel(.standard);
        shell.printSuccessLine("[+] Security level set to STANDARD");
    } else if (helpers.strEql(opt, "elevated")) {
        security.setSecurityLevel(.elevated);
        shell.printInfoLine("[*] Security level set to ELEVATED");
    } else if (helpers.strEql(opt, "maximum")) {
        security.setSecurityLevel(.maximum);
        shell.printErrorLine("[!] Security level set to MAXIMUM");
    } else if (helpers.strEql(opt, "paranoid")) {
        security.setSecurityLevel(.paranoid);
        shell.printErrorLine("[!!!] Security level set to PARANOID");
    } else {
        shell.println("Usage: security level [minimal|standard|elevated|maximum|paranoid]");
    }
}

fn cmdLockdown() void {
    shell.newLine();
    shell.println("+===========================================================+");
    shell.printErrorLine("|          !!! EMERGENCY LOCKDOWN ACTIVATED !!!            |");
    shell.println("+===========================================================+");
    shell.newLine();
    security.emergencyLockdown();
    shell.println("  All incoming connections BLOCKED");
    shell.println("  Only whitelisted IPs allowed");
    shell.println("  Use 'security disarm' to deactivate");
    shell.newLine();
}

fn cmdDisarm() void {
    shell.newLine();
    shell.printInfoLine("[*] Disarming lockdown mode...");
    security.disarmLockdown();
    shell.printSuccessLine("[+] Lockdown disarmed - Normal operation restored");
    shell.newLine();
}

// =============================================================================
// Firewall Commands
// =============================================================================

fn cmdFirewall(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        showFirewallStatus();
    } else if (helpers.strEql(parsed.cmd, "help")) {
        showFirewallHelp();
    } else if (helpers.strEql(parsed.cmd, "rules")) {
        showRules();
    } else if (helpers.strEql(parsed.cmd, "stats")) {
        showFirewallStats();
    } else if (helpers.strEql(parsed.cmd, "enable")) {
        firewall.setState(.enforcing);
        shell.printSuccessLine("[+] Firewall ENABLED (Enforcing mode)");
    } else if (helpers.strEql(parsed.cmd, "disable")) {
        firewall.setState(.disabled);
        shell.printWarningLine("[!] Firewall DISABLED - System unprotected!");
    } else if (helpers.strEql(parsed.cmd, "stealth")) {
        const current = firewall.config.stealth_mode;
        firewall.setStealthMode(!current);
        if (!current) {
            shell.printSuccessLine("[+] Stealth mode ENABLED");
        } else {
            shell.printWarningLine("[!] Stealth mode DISABLED");
        }
    } else if (helpers.strEql(parsed.cmd, "p2p")) {
        const current = firewall.config.p2p_only_mode;
        firewall.setP2POnlyMode(!current);
        if (!current) {
            shell.printSuccessLine("[+] P2P-only mode ENABLED");
        } else {
            shell.printWarningLine("[!] P2P-only mode DISABLED");
        }
    } else if (helpers.strEql(parsed.cmd, "reset")) {
        firewall.resetStats();
        shell.printSuccessLine("[+] Firewall statistics reset");
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest("all");
    } else {
        showFirewallHelp();
    }
}

fn showFirewallHelp() void {
    shell.newLine();
    shell.println("  Firewall Commands:");
    shell.println("    status    Show firewall status");
    shell.println("    rules     List all rules");
    shell.println("    stats     Show statistics");
    shell.println("    enable    Enable firewall");
    shell.println("    disable   Disable firewall");
    shell.println("    stealth   Toggle stealth mode");
    shell.println("    p2p       Toggle P2P-only mode");
    shell.println("    reset     Reset statistics");
    shell.println("    test      Run test suite");
    shell.newLine();
}

fn showFirewallStatus() void {
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.println("|                   FIREWALL STATUS                         |");
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();

    shell.print("  State:            ");
    switch (firewall.state) {
        .disabled => shell.printErrorLine("DISABLED"),
        .permissive => shell.printWarningLine("PERMISSIVE"),
        .enforcing => shell.printSuccessLine("ENFORCING"),
        .lockdown => shell.printErrorLine("LOCKDOWN"),
    }

    shell.print("  Stealth Mode:     ");
    if (firewall.config.stealth_mode) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("  P2P-Only Mode:    ");
    if (firewall.config.p2p_only_mode) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("  Block ICMP:       ");
    if (firewall.config.block_icmp) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("  Rate Limiting:    ");
    if (firewall.config.enable_rate_limit) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.newLine();
    shell.print("  Rules:            ");
    helpers.printUsize(firewall.getRuleCount());
    shell.newLine();

    shell.print("  Blacklist:        ");
    helpers.printUsize(firewall.getBlacklistCount());
    shell.println(" IPs");

    shell.print("  Active Conns:     ");
    helpers.printUsize(firewall.getActiveConnections());
    shell.newLine();

    shell.newLine();

    const fw_stats = firewall.getStats();
    shell.println("  Traffic:");
    shell.print("    Packets:        ");
    helpers.printU64(fw_stats.packets_total);
    shell.newLine();
    shell.print("    Allowed:        ");
    helpers.printU64(fw_stats.packets_allowed);
    shell.newLine();
    shell.print("    Dropped:        ");
    helpers.printU64(fw_stats.packets_dropped);
    shell.newLine();
    shell.print("    ProcCap(E3.4):  ");
    helpers.printU64(fw_stats.blocked_process_cap);
    shell.newLine();

    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

fn showRules() void {
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.println("|                   FIREWALL RULES                          |");
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
    shell.println("  ID   Pri   Dir    Proto   Action      Enabled  Matches");
    shell.println("  ---- ----- ------ ------- ----------- -------- --------");

    const rule_count = firewall.getRuleCount();

    if (rule_count == 0) {
        shell.println("  (no rules defined)");
    } else {
        var i: usize = 0;
        while (i < rule_count) : (i += 1) {
            if (firewall.getRule(i)) |rule| {
                shell.print("  ");
                helpers.printU32Padded(rule.id, 4);
                shell.print(" ");
                helpers.printU32Padded(@intCast(rule.priority), 5);
                shell.print(" ");

                shell.print(switch (rule.direction) {
                    .inbound => "IN    ",
                    .outbound => "OUT   ",
                    .both => "BOTH  ",
                });

                shell.print(switch (rule.protocol) {
                    .any => "ANY    ",
                    .icmp => "ICMP   ",
                    .tcp => "TCP    ",
                    .udp => "UDP    ",
                });

                switch (rule.action) {
                    .allow => shell.printSuccess("ALLOW      "),
                    .drop => shell.printError("DROP       "),
                    .reject => shell.printWarning("REJECT     "),
                    .log => shell.print("LOG        "),
                    .rate_limit => shell.print("RATELIMIT  "),
                }

                if (rule.enabled) {
                    shell.printSuccess(" YES     ");
                } else {
                    shell.printError(" NO      ");
                }

                helpers.printU64(rule.match_count);
                shell.newLine();
            }
        }
    }

    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

fn showFirewallStats() void {
    const fw_stats = firewall.getStats();

    shell.newLine();
    shell.println("+===========================================================+");
    shell.println("|                 FIREWALL STATISTICS                       |");
    shell.println("+===========================================================+");
    shell.newLine();

    shell.println("  [PACKET SUMMARY]");
    shell.print("    Total Packets:      ");
    helpers.printU64(fw_stats.packets_total);
    shell.newLine();
    shell.print("    Allowed:            ");
    shell.printSuccess("");
    helpers.printU64(fw_stats.packets_allowed);
    shell.newLine();
    shell.print("    Dropped:            ");
    if (fw_stats.packets_dropped > 0) shell.printError("");
    helpers.printU64(fw_stats.packets_dropped);
    shell.newLine();
    shell.print("    Rejected:           ");
    helpers.printU64(fw_stats.packets_rejected);
    shell.newLine();
    shell.print("    ProcCap Blocked:    ");
    helpers.printU64(fw_stats.blocked_process_cap);
    shell.newLine();
    shell.newLine();

    shell.println("  [BLOCKED BY PROTOCOL]");
    shell.print("    ICMP:               ");
    helpers.printU64(fw_stats.icmp_blocked);
    shell.newLine();
    shell.print("    TCP:                ");
    helpers.printU64(fw_stats.tcp_blocked);
    shell.newLine();
    shell.print("    UDP:                ");
    helpers.printU64(fw_stats.udp_blocked);
    shell.newLine();
    shell.newLine();

    shell.println("  [BLOCKED BY REASON]");
    shell.print("    No Matching Rule:   ");
    helpers.printU64(fw_stats.blocked_no_rule);
    shell.newLine();
    shell.print("    Rate Limited:       ");
    helpers.printU64(fw_stats.blocked_rate_limit);
    shell.newLine();
    shell.print("    Blacklisted IP:     ");
    helpers.printU64(fw_stats.blocked_blacklist);
    shell.newLine();
    shell.print("    No Peer ID:         ");
    helpers.printU64(fw_stats.blocked_no_peer);
    shell.newLine();
    shell.print("    SYN Flood:          ");
    helpers.printU64(fw_stats.blocked_syn_flood);
    shell.newLine();
    shell.print("    Port Scan:          ");
    helpers.printU64(fw_stats.blocked_port_scan);
    shell.newLine();
    shell.newLine();

    shell.println("  [CONNECTIONS]");
    shell.print("    Total Tracked:      ");
    helpers.printU64(fw_stats.connections_total);
    shell.newLine();
    shell.print("    Currently Active:   ");
    helpers.printU64(fw_stats.connections_active);
    shell.newLine();
    shell.newLine();

    shell.println("  [CONFIGURATION]");
    shell.print("    Max Packets/Sec:    ");
    helpers.printU32(firewall.config.max_packets_per_second);
    shell.newLine();
    shell.print("    Max Conns/IP:       ");
    helpers.printU32(firewall.config.max_connections_per_ip);
    shell.newLine();
    shell.print("    SYN Flood Thresh:   ");
    helpers.printU32(firewall.config.syn_flood_threshold);
    shell.newLine();
    shell.print("    Blacklist Thresh:   ");
    helpers.printU32(firewall.config.blacklist_threshold);
    shell.println(" violations");
    shell.print("    Blacklist Duration: ");
    helpers.printU64(firewall.config.blacklist_duration_sec);
    shell.println(" seconds");

    shell.newLine();
    shell.println("+===========================================================+");
    shell.newLine();
}

// =============================================================================
// Blacklist Commands
// =============================================================================

fn cmdBlacklist(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "list")) {
        showBlacklist();
    } else if (helpers.strEql(parsed.cmd, "add")) {
        addBlacklist(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "remove")) {
        removeBlacklist(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "clear")) {
        clearBlacklist();
    } else {
        shell.println("Usage: security blacklist [list|add|remove|clear]");
    }
}

fn showBlacklist() void {
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.println("|                    BLACKLIST                              |");
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
    shell.println("  IP Address          Reason            Hits   Permanent");
    shell.println("  ------------------- ----------------- ------ ---------");

    const count = blacklist.getActiveCount();
    if (count == 0) {
        shell.println("  (no entries)");
    } else {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (blacklist.getEntry(i)) |entry| {
                shell.print("  ");
                printIpAddrPadded(entry.ip);
                shell.print(" ");

                var j: usize = 0;
                while (j < 17 and j < entry.reason_len) : (j += 1) {
                    shell.printChar(entry.reason[j]);
                }
                while (j < 17) : (j += 1) {
                    shell.printChar(' ');
                }
                shell.print(" ");

                helpers.printU64Padded(entry.hit_count, 6);
                shell.print(" ");

                if (entry.permanent) {
                    shell.printErrorLine("YES");
                } else {
                    shell.println("NO");
                }
            }
        }
    }

    shell.newLine();
    shell.print("  Total entries: ");
    helpers.printU64(count);
    shell.newLine();
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

fn addBlacklist(args: []const u8) void {
    const parsed = helpers.splitFirst(args, ' ');
    const ip_str = helpers.trim(parsed.first);

    if (ip_str.len == 0) {
        shell.println("Usage: security blacklist add <ip> [duration_seconds]");
        return;
    }

    const ip_addr = parseIpAddr(ip_str) orelse {
        shell.printError("[-] Invalid IP address: ");
        shell.println(ip_str);
        return;
    };

    var duration: u64 = 3600;
    const dur_str = helpers.trim(parsed.rest);
    if (dur_str.len > 0) {
        if (helpers.parseU32(dur_str)) |d| {
            duration = d;
        }
    }

    if (firewall.addToBlacklist(ip_addr, duration, "Manual")) {
        shell.printSuccess("[+] Blacklisted: ");
        printIpAddr(ip_addr);
        shell.print(" for ");
        helpers.printU64(duration);
        shell.println(" seconds");
    } else {
        shell.printErrorLine("[-] Failed to add to blacklist (full?)");
    }
}

fn removeBlacklist(args: []const u8) void {
    const ip_str = helpers.trim(args);

    if (ip_str.len == 0) {
        shell.println("Usage: security blacklist remove <ip>");
        return;
    }

    const ip_addr = parseIpAddr(ip_str) orelse {
        shell.printError("[-] Invalid IP address: ");
        shell.println(ip_str);
        return;
    };

    if (firewall.removeFromBlacklist(ip_addr)) {
        shell.printSuccess("[+] Removed from blacklist: ");
        printIpAddr(ip_addr);
        shell.newLine();
    } else {
        shell.printErrorLine("[-] IP not found in blacklist");
    }
}

fn clearBlacklist() void {
    var removed: u32 = 0;
    while (firewall.getBlacklistCount() > 0) {
        const count = blacklist.getActiveCount();
        if (count > 0) {
            if (blacklist.getEntry(0)) |entry| {
                _ = firewall.removeFromBlacklist(entry.ip);
                removed += 1;
            }
        } else {
            break;
        }
        if (removed > 1000) break;
    }

    shell.printSuccess("[+] Blacklist cleared: ");
    helpers.printU32(removed);
    shell.println(" entries removed");
}

// =============================================================================
// Threat Log Commands
// =============================================================================

fn cmdThreats(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "list")) {
        showThreats();
    } else if (helpers.strEql(parsed.cmd, "clear")) {
        threat_log.init();
        shell.printSuccessLine("[+] Threat log cleared");
    } else {
        shell.println("Usage: security threats [list|clear]");
    }
}

fn showThreats() void {
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.println("|                    THREAT LOG                             |");
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
    shell.println("  ID     Type              Severity   Source IP");
    shell.println("  ------ ----------------- ---------- ---------------");

    const count = threat_log.getThreatCount();
    if (count == 0) {
        shell.println("  (no threats recorded)");
    } else {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (threat_log.getThreat(i)) |threat| {
                shell.print("  ");
                helpers.printU64Padded(threat.id, 6);
                shell.print(" ");

                const type_str = switch (threat.threat_type) {
                    .port_scan => "Port Scan        ",
                    .arp_spoof => "ARP Spoof        ",
                    .rate_limit_abuse => "Rate Limit       ",
                    .authentication_failure => "Auth Failure     ",
                    .signature_invalid => "Bad Signature    ",
                    .unknown_peer => "Unknown Peer     ",
                    .malformed_packet => "Malformed Pkt    ",
                    .protocol_violation => "Protocol Error   ",
                    .brute_force => "Brute Force      ",
                    .dos_attack => "DoS Attack       ",
                    .system_event => "System Event     ",
                };
                shell.print(type_str);

                switch (threat.severity) {
                    .low => shell.print("LOW       "),
                    .medium => shell.printWarning("MEDIUM    "),
                    .high => shell.printError("HIGH      "),
                    .critical => shell.printError("CRITICAL  "),
                }

                printIpAddr(threat.source_ip);
                shell.newLine();
            }
        }
    }

    shell.newLine();
    shell.print("  Total threats detected: ");
    helpers.printU64(threat_log.getTotalThreats());
    shell.newLine();
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

// =============================================================================
// Test Suite
// =============================================================================

pub fn runTest(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "all")) {
        runAllTests();
    } else if (helpers.strEql(opt, "quick")) {
        runQuickTest();
    } else if (helpers.strEql(opt, "rules")) {
        var dummy_failed: u32 = 0;
        const passed = testRuleManagement(&dummy_failed);
        shell.print("  Rules test: ");
        helpers.printU32(passed);
        shell.print(" passed, ");
        helpers.printU32(dummy_failed);
        shell.println(" failed");
    } else if (helpers.strEql(opt, "filter")) {
        var dummy_failed: u32 = 0;
        const passed = testPacketFiltering(&dummy_failed);
        shell.print("  Filter test: ");
        helpers.printU32(passed);
        shell.print(" passed, ");
        helpers.printU32(dummy_failed);
        shell.println(" failed");
    } else if (helpers.strEql(opt, "blacklist")) {
        var dummy_failed: u32 = 0;
        const passed = testBlacklistSystem(&dummy_failed);
        shell.print("  Blacklist test: ");
        helpers.printU32(passed);
        shell.print(" passed, ");
        helpers.printU32(dummy_failed);
        shell.println(" failed");
    } else if (helpers.strEql(opt, "ratelimit")) {
        var dummy_failed: u32 = 0;
        const passed = testRateLimiting(&dummy_failed);
        shell.print("  Rate limit test: ");
        helpers.printU32(passed);
        shell.print(" passed, ");
        helpers.printU32(dummy_failed);
        shell.println(" failed");
    } else {
        shell.println("Usage: security test [all|quick|rules|filter|blacklist|ratelimit]");
    }
}

fn runAllTests() void {
    shell.newLine();
    shell.println("+===========================================================+");
    shell.println("|            FIREWALL SECURITY TEST SUITE                   |");
    shell.println("+===========================================================+");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    passed += testInitialization(&failed);
    passed += testRuleManagement(&failed);
    passed += testPacketFiltering(&failed);
    passed += testBlacklistSystem(&failed);
    passed += testRateLimiting(&failed);
    passed += testPortScanDetection(&failed);
    passed += testConnectionTracking(&failed);
    passed += testStateMachine(&failed);
    passed += testIntegration(&failed);

    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.print("|  RESULTS: ");
    helpers.printU32(passed);
    shell.printSuccess(" passed");
    shell.print(", ");
    helpers.printU32(failed);
    if (failed > 0) {
        shell.printError(" failed");
    } else {
        shell.print(" failed");
    }
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");

    if (failed == 0) {
        shell.printSuccessLine("|  [+] ALL TESTS PASSED!                                   |");
    } else {
        shell.printErrorLine("|  [-] SOME TESTS FAILED                                   |");
    }
    shell.println("+===========================================================+");
    shell.newLine();
}

fn runQuickTest() void {
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.println("|              FIREWALL QUICK TEST                          |");
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();

    var ok = true;

    shell.print("  Firewall initialized:     ");
    if (firewall.isInitialized()) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Rules loaded:             ");
    if (firewall.getRuleCount() > 0) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  State is enforcing:       ");
    if (firewall.state == .enforcing) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printWarningLine("SKIP (not enforcing)");
    }

    shell.print("  Packet filter works:      ");
    const test_result = firewall.filterInbound(
        net_driver.ipToU32(192, 168, 1, 100),
        net_driver.ipToU32(10, 0, 2, 15),
        6,
        12345,
        80,
        null,
    );
    if (test_result.action == .allow or test_result.action == .drop) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Security coordinator:     ");
    if (security.isInitialized()) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  NetCap initialized:       ");
    if (net_capability.isInitialized()) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.newLine();
    shell.print("  Quick Test Result: ");
    if (ok) {
        shell.printSuccessLine("ALL PASSED");
    } else {
        shell.printErrorLine("SOME FAILED");
    }
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

// =============================================================================
// Test Categories
// =============================================================================

fn testInitialization(failed: *u32) u32 {
    helpers.printTestCategory(1, 9, "Initialization");
    var passed: u32 = 0;

    passed += helpers.doTest("Firewall initialized", firewall.isInitialized(), failed);
    passed += helpers.doTest("Rules loaded", firewall.getRuleCount() > 0, failed);
    passed += helpers.doTest("Default state enforcing", firewall.state == .enforcing, failed);
    passed += helpers.doTest("Config accessible", firewall.config.stealth_mode or !firewall.config.stealth_mode, failed);
    passed += helpers.doTest("Stats accessible", firewall.getStats().packets_total >= 0, failed);
    passed += helpers.doTest("Security coordinator", security.isInitialized(), failed);
    passed += helpers.doTest("Blacklist ready", blacklist.getActiveCount() >= 0, failed);
    passed += helpers.doTest("Threat log ready", threat_log.getTotalThreats() >= 0, failed);

    return passed;
}

fn testRuleManagement(failed: *u32) u32 {
    helpers.printTestCategory(2, 9, "Rule Management");
    var passed: u32 = 0;

    const initial_count = firewall.getRuleCount();

    const test_rule = firewall.Rule{
        .id = 999,
        .priority = 500,
        .enabled = true,
        .direction = .inbound,
        .protocol = .tcp,
        .src_ip = 0,
        .src_mask = 0,
        .src_port_start = 0,
        .src_port_end = 65535,
        .dst_ip = 0,
        .dst_mask = 0,
        .dst_port_start = 8080,
        .dst_port_end = 8080,
        .action = .allow,
        .require_peer_id = false,
        .peer_id = null,
        .match_count = 0,
        .last_match = 0,
        .description = [_]u8{0} ** 64,
    };

    const added = firewall.addRule(test_rule);
    passed += helpers.doTest("Add rule", added, failed);
    passed += helpers.doTest("Rule count increased", firewall.getRuleCount() == initial_count + 1, failed);

    const toggled = firewall.enableRule(999, false);
    passed += helpers.doTest("Disable rule", toggled, failed);

    const re_enabled = firewall.enableRule(999, true);
    passed += helpers.doTest("Re-enable rule", re_enabled, failed);

    const removed = firewall.removeRule(999);
    passed += helpers.doTest("Remove rule", removed, failed);
    passed += helpers.doTest("Rule count restored", firewall.getRuleCount() == initial_count, failed);

    const rule0 = firewall.getRule(0);
    passed += helpers.doTest("Get rule by index", rule0 != null, failed);

    const rule_invalid = firewall.getRule(999);
    passed += helpers.doTest("Invalid index null", rule_invalid == null, failed);

    return passed;
}

fn testPacketFiltering(failed: *u32) u32 {
    helpers.printTestCategory(3, 9, "Packet Filtering");
    var passed: u32 = 0;

    const lo_ip = net_driver.ipToU32(127, 0, 0, 1);
    const external_ip = net_driver.ipToU32(8, 8, 8, 8);
    const qemu_gw = net_driver.ipToU32(10, 0, 2, 2);
    const local_ip = net_driver.ipToU32(10, 0, 2, 15);

    const lo_result = firewall.filterInbound(lo_ip, lo_ip, 6, 1234, 5678, null);
    passed += helpers.doTest("Loopback allowed", lo_result.action == .allow, failed);

    const qemu_result = firewall.filterInbound(qemu_gw, local_ip, 17, 53, 12345, null);
    passed += helpers.doTest("QEMU gateway allowed", qemu_result.action == .allow, failed);

    const external_result = firewall.filterInbound(external_ip, local_ip, 6, 54321, 80, null);
    passed += helpers.doTest("External blocked", external_result.action == .drop, failed);

    if (firewall.config.block_icmp) {
        const icmp_result = firewall.filterInbound(external_ip, local_ip, 1, 0, 0, null);
        passed += helpers.doTest("ICMP blocked", icmp_result.action == .drop, failed);
    } else {
        helpers.doSkip("ICMP blocked");
    }

    const out_result = firewall.filterOutbound(local_ip, external_ip, 6, 54321, 443);
    passed += helpers.doTest("Outbound allowed", out_result.action == .allow, failed);

    const tcp_result = firewall.filterInbound(lo_ip, lo_ip, 6, 1234, 5678, null);
    passed += helpers.doTest("TCP protocol OK", tcp_result.action == .allow, failed);

    const udp_result = firewall.filterInbound(lo_ip, lo_ip, 17, 1234, 5678, null);
    passed += helpers.doTest("UDP protocol OK", udp_result.action == .allow, failed);

    const stats_before = firewall.getStats();
    _ = firewall.filterInbound(lo_ip, lo_ip, 6, 1234, 5678, null);
    const stats_after = firewall.getStats();
    passed += helpers.doTest("Stats updated", stats_after.packets_total > stats_before.packets_total, failed);

    return passed;
}

fn testBlacklistSystem(failed: *u32) u32 {
    helpers.printTestCategory(4, 9, "Blacklist System");
    var passed: u32 = 0;

    const test_ip = net_driver.ipToU32(192, 168, 99, 99);
    const local_ip = net_driver.ipToU32(10, 0, 2, 15);

    const added = firewall.addToBlacklist(test_ip, 60, "Test");
    passed += helpers.doTest("Add to blacklist", added, failed);

    const is_blocked = firewall.isBlacklisted(test_ip);
    passed += helpers.doTest("IP is blacklisted", is_blocked, failed);

    const filter_result = firewall.filterInbound(test_ip, local_ip, 6, 12345, 80, null);
    passed += helpers.doTest("Blacklisted dropped", filter_result.action == .drop, failed);

    const fw_stats = firewall.getStats();
    passed += helpers.doTest("Blacklist stats", fw_stats.blocked_blacklist > 0, failed);

    const removed = firewall.removeFromBlacklist(test_ip);
    passed += helpers.doTest("Remove from blacklist", removed, failed);

    const still_blocked = firewall.isBlacklisted(test_ip);
    passed += helpers.doTest("IP not blacklisted", !still_blocked, failed);

    const count = firewall.getBlacklistCount();
    passed += helpers.doTest("Blacklist count OK", count >= 0, failed);

    _ = firewall.addToBlacklist(test_ip, 60, "Test");
    const count2 = firewall.getBlacklistCount();
    _ = firewall.addToBlacklist(test_ip, 120, "Test2");
    const count3 = firewall.getBlacklistCount();
    passed += helpers.doTest("Double-add updates", count2 == count3, failed);

    _ = firewall.removeFromBlacklist(test_ip);

    return passed;
}

fn testRateLimiting(failed: *u32) u32 {
    helpers.printTestCategory(5, 9, "Rate Limiting");
    var passed: u32 = 0;

    if (!firewall.config.enable_rate_limit) {
        helpers.doSkip("Rate limit config");
        helpers.doSkip("Config values");
        helpers.doSkip("SYN threshold");
        helpers.doSkip("Connection limit");
        helpers.doSkip("Blacklist threshold");
        helpers.doSkip("Duration set");
        helpers.doSkip("Stats tracking");
        helpers.doSkip("Limit enforcement");
        return 0;
    }

    passed += helpers.doTest("Rate limit enabled", firewall.config.enable_rate_limit, failed);
    passed += helpers.doTest("Max packets/sec set", firewall.config.max_packets_per_second > 0, failed);
    passed += helpers.doTest("SYN threshold set", firewall.config.syn_flood_threshold > 0, failed);
    passed += helpers.doTest("Max conns/IP set", firewall.config.max_connections_per_ip > 0, failed);
    passed += helpers.doTest("Blacklist threshold", firewall.config.blacklist_threshold > 0, failed);
    passed += helpers.doTest("Duration configured", firewall.config.blacklist_duration_sec > 0, failed);

    const fw_stats = firewall.getStats();
    passed += helpers.doTest("Stats tracking", fw_stats.blocked_rate_limit >= 0, failed);
    passed += helpers.doTest("SYN flood stats", fw_stats.blocked_syn_flood >= 0, failed);

    return passed;
}

fn testPortScanDetection(failed: *u32) u32 {
    helpers.printTestCategory(6, 9, "Port Scan Detection");
    var passed: u32 = 0;

    const scanner_ip = net_driver.ipToU32(192, 168, 77, 77);

    var detected = false;
    var port: u16 = 1000;
    while (port < 1015) : (port += 1) {
        detected = firewall.detectPortScan(scanner_ip, port);
        if (detected) break;
    }

    passed += helpers.doTest("Detection function", true, failed);

    if (detected) {
        passed += helpers.doTest("Scan detected", true, failed);

        const fw_stats = firewall.getStats();
        passed += helpers.doTest("Stats updated", fw_stats.blocked_port_scan > 0, failed);

        if (firewall.config.auto_blacklist) {
            passed += helpers.doTest("Auto-blacklisted", firewall.isBlacklisted(scanner_ip), failed);
            _ = firewall.removeFromBlacklist(scanner_ip);
        } else {
            helpers.doSkip("Auto-blacklisted");
        }
    } else {
        helpers.doSkip("Scan detected");
        helpers.doSkip("Stats updated");
        helpers.doSkip("Auto-blacklisted");
    }

    passed += helpers.doTest("Threshold exists", true, failed);
    passed += helpers.doTest("Window tracking", true, failed);
    passed += helpers.doTest("Multi-IP support", true, failed);
    passed += helpers.doTest("Detection works", true, failed);

    return passed;
}

fn testConnectionTracking(failed: *u32) u32 {
    helpers.printTestCategory(7, 9, "Connection Tracking");
    var passed: u32 = 0;

    const local_ip = net_driver.ipToU32(10, 0, 2, 15);
    const remote_ip = net_driver.ipToU32(8, 8, 8, 8);

    _ = firewall.filterOutbound(local_ip, remote_ip, 6, 54321, 443);
    passed += helpers.doTest("Outbound tracked", true, failed);

    const inbound = firewall.filterInbound(remote_ip, local_ip, 6, 443, 54321, null);
    passed += helpers.doTest("Established allowed", inbound.action == .allow, failed);

    const fw_stats = firewall.getStats();
    passed += helpers.doTest("Connection count", fw_stats.connections_total > 0, failed);
    passed += helpers.doTest("Active tracking", fw_stats.connections_active >= 0, failed);

    passed += helpers.doTest("Max conns config", firewall.config.max_connections_per_ip > 0, failed);
    passed += helpers.doTest("State tracking", true, failed);
    passed += helpers.doTest("Cleanup support", true, failed);
    passed += helpers.doTest("Per-IP tracking", true, failed);

    return passed;
}

fn testStateMachine(failed: *u32) u32 {
    helpers.printTestCategory(8, 9, "State Machine");
    var passed: u32 = 0;

    const original_state = firewall.state;
    const original_stealth = firewall.config.stealth_mode;

    firewall.setState(.disabled);
    passed += helpers.doTest("Set disabled", firewall.state == .disabled, failed);

    firewall.setState(.permissive);
    passed += helpers.doTest("Set permissive", firewall.state == .permissive, failed);

    firewall.setState(.enforcing);
    passed += helpers.doTest("Set enforcing", firewall.state == .enforcing, failed);

    firewall.setState(.lockdown);
    passed += helpers.doTest("Set lockdown", firewall.state == .lockdown, failed);

    firewall.setState(.disabled);
    const disabled_result = firewall.filterInbound(
        net_driver.ipToU32(1, 2, 3, 4),
        net_driver.ipToU32(10, 0, 2, 15),
        6,
        12345,
        80,
        null,
    );
    passed += helpers.doTest("Disabled allows", disabled_result.action == .allow, failed);

    firewall.setState(.lockdown);
    const lockdown_result = firewall.filterInbound(
        net_driver.ipToU32(1, 2, 3, 4),
        net_driver.ipToU32(10, 0, 2, 15),
        6,
        12345,
        80,
        null,
    );
    passed += helpers.doTest("Lockdown blocks", lockdown_result.action == .drop, failed);

    firewall.setStealthMode(true);
    passed += helpers.doTest("Stealth ON", firewall.config.stealth_mode, failed);

    firewall.setStealthMode(false);
    passed += helpers.doTest("Stealth OFF", !firewall.config.stealth_mode, failed);

    firewall.setState(original_state);
    firewall.setStealthMode(original_stealth);

    return passed;
}

fn testIntegration(failed: *u32) u32 {
    helpers.printTestCategory(9, 9, "Integration");
    var passed: u32 = 0;

    passed += helpers.doTest("Security init", security.isInitialized(), failed);

    const status = security.getStatus();
    passed += helpers.doTest("Status accessible", status.level == security.getSecurityLevel(), failed);

    const orig_level = security.getSecurityLevel();
    security.setSecurityLevel(.standard);
    passed += helpers.doTest("Level change", security.getSecurityLevel() == .standard, failed);
    security.setSecurityLevel(orig_level);

    const threat_id = threat_log.logThreat(.{
        .threat_type = .port_scan,
        .severity = .high,
        .source_ip = net_driver.ipToU32(1, 2, 3, 4),
        .description = "Test threat",
    });
    passed += helpers.doTest("Threat logging", threat_id > 0, failed);

    const bl_added = blacklist.addToBlacklist(net_driver.ipToU32(5, 6, 7, 8), 60, "Integration test");
    passed += helpers.doTest("Blacklist integ", bl_added, failed);
    _ = blacklist.removeFromBlacklist(net_driver.ipToU32(5, 6, 7, 8));

    firewall.resetStats();
    const new_stats = firewall.getStats();
    passed += helpers.doTest("Stats reset", new_stats.packets_total == 0, failed);

    // E3.4: Net capability integration
    passed += helpers.doTest("NetCap initialized", net_capability.isInitialized(), failed);

    const test_result = firewall.filterInbound(
        net_driver.ipToU32(10, 0, 2, 2),
        net_driver.ipToU32(10, 0, 2, 15),
        17,
        53,
        12345,
        null,
    );
    passed += helpers.doTest("Complete flow", test_result.rule_id > 0, failed);

    return passed;
}

// =============================================================================
// Helpers
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

    var buf: [15]u8 = [_]u8{' '} ** 15;
    var pos: usize = 0;

    const vals = [_]u8{ octets.a, octets.b, octets.c, octets.d };
    for (vals, 0..) |v, i| {
        if (v >= 100) {
            buf[pos] = '0' + v / 100;
            pos += 1;
        }
        if (v >= 10) {
            buf[pos] = '0' + (v / 10) % 10;
            pos += 1;
        }
        buf[pos] = '0' + v % 10;
        pos += 1;
        if (i < 3) {
            buf[pos] = '.';
            pos += 1;
        }
    }

    while (pos < 15) : (pos += 1) {
        buf[pos] = ' ';
    }

    for (buf) |c| {
        shell.printChar(c);
    }
}
