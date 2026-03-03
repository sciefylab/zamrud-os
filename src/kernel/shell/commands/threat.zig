//! Zamrud OS - H.8 Threat Scoring Commands
//! Delegated from security.zig for modularity

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");

// H.8: Threat Scoring
const threat_score = @import("../../security/threat_score.zig");
const threat_log = @import("../../security/threat_log.zig");
const net_driver = @import("../../drivers/network/network.zig");

// =============================================================================
// Main Entry Point (called from security.zig)
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        showStatus();
    } else if (helpers.strEql(parsed.cmd, "top")) {
        showTopThreats();
    } else if (helpers.strEql(parsed.cmd, "thresholds")) {
        showThresholds();
    } else if (helpers.strEql(parsed.cmd, "reset")) {
        resetScore(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "remove")) {
        removeEntry(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "decay")) {
        threat_score.forceDecay();
        shell.printSuccessLine("[+] Forced score decay cycle");
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest();
    } else if (helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else {
        // Assume it's an IP address
        showScoreForIP(parsed.cmd);
    }
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.println("|          H.8 THREAT SCORING COMMANDS                      |");
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
    shell.println("  USAGE: security score <command> [options]");
    shell.newLine();
    shell.println("  COMMANDS:");
    shell.println("    status        Show threat scoring engine status");
    shell.println("    top           Display top threats by score (0-100)");
    shell.println("    <ip>          Show score for specific IP address");
    shell.println("    reset <ip>    Reset score for IP (forgive)");
    shell.println("    remove <ip>   Remove IP from tracking entirely");
    shell.println("    thresholds    Show auto-response thresholds");
    shell.println("    decay         Force score decay cycle");
    shell.println("    test          Run H.8 test suite");
    shell.println("    help          Show this help");
    shell.newLine();
    shell.println("  EXAMPLES:");
    shell.println("    security score status");
    shell.println("    security score top");
    shell.println("    security score 192.168.1.100");
    shell.println("    security score reset 10.0.2.50");
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

// =============================================================================
// Status
// =============================================================================

fn showStatus() void {
    if (!threat_score.isInitialized()) {
        threat_score.init();
    }

    shell.newLine();
    shell.println("+===========================================================+");
    shell.println("|          H.8 THREAT SCORING ENGINE STATUS                 |");
    shell.println("+===========================================================+");
    shell.newLine();

    const ts_stats = threat_score.getStats();

    shell.println("  [ENGINE STATUS]");
    shell.print("    Initialized:    ");
    if (threat_score.isInitialized()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printErrorLine("NO");
    }
    shell.print("    Active IPs:     ");
    helpers.printU32(ts_stats.current_ips_active);
    shell.newLine();
    shell.print("    Total Tracked:  ");
    helpers.printU64(ts_stats.total_ips_tracked);
    shell.newLine();
    shell.newLine();

    shell.println("  [EVENT STATISTICS]");
    shell.print("    Total Events:   ");
    helpers.printU64(ts_stats.total_events);
    shell.newLine();
    shell.print("    Port Scans:     ");
    helpers.printU64(ts_stats.port_scan_events);
    shell.newLine();
    shell.print("    Rate Limits:    ");
    helpers.printU64(ts_stats.rate_limit_events);
    shell.newLine();
    shell.print("    Auth Failures:  ");
    helpers.printU64(ts_stats.auth_failure_events);
    shell.newLine();
    shell.print("    ARP Spoofs:     ");
    helpers.printU64(ts_stats.arp_spoof_events);
    shell.newLine();
    shell.print("    DoS Events:     ");
    helpers.printU64(ts_stats.dos_events);
    shell.newLine();
    shell.print("    Other Events:   ");
    helpers.printU64(ts_stats.other_events);
    shell.newLine();
    shell.newLine();

    shell.println("  [AUTO-RESPONSE STATS]");
    shell.print("    Warnings:       ");
    helpers.printU64(ts_stats.warnings_issued);
    shell.newLine();
    shell.print("    Rate Limits:    ");
    helpers.printU64(ts_stats.rate_limits_applied);
    shell.newLine();
    shell.print("    Temp Bans:      ");
    helpers.printU64(ts_stats.temp_blacklists);
    shell.newLine();
    shell.print("    Perm Bans:      ");
    helpers.printU64(ts_stats.perm_blacklists);
    shell.newLine();
    shell.print("    Lockdowns:      ");
    helpers.printU64(ts_stats.lockdowns_triggered);
    shell.newLine();
    shell.newLine();

    shell.println("  [DECAY STATISTICS]");
    shell.print("    Decay Cycles:   ");
    helpers.printU64(ts_stats.decay_cycles);
    shell.newLine();
    shell.print("    Points Decayed: ");
    helpers.printU64(ts_stats.points_decayed);
    shell.newLine();
    shell.newLine();

    shell.println("  [PEAK TRACKING]");
    shell.print("    Highest Score:  ");
    helpers.printU32(ts_stats.highest_score_seen);
    if (ts_stats.highest_score_seen > 0) {
        shell.print(" (");
        printIpAddr(ts_stats.highest_score_ip);
        shell.print(")");
    }
    shell.newLine();

    shell.newLine();
    shell.println("+===========================================================+");
    shell.newLine();
}

// =============================================================================
// Top Threats
// =============================================================================

fn showTopThreats() void {
    if (!threat_score.isInitialized()) {
        threat_score.init();
    }

    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.println("|                   TOP THREATS BY SCORE                    |");
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
    shell.println("  IP ADDRESS         SCORE  LEVEL      STATUS");
    shell.println("  ------------------- ----- ---------- ------------------");

    var top: [10]threat_score.ThreatSummary = undefined;
    const count = threat_score.getTopThreats(&top);

    if (count == 0) {
        shell.println("  (no active threats)");
    } else {
        for (0..count) |i| {
            shell.print("  ");
            printIpAddrPadded(top[i].ip);
            shell.print(" ");
            helpers.printU32Padded(top[i].score, 5);
            shell.print(" ");

            const level = threat_score.getLevel(top[i].ip);
            switch (level) {
                .normal => shell.print("NORMAL    "),
                .elevated => shell.printWarning("ELEVATED  "),
                .warning => shell.printWarning("WARNING   "),
                .high => shell.printError("HIGH      "),
                .critical => shell.printError("CRITICAL  "),
                .maximum => shell.printError("MAXIMUM   "),
            }

            // Show status flags
            if (threat_score.getEntryByIndex(i)) |entry| {
                if (entry.perm_blacklisted) {
                    shell.printError("PERM-BANNED");
                } else if (entry.temp_blacklisted) {
                    shell.printWarning("TEMP-BANNED");
                } else if (entry.rate_limited) {
                    shell.print("Rate-Limited");
                } else if (entry.warned) {
                    shell.print("Warned");
                } else {
                    shell.print("-");
                }
            }
            shell.newLine();
        }
    }

    shell.newLine();
    shell.print("  Active threats: ");
    helpers.printU32(threat_score.getActiveCount());
    shell.newLine();
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

// =============================================================================
// Thresholds
// =============================================================================

fn showThresholds() void {
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.println("|             THREAT SCORE THRESHOLDS                       |");
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
    shell.println("  LEVEL      SCORE RANGE   AUTO-RESPONSE");
    shell.println("  ---------- ------------- -----------------------------");
    shell.printSuccess("  NORMAL     ");
    shell.println("0-19          (none)");
    shell.printWarning("  ELEVATED   ");
    shell.println("20-39         Log warning");
    shell.printWarning("  WARNING    ");
    shell.println("40-59         Apply rate limiting");
    shell.printError("  HIGH       ");
    shell.println("60-79         Temporary blacklist (1 hour)");
    shell.printError("  CRITICAL   ");
    shell.println("80-99         Permanent blacklist (7 days)");
    shell.printError("  MAXIMUM    ");
    shell.println("100           Emergency lockdown trigger");
    shell.newLine();

    shell.println("  EVENT WEIGHTS:");
    shell.println("    DoS Attack:      +35 points");
    shell.println("    ARP Spoof:       +30 points");
    shell.println("    Port Scan:       +25 points");
    shell.println("    Brute Force:     +20 points");
    shell.println("    Bad Signature:   +20 points");
    shell.println("    Auth Failure:    +15 points");
    shell.println("    Unknown Peer:    +12 points");
    shell.println("    Rate Violation:  +10 points");
    shell.println("    Malformed Pkt:   +8 points");
    shell.println("    Protocol Error:  +5 points");
    shell.newLine();

    shell.println("  SEVERITY MULTIPLIERS:");
    shell.println("    Low:      x1");
    shell.println("    Medium:   x2");
    shell.println("    High:     x3");
    shell.println("    Critical: x5");
    shell.newLine();

    shell.println("  DECAY: -1 point per minute (after 5 min idle)");
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

// =============================================================================
// Show Score for IP
// =============================================================================

fn showScoreForIP(ip_str: []const u8) void {
    const ip_addr = parseIpAddr(ip_str) orelse {
        shell.printError("[-] Invalid IP address: ");
        shell.println(ip_str);
        shell.println("    Use format: x.x.x.x (e.g., 192.168.1.100)");
        return;
    };

    if (!threat_score.isInitialized()) {
        threat_score.init();
    }

    const score = threat_score.getScore(ip_addr);
    const level = threat_score.getLevel(ip_addr);

    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.print("|  THREAT SCORE: ");
    printIpAddr(ip_addr);
    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();

    shell.print("  Score:       ");
    if (score >= 60) {
        shell.printError("");
    } else if (score >= 20) {
        shell.printWarning("");
    } else {
        shell.printSuccess("");
    }
    helpers.printU32(score);
    shell.print("/100");
    shell.newLine();

    shell.print("  Level:       ");
    switch (level) {
        .normal => shell.printSuccessLine("NORMAL"),
        .elevated => shell.printWarningLine("ELEVATED"),
        .warning => shell.printWarningLine("WARNING"),
        .high => shell.printErrorLine("HIGH"),
        .critical => shell.printErrorLine("CRITICAL"),
        .maximum => shell.printErrorLine("MAXIMUM"),
    }

    // Show detailed info if entry exists
    var found = false;
    var idx: usize = 0;
    while (idx < 256) : (idx += 1) {
        if (threat_score.getEntryByIndex(idx)) |entry| {
            if (entry.ip == ip_addr) {
                found = true;
                shell.newLine();
                shell.println("  [EVENT COUNTS]");
                shell.print("    Port Scans:      ");
                helpers.printU32(entry.port_scans);
                shell.newLine();
                shell.print("    Rate Violations: ");
                helpers.printU32(entry.rate_violations);
                shell.newLine();
                shell.print("    Auth Failures:   ");
                helpers.printU32(entry.auth_failures);
                shell.newLine();
                shell.print("    ARP Spoofs:      ");
                helpers.printU32(entry.arp_spoofs);
                shell.newLine();
                shell.print("    DoS Events:      ");
                helpers.printU32(entry.dos_events);
                shell.newLine();
                shell.print("    Protocol Errors: ");
                helpers.printU32(entry.protocol_errors);
                shell.newLine();
                shell.print("    Brute Force:     ");
                helpers.printU32(entry.brute_force_attempts);
                shell.newLine();
                shell.newLine();

                shell.println("  [STATUS FLAGS]");
                shell.print("    Warned:          ");
                if (entry.warned) shell.printWarningLine("YES") else shell.println("NO");
                shell.print("    Rate Limited:    ");
                if (entry.rate_limited) shell.printWarningLine("YES") else shell.println("NO");
                shell.print("    Temp Blacklist:  ");
                if (entry.temp_blacklisted) shell.printErrorLine("YES") else shell.println("NO");
                shell.print("    Perm Blacklist:  ");
                if (entry.perm_blacklisted) shell.printErrorLine("YES") else shell.println("NO");
                shell.print("    Lockdown Trig:   ");
                if (entry.lockdown_triggered) shell.printErrorLine("YES") else shell.println("NO");

                if (entry.pid_count > 0) {
                    shell.newLine();
                    shell.println("  [ASSOCIATED PROCESSES]");
                    shell.print("    PIDs:            ");
                    var p: usize = 0;
                    while (p < entry.pid_count) : (p += 1) {
                        helpers.printU32(entry.associated_pids[p]);
                        if (p < entry.pid_count - 1) shell.print(", ");
                    }
                    shell.newLine();
                }

                break;
            }
        } else {
            break;
        }
    }

    if (!found and score == 0) {
        shell.newLine();
        shell.printInfo("  (IP not tracked - no threat events recorded)");
        shell.newLine();
    }

    shell.newLine();
    shell.println("+-----------------------------------------------------------+");
    shell.newLine();
}

// =============================================================================
// Reset Score
// =============================================================================

fn resetScore(args: []const u8) void {
    const ip_str = helpers.trim(args);

    if (ip_str.len == 0) {
        shell.println("Usage: security score reset <ip>");
        shell.println("       Resets threat score to 0 (forgive IP)");
        return;
    }

    const ip_addr = parseIpAddr(ip_str) orelse {
        shell.printError("[-] Invalid IP address: ");
        shell.println(ip_str);
        return;
    };

    const old_score = threat_score.getScore(ip_addr);

    if (threat_score.resetScore(ip_addr)) {
        shell.printSuccess("[+] Score reset: ");
        printIpAddr(ip_addr);
        shell.print(" (was ");
        helpers.printU32(old_score);
        shell.println(", now 0)");
    } else {
        shell.printWarning("[!] IP not found in threat tracking: ");
        printIpAddr(ip_addr);
        shell.newLine();
    }
}

// =============================================================================
// Remove Entry
// =============================================================================

fn removeEntry(args: []const u8) void {
    const ip_str = helpers.trim(args);

    if (ip_str.len == 0) {
        shell.println("Usage: security score remove <ip>");
        shell.println("       Completely removes IP from tracking");
        return;
    }

    const ip_addr = parseIpAddr(ip_str) orelse {
        shell.printError("[-] Invalid IP address: ");
        shell.println(ip_str);
        return;
    };

    if (threat_score.removeEntry(ip_addr)) {
        shell.printSuccess("[+] Removed from tracking: ");
        printIpAddr(ip_addr);
        shell.newLine();
    } else {
        shell.printWarning("[!] IP not found in threat tracking: ");
        printIpAddr(ip_addr);
        shell.newLine();
    }
}

// =============================================================================
// Test
// =============================================================================

pub fn runTest() void {
    shell.newLine();
    shell.println("+===========================================================+");
    shell.println("|           H.8 THREAT SCORING TEST SUITE                   |");
    shell.println("+===========================================================+");
    shell.newLine();

    const result = threat_score.runTests();

    shell.newLine();
    if (result) {
        shell.printSuccessLine("|  [+] ALL H.8 TESTS PASSED!                              |");
    } else {
        shell.printErrorLine("|  [-] SOME H.8 TESTS FAILED                               |");
    }
    shell.println("+===========================================================+");
    shell.newLine();
}

// =============================================================================
// Summary for security status
// =============================================================================

pub fn printSummary() void {
    if (!threat_score.isInitialized()) {
        shell.println("    Not initialized");
        return;
    }

    const ts_stats = threat_score.getStats();

    shell.print("    Active IPs:     ");
    helpers.printU32(ts_stats.current_ips_active);
    shell.newLine();

    shell.print("    Total Events:   ");
    helpers.printU64(ts_stats.total_events);
    shell.newLine();

    shell.print("    Highest Score:  ");
    helpers.printU32(ts_stats.highest_score_seen);
    if (ts_stats.highest_score_seen > 0) {
        shell.print(" (");
        printIpAddr(ts_stats.highest_score_ip);
        shell.print(")");
    }
    shell.newLine();

    shell.print("    Auto-Bans:      ");
    helpers.printU64(ts_stats.temp_blacklists + ts_stats.perm_blacklists);
    shell.newLine();

    shell.print("    Lockdowns:      ");
    helpers.printU64(ts_stats.lockdowns_triggered);
    shell.newLine();
}

// =============================================================================
// IP Address Helpers
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
            if (cur > 255) return null;
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
