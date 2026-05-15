//! Zamrud OS - ELF Process Execution (F5.2 & E3.6)
//! Creates and runs processes from loaded ELF binaries
//! 🆕 E3.6: Strict Production checking, Physical Proof of Presence, & Session-Bound Dev Trust

const serial = @import("../drivers/serial/serial.zig");
const process = @import("../proc/process.zig");
const scheduler = @import("../proc/scheduler.zig");
const capability = @import("../security/capability.zig");
const binaryverify = @import("../security/binaryverify.zig");
const violation = @import("../security/violation.zig");
const zam_header = @import("zam_header.zig");
const elf_parser = @import("elf_parser.zig");
const segment_loader = @import("segment_loader.zig");
const loader = @import("loader.zig");

const config = @import("config");
const terminal = @import("../drivers/display/terminal.zig");
const keyboard = @import("../drivers/input/keyboard.zig");
const ct = @import("../crypto/constant_time.zig"); // Untuk komparasi key

// ============================================================================
// Constants & Error Types
// ============================================================================

pub const MAX_ELF_PROCESSES: usize = 16;
pub const MAX_TRUSTED_DEV_SESSIONS: usize = 4; // Maksimal DevKey yang di-Auto-Run dalam 1 sesi

pub const ExecError = enum(u8) {
    None = 0,
    ParseFailed = 1,
    VerifyFailed = 2,
    LoadFailed = 3,
    ProcessCreateFailed = 4,
    CapabilityDenied = 5,
    TooManyProcesses = 6,
    InvalidEntry = 7,
    NotInitialized = 8,
    ProductionLockdown = 9,
};

pub fn execErrorName(err: ExecError) []const u8 {
    return switch (err) {
        .None => "None",
        .ParseFailed => "ParseFailed",
        .VerifyFailed => "VerifyFailed",
        .LoadFailed => "LoadFailed",
        .ProcessCreateFailed => "ProcessCreateFailed",
        .CapabilityDenied => "CapabilityDenied",
        .TooManyProcesses => "TooManyProcesses",
        .InvalidEntry => "InvalidEntry",
        .NotInitialized => "NotInitialized",
        .ProductionLockdown => "ProductionLockdown",
    };
}

// ============================================================================
// ELF Process tracking
// ============================================================================

pub const ElfProcess = struct {
    pid: u32,
    load_result: segment_loader.LoadResult,
    entry_point: u64,
    caps_granted: u32,
    trust_level: u8,
    active: bool,
    name: [32]u8,
    name_len: u8,

    pub fn init() ElfProcess {
        return ElfProcess{
            .pid = 0,
            .load_result = segment_loader.LoadResult.init(),
            .entry_point = 0,
            .caps_granted = capability.CAP_NONE,
            .trust_level = 0,
            .active = false,
            .name = [_]u8{0} ** 32,
            .name_len = 0,
        };
    }

    pub fn getName(self: *const ElfProcess) []const u8 {
        if (self.name_len == 0) return "elf_proc";
        return self.name[0..self.name_len];
    }
};

var elf_processes: [MAX_ELF_PROCESSES]ElfProcess = undefined;
var elf_proc_count: usize = 0;
var initialized: bool = false;

// 🆕 Tabel Sesi Auto-Run untuk DevKey
var trusted_dev_keys: [MAX_TRUSTED_DEV_SESSIONS][zam_header.PUBKEY_SIZE]u8 = undefined;
var trusted_dev_active: [MAX_TRUSTED_DEV_SESSIONS]bool = [_]bool{false} ** MAX_TRUSTED_DEV_SESSIONS;

pub fn init() void {
    serial.writeString("[ELFEXEC] Initializing ELF executor...\n");

    var i: usize = 0;
    while (i < MAX_ELF_PROCESSES) : (i += 1) {
        elf_processes[i] = ElfProcess.init();
    }

    // Bersihkan sesi DevKey
    i = 0;
    while (i < MAX_TRUSTED_DEV_SESSIONS) : (i += 1) {
        trusted_dev_active[i] = false;
    }

    elf_proc_count = 0;
    initialized = true;

    serial.writeString("[ELFEXEC] ELF executor ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// 🆕 E3.6: Session-Bound Dev Trust (Auto-Run Cache)
// ============================================================================

fn isDevKeyAutoTrusted(pubkey: *const [zam_header.PUBKEY_SIZE]u8) bool {
    var i: usize = 0;
    while (i < MAX_TRUSTED_DEV_SESSIONS) : (i += 1) {
        if (trusted_dev_active[i]) {
            // Kita asumsikan ada fungsi constant_time komparasi, atau bandingkan manual
            var match = true;
            var j: usize = 0;
            while (j < zam_header.PUBKEY_SIZE) : (j += 1) {
                if (trusted_dev_keys[i][j] != pubkey[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

fn addDevKeyToAutoTrust(pubkey: *const [zam_header.PUBKEY_SIZE]u8) void {
    var i: usize = 0;
    while (i < MAX_TRUSTED_DEV_SESSIONS) : (i += 1) {
        if (!trusted_dev_active[i]) {
            var j: usize = 0;
            while (j < zam_header.PUBKEY_SIZE) : (j += 1) {
                trusted_dev_keys[i][j] = pubkey[j];
            }
            trusted_dev_active[i] = true;
            serial.writeString("[SECURITY] DevKey added to Session Auto-Run Cache.\n");
            return;
        }
    }
    serial.writeString("[SECURITY] Warning: DevKey Session Cache is full!\n");
}

// ============================================================================
// 🆕 E3.6: Physical Approval (Proof of Presence)
// ============================================================================

/// Meminta input fisik dari user, menawarkan fitur Auto-Run Sesi
fn requestPhysicalApproval(zam: *const zam_header.ZamHeader, app_name: []const u8, requested_caps: u32) bool {
    // 1. Cek apakah kunci ini sudah di-Allow untuk sesi ini
    if (isDevKeyAutoTrusted(&zam.signer_pubkey)) {
        serial.writeString("[SECURITY] DevKey is in Auto-Run Session. Bypassing physical prompt.\n");
        return true;
    }

    serial.writeString("\n[SECURITY] Awaiting physical approval for DevKey execution...\n");

    if (terminal.isInitialized()) {
        terminal.setFgColor(0xFFAA00); // Kuning Peringatan
        terminal.println("\n==============================================");
        terminal.println(" ZAMRUD SECURITY: DEV-KEY EXECUTION ATTEMPT");
        terminal.println("==============================================");
        terminal.setFgColor(0xFFFFFF);

        terminal.print(" App Name : ");
        terminal.println(app_name);
        terminal.print(" Caps Req : 0x");
        printHex32ToTerminal(requested_caps);
        terminal.println("");

        terminal.println("\n This binary is signed with an untrusted Local DevKey.");
        terminal.println(" [Y] - ALLOW once (Sandboxed)");
        terminal.println(" [A] - ALLOW ALL for this session (Fast Dev Mode)");
        terminal.println(" [N] - BLOCK execution");
        terminal.print(" > ");

        while (true) {
            if (keyboard.hasKey()) {
                const key = keyboard.getKey();
                if (key == 'y' or key == 'Y') {
                    terminal.setFgColor(0x55FF55);
                    terminal.println("Y -> APPROVED ONCE.");
                    terminal.setFgColor(0xFFFFFF);
                    return true;
                } else if (key == 'a' or key == 'A') {
                    terminal.setFgColor(0x55FF55);
                    terminal.println("A -> AUTO-RUN ACTIVATED FOR THIS SESSION.");
                    terminal.setFgColor(0xFFFFFF);
                    addDevKeyToAutoTrust(&zam.signer_pubkey);
                    return true;
                } else {
                    terminal.setFgColor(0xFF5555);
                    terminal.println("N -> BLOCKED BY USER.");
                    terminal.setFgColor(0xFFFFFF);
                    return false;
                }
            }
        }
    }

    serial.writeString("[SECURITY] Terminal not ready. Auto-denying DevKey.\n");
    return false;
}

// ============================================================================
// Capability mapping from ZAM trust level
// ============================================================================

fn trustLevelToCaps(trust_level: u8, zam_caps: u32) u32 {
    var caps: u32 = zam_caps;
    switch (trust_level) {
        zam_header.TRUST_KERNEL => caps = capability.CAP_ALL,
        zam_header.TRUST_SYSTEM => {
            caps = caps & ~capability.CAP_ADMIN;
            caps |= capability.CAP_EXEC | capability.CAP_FS_READ |
                capability.CAP_FS_WRITE | capability.CAP_NET;
        },
        zam_header.TRUST_USER => caps = caps & (capability.CAP_FS_READ | capability.CAP_FS_WRITE |
            capability.CAP_IPC | capability.CAP_GRAPHICS | capability.CAP_EXEC),
        zam_header.TRUST_UNTRUSTED => caps = capability.CAP_FS_READ,
        else => caps = capability.CAP_MINIMAL,
    }
    return caps;
}

fn findFreeSlot() ?usize {
    var i: usize = 0;
    while (i < MAX_ELF_PROCESSES) : (i += 1) {
        if (!elf_processes[i].active) return i;
    }
    return null;
}

fn findByPid(pid: u32) ?usize {
    var i: usize = 0;
    while (i < MAX_ELF_PROCESSES) : (i += 1) {
        if (elf_processes[i].active and elf_processes[i].pid == pid) return i;
    }
    return null;
}

// ============================================================================
// Execution result
// ============================================================================

pub const ExecResult = struct {
    err: ExecError,
    pid: u32,
    entry_point: u64,
    caps_granted: u32,
    pages_used: u64,
};

// ============================================================================
// Main API: Execute from raw .zam data
// ============================================================================

pub fn execZam(data: []const u8, name: []const u8) ExecResult {
    var result = ExecResult{
        .err = .None,
        .pid = 0,
        .entry_point = 0,
        .caps_granted = 0,
        .pages_used = 0,
    };

    if (!initialized) {
        result.err = .NotInitialized;
        return result;
    }

    serial.writeString("\n[ELFEXEC] === Executing: ");
    serialPrintStr(name);
    serial.writeString(" ===\n");

    const slot = findFreeSlot() orelse {
        serial.writeString("[ELFEXEC] No free process slot\n");
        result.err = .TooManyProcesses;
        return result;
    };

    // Step 2: Parse .zam file
    serial.writeString("[ELFEXEC] Step 1: Parsing .zam...\n");
    const parsed = loader.parseZamFile(data) orelse {
        serial.writeString("[ELFEXEC] Parse failed\n");
        result.err = .ParseFailed;
        return result;
    };

    // Step 3: Binary verification (E3.3)
    serial.writeString("[ELFEXEC] Step 2: Binary verification...\n");
    if (binaryverify.isInitialized()) {
        const elf_data = data[parsed.elf_data_offset .. parsed.elf_data_offset + parsed.elf_data_size];
        if (!binaryverify.checkExec(elf_data)) {
            serial.writeString("[ELFEXEC] Binary verification BLOCKED\n");
            result.err = .VerifyFailed;
            return result;
        }
        serial.writeString("[ELFEXEC] Binary verification: OK\n");
    }

    // Step 4: Verify integrity (hash check)
    serial.writeString("[ELFEXEC] Step 3: Integrity check...\n");
    if (!loader.verifyZamIntegrity(data)) {
        serial.writeString("[ELFEXEC] Integrity check FAILED\n");
        result.err = .VerifyFailed;
        return result;
    }
    serial.writeString("[ELFEXEC] Integrity: OK\n");

    // Step 5: Determine capabilities (E3.6 DEVKEY LOGIC)
    serial.writeString("[ELFEXEC] Step 4: Capability assignment...\n");
    var caps = trustLevelToCaps(parsed.zam.trust_level, parsed.zam.required_caps);

    if (parsed.zam.isDevKey()) {
        serial.writeString("[SECURITY] DEVKEY Signature Detected.\n");

        // HARD BLOCK JIKA INI SERVER PRODUCTION
        if (config.is_production) {
            serial.writeString("[SECURITY] CRITICAL: Attempted to run DevKey binary on PRODUCTION server. BLOCKED!\n");
            if (violation.isInitialized()) {
                _ = violation.reportViolation(.{
                    .violation_type = .binary_untrusted,
                    .severity = .critical,
                    .pid = 0,
                    .source_ip = 0,
                    .detail = "DevKey Exec Attempt in Prod",
                });
            }
            result.err = .ProductionLockdown;
            return result;
        }

        // Minta ijin interaktif via Hardware (Atau gunakan Auto-Run Sesi)
        if (!requestPhysicalApproval(&parsed.zam, name, caps)) {
            serial.writeString("[SECURITY] Physical approval denied. Execution aborted.\n");
            result.err = .CapabilityDenied;
            return result;
        }

        // Eksekusi diizinkan, tapi downgrade hak aksesnya secara paksa!
        caps &= ~capability.CAP_ADMIN;
        serial.writeString("[SECURITY] DevKey allowed. Sandboxing enforced (CAP_ADMIN stripped).\n");
    } else {
        serial.writeString("[SECURITY] AUTHORITY Signature Detected. Proceeding with global trust.\n");
    }

    serial.writeString("[ELFEXEC] Caps granted: 0x");
    printHex32(caps);
    serial.writeString("\n");

    const current_pid = process.getCurrentPid();
    if (capability.isInitialized()) {
        if (!capability.check(current_pid, capability.CAP_EXEC)) {
            serial.writeString("[ELFEXEC] Caller lacks CAP_EXEC\n");
            result.err = .CapabilityDenied;
            return result;
        }
    }

    // Step 6: Load segments into memory
    serial.writeString("[ELFEXEC] Step 5: Loading segments...\n");
    const elf_data = data[parsed.elf_data_offset .. parsed.elf_data_offset + parsed.elf_data_size];
    var load_result = segment_loader.loadSegments(&parsed.elf, elf_data, false);

    if (load_result.err != .None) {
        serial.writeString("[ELFEXEC] Segment loading failed: ");
        serial.writeString(segment_loader.loadErrorName(load_result.err));
        serial.writeString("\n");
        result.err = .LoadFailed;
        return result;
    }

    // Step 7: Create kernel process with ELF entry point
    serial.writeString("[ELFEXEC] Step 6: Creating process...\n");
    const entry = load_result.entry_point;

    if (entry < segment_loader.USER_SPACE_MIN or entry >= segment_loader.USER_SPACE_MAX) {
        serial.writeString("[ELFEXEC] Invalid entry point: 0x");
        printHex64(entry);
        serial.writeString("\n");
        segment_loader.cleanupAllSegments(&load_result);
        result.err = .InvalidEntry;
        return result;
    }

    const pid = process.createWithCaps(name, entry, 0, caps) orelse {
        serial.writeString("[ELFEXEC] Process creation failed\n");
        segment_loader.cleanupAllSegments(&load_result);
        result.err = .ProcessCreateFailed;
        return result;
    };

    // Step 8: Track in elf_processes table
    elf_processes[slot].pid = pid;
    elf_processes[slot].load_result = load_result;
    elf_processes[slot].entry_point = entry;
    elf_processes[slot].caps_granted = caps;
    elf_processes[slot].trust_level = parsed.zam.trust_level;
    elf_processes[slot].active = true;

    const nlen = @min(name.len, 32);
    var ni: usize = 0;
    while (ni < nlen) : (ni += 1) {
        elf_processes[slot].name[ni] = name[ni];
    }
    elf_processes[slot].name_len = @intCast(nlen);

    elf_proc_count += 1;

    result.pid = pid;
    result.entry_point = entry;
    result.caps_granted = caps;
    result.pages_used = load_result.total_pages_used;

    serial.writeString("[ELFEXEC] === Process created ===\n");
    serial.writeString("[ELFEXEC] PID: ");
    printDec(pid);
    serial.writeString("\n");
    serial.writeString("[ELFEXEC] Entry: 0x");
    printHex64(entry);
    serial.writeString("\n");

    return result;
}

pub fn execRawElf(elf_data: []const u8, name: []const u8, caps: u32) ExecResult {
    var result = ExecResult{ .err = .None, .pid = 0, .entry_point = 0, .caps_granted = 0, .pages_used = 0 };
    if (!initialized) {
        result.err = .NotInitialized;
        return result;
    }

    serial.writeString("\n[ELFEXEC] === Exec raw ELF: ");
    serialPrintStr(name);
    serial.writeString(" ===\n");

    const slot = findFreeSlot() orelse {
        result.err = .TooManyProcesses;
        return result;
    };
    const parsed = elf_parser.parseElf(elf_data) orelse {
        result.err = .ParseFailed;
        return result;
    };

    if (binaryverify.isInitialized()) {
        if (!binaryverify.checkExec(elf_data)) {
            result.err = .VerifyFailed;
            return result;
        }
    }

    var load_result = segment_loader.loadSegments(&parsed, elf_data, false);
    if (load_result.err != .None) {
        result.err = .LoadFailed;
        return result;
    }

    const entry = load_result.entry_point;
    const pid = process.createWithCaps(name, entry, 0, caps) orelse {
        segment_loader.cleanupAllSegments(&load_result);
        result.err = .ProcessCreateFailed;
        return result;
    };

    elf_processes[slot].pid = pid;
    elf_processes[slot].load_result = load_result;
    elf_processes[slot].entry_point = entry;
    elf_processes[slot].caps_granted = caps;
    elf_processes[slot].trust_level = zam_header.TRUST_USER;
    elf_processes[slot].active = true;

    const nlen = @min(name.len, 32);
    var ni: usize = 0;
    while (ni < nlen) : (ni += 1) elf_processes[slot].name[ni] = name[ni];
    elf_processes[slot].name_len = @intCast(nlen);
    elf_proc_count += 1;

    result.pid = pid;
    result.entry_point = entry;
    result.caps_granted = caps;
    result.pages_used = load_result.total_pages_used;
    return result;
}

// ============================================================================
// Process cleanup & Queries
// ============================================================================

pub fn cleanupProcess(pid: u32) bool {
    const slot = findByPid(pid) orelse return false;
    segment_loader.cleanupAllSegments(&elf_processes[slot].load_result);
    _ = process.terminate(pid);
    elf_processes[slot] = ElfProcess.init();
    if (elf_proc_count > 0) elf_proc_count -= 1;
    return true;
}

pub fn cleanupAll() void {
    var i: usize = 0;
    while (i < MAX_ELF_PROCESSES) : (i += 1) {
        if (elf_processes[i].active) _ = cleanupProcess(elf_processes[i].pid);
    }
}

pub fn getProcessCount() usize {
    return elf_proc_count;
}

pub fn getProcessInfo(index: usize) ?struct {
    pid: u32,
    entry: u64,
    caps: u32,
    trust: u8,
    pages: u64,
    name: []const u8,
} {
    var count: usize = 0;
    var i: usize = 0;
    while (i < MAX_ELF_PROCESSES) : (i += 1) {
        if (elf_processes[i].active) {
            if (count == index) {
                return .{
                    .pid = elf_processes[i].pid,
                    .entry = elf_processes[i].entry_point,
                    .caps = elf_processes[i].caps_granted,
                    .trust = elf_processes[i].trust_level,
                    .pages = elf_processes[i].load_result.total_pages_used,
                    .name = elf_processes[i].getName(),
                };
            }
            count += 1;
        }
    }
    return null;
}

pub fn isElfProcess(pid: u32) bool {
    return findByPid(pid) != null;
}

// ============================================================================
// Print helpers
// ============================================================================

fn printHex32ToTerminal(val: u32) void {
    if (!terminal.isInitialized()) return;
    const hex = "0123456789ABCDEF";
    var i: u5 = 28;
    while (true) {
        terminal.printChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    var i: u5 = 28;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printDec(val: anytype) void {
    const v: u64 = @intCast(val);
    if (v == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;
    while (n > 0) : (i += 1) {
        buf[i] = @intCast((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn serialPrintStr(s: []const u8) void {
    for (s) |c| serial.writeChar(c);
}
