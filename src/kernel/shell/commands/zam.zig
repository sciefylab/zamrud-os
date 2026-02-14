//! Zamrud OS - Shell Commands for ZAM Binary Loader (F5.0-F5.3)
//! Commands: test, segtest, exectest, demo, info, elfinfo, verify,
//!           exec, run, load, diskls, disktest, status, help

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const serial = @import("../../drivers/serial/serial.zig");

const loader = @import("../../loader/loader.zig");
const zam_header = @import("../../loader/zam_header.zig");
const elf_parser = @import("../../loader/elf_parser.zig");
const elf_exec = @import("../../loader/elf_exec.zig");
const segment_loader = @import("../../loader/segment_loader.zig");
const test_zam_elf = @import("../../tests/test_zam_elf.zig");
const fat32 = @import("../../fs/fat32.zig");
const capability = @import("../../security/capability.zig");

// ============================================================================
// Constants
// ============================================================================

const MAX_FILE_SIZE: usize = 64 * 1024; // 64KB max ELF file
const FILE_BUF_SIZE: usize = 8192; // 8KB read buffer (stack-safe)

// ============================================================================
// Main dispatcher
// ============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);
    const sub = parsed.cmd;

    if (sub.len == 0 or helpers.strEql(sub, "help")) {
        cmdHelp();
    } else if (helpers.strEql(sub, "test")) {
        cmdZamTest();
    } else if (helpers.strEql(sub, "info")) {
        cmdZamInfo(parsed.rest);
    } else if (helpers.strEql(sub, "elfinfo")) {
        cmdElfInfo(parsed.rest);
    } else if (helpers.strEql(sub, "verify")) {
        cmdZamVerify(parsed.rest);
    } else if (helpers.strEql(sub, "status")) {
        cmdStatus();
    } else if (helpers.strEql(sub, "demo")) {
        cmdDemo();
    } else if (helpers.strEql(sub, "segtest")) {
        cmdSegTest();
    } else if (helpers.strEql(sub, "exectest")) {
        cmdExecTest();
    } else if (helpers.strEql(sub, "disktest")) {
        cmdDiskTest();
    } else if (helpers.strEql(sub, "exec")) {
        cmdExec(parsed.rest);
    } else if (helpers.strEql(sub, "run")) {
        cmdRun(parsed.rest);
    } else if (helpers.strEql(sub, "load")) {
        cmdLoad(parsed.rest);
    } else if (helpers.strEql(sub, "diskls")) {
        cmdDiskLs();
    } else if (helpers.strEql(sub, "procs")) {
        cmdProcs();
    } else if (helpers.strEql(sub, "kill")) {
        cmdKill(parsed.rest);
    } else {
        shell.printError("Unknown zam subcommand: ");
        shell.print(sub);
        shell.newLine();
        shell.println("  Type 'zam help' for usage");
    }
}

// ============================================================================
// Help
// ============================================================================

fn cmdHelp() void {
    shell.println("");
    shell.printInfoLine("=== ZAM Binary Loader (F5.0-F5.3) ===");
    shell.println("");
    shell.println("  Testing:");
    shell.println("    zam test         Run F5.0 parser tests (25 tests)");
    shell.println("    zam segtest      Run F5.1 segment loader tests (20 tests)");
    shell.println("    zam exectest     Run F5.2 process execution tests (20 tests)");
    shell.println("    zam disktest     Run F5.3 FAT32 integration tests (20 tests)");
    shell.println("");
    shell.println("  Inspect:");
    shell.println("    zam status       Show loader status");
    shell.println("    zam demo         Parse a built-in test .zam binary");
    shell.println("    zam info         Show test ZAM header info");
    shell.println("    zam elfinfo      Show test ELF64 header info");
    shell.println("    zam verify       Verify test ZAM hash + signature");
    shell.println("");
    shell.println("  Disk (F5.3):");
    shell.println("    zam diskls       List .zam/.elf files on /disk");
    shell.println("    zam load <file>  Load & inspect file from /disk");
    shell.println("    zam exec <file>  Execute .zam file from /disk");
    shell.println("    zam run <file>   Execute raw .elf file from /disk");
    shell.println("    zam procs        List active ELF processes");
    shell.println("    zam kill <pid>   Kill an ELF process");
    shell.println("    zam help         This help");
    shell.println("");
}

// ============================================================================
// Status
// ============================================================================

fn cmdStatus() void {
    shell.println("");
    shell.printInfoLine("=== ZAM Loader Status ===");

    shell.print("  Loader initialized: ");
    if (loader.isInitialized()) {
        shell.printInfoLine("YES");
    } else {
        shell.printError("NO");
        shell.newLine();
    }

    shell.print("  ELF executor:       ");
    if (elf_exec.isInitialized()) {
        shell.printInfoLine("YES");
    } else {
        shell.printError("NO");
        shell.newLine();
    }

    shell.print("  FAT32 mounted:      ");
    if (fat32.isMounted()) {
        shell.printInfoLine("YES");
    } else {
        shell.printError("NO");
        shell.newLine();
    }

    shell.print("  Active ELF procs:   ");
    helpers.printDec(elf_exec.getProcessCount());
    shell.newLine();

    shell.print("  ZAM header size:    ");
    helpers.printDec(zam_header.ZAM_HEADER_SIZE);
    shell.println(" bytes");

    shell.print("  Max file size:      ");
    helpers.printDec(MAX_FILE_SIZE / 1024);
    shell.println(" KB");

    shell.println("");
}

// ============================================================================
// F5.0 Tests
// ============================================================================

pub fn cmdZamTest() void {
    shell.println("");
    shell.printInfoLine("=== Running F5.0 ZAM/ELF Parser Tests ===");
    shell.println("");
    test_zam_elf.runTests();
    shell.println("");
}

// ============================================================================
// F5.1 Segment Tests
// ============================================================================

fn cmdSegTest() void {
    shell.println("");
    shell.printInfoLine("=== Running F5.1 Segment Loader Tests ===");
    shell.println("");
    const test_seg = @import("../../tests/test_segment_loader.zig");
    test_seg.runTests();
    shell.println("");
}

// ============================================================================
// F5.2 Exec Tests
// ============================================================================

fn cmdExecTest() void {
    shell.println("");
    shell.printInfoLine("=== Running F5.2 Process Execution Tests ===");
    shell.println("");
    const test_exec = @import("../../tests/test_elf_exec.zig");
    test_exec.runTests();
    shell.println("");
}

// ============================================================================
// F5.3 Disk Tests
// ============================================================================

fn cmdDiskTest() void {
    shell.println("");
    shell.printInfoLine("=== Running F5.3 FAT32 Integration Tests ===");
    shell.println("");
    const test_disk = @import("../../tests/test_disk_loader.zig");
    test_disk.runTests();
    shell.println("");
}

// ============================================================================
// F5.3: List .zam/.elf files on disk
// ============================================================================

fn cmdDiskLs() void {
    shell.println("");
    shell.printInfoLine("=== Files on /disk ===");
    shell.println("");

    if (!fat32.isMounted()) {
        shell.printError("FAT32 not mounted");
        shell.newLine();
        shell.println("");
        return;
    }

    var entries: [64]fat32.FileInfo = undefined;
    const count = fat32.listRoot(&entries);

    if (count == 0) {
        shell.println("  (empty)");
        shell.println("");
        return;
    }

    var zam_count: usize = 0;
    var elf_count: usize = 0;

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const entry = &entries[i];
        const name = entry.getName();

        const is_zam = isZamFile(name);
        const is_elf = isElfFile(name);

        shell.print("  ");
        if (entry.is_dir) {
            shell.print("[DIR] ");
        } else if (is_zam) {
            shell.print("[ZAM] ");
            zam_count += 1;
        } else if (is_elf) {
            shell.print("[ELF] ");
            elf_count += 1;
        } else {
            shell.print("      ");
        }

        shell.print(name);

        if (!entry.is_dir) {
            shell.print("  (");
            helpers.printDec(entry.size);
            shell.print(" bytes)");
        }
        shell.newLine();
    }

    shell.println("");
    shell.print("  Total: ");
    helpers.printDec(count);
    shell.print(" files, ");
    helpers.printDec(zam_count);
    shell.print(" .zam, ");
    helpers.printDec(elf_count);
    shell.println(" .elf");
    shell.println("");
}

// ============================================================================
// F5.3: Load & inspect file from disk
// ============================================================================

fn cmdLoad(args: []const u8) void {
    shell.println("");

    if (args.len == 0) {
        shell.printError("Usage: zam load <filename>");
        shell.newLine();
        shell.println("  Example: zam load HELLO.ZAM");
        shell.println("");
        return;
    }

    if (!fat32.isMounted()) {
        shell.printError("FAT32 not mounted");
        shell.newLine();
        shell.println("");
        return;
    }

    // Find file
    const file_info = fat32.findInRoot(args) orelse {
        shell.printError("File not found: ");
        shell.print(args);
        shell.newLine();
        shell.println("");
        return;
    };

    shell.printInfoLine("=== Loading file from /disk ===");
    shell.println("");

    shell.print("  File:   ");
    shell.print(args);
    shell.newLine();

    shell.print("  Size:   ");
    helpers.printDec(file_info.size);
    shell.println(" bytes");

    shell.print("  Cluster: ");
    helpers.printDec(file_info.cluster);
    shell.newLine();

    // Validate size
    if (file_info.size == 0) {
        shell.printError("  File is empty!");
        shell.newLine();
        shell.println("");
        return;
    }

    if (file_info.size > MAX_FILE_SIZE) {
        shell.printError("  File too large (max ");
        helpers.printDec(MAX_FILE_SIZE / 1024);
        shell.print(" KB)");
        shell.newLine();
        shell.println("");
        return;
    }

    // Read file
    var buf: [FILE_BUF_SIZE]u8 = [_]u8{0} ** FILE_BUF_SIZE;
    const read_size = @min(@as(usize, file_info.size), FILE_BUF_SIZE);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    if (bytes == 0) {
        shell.printError("  Read failed!");
        shell.newLine();
        shell.println("");
        return;
    }

    shell.print("  Read:   ");
    helpers.printDec(bytes);
    shell.println(" bytes");

    // Check file type
    const name = file_info.getName();
    if (isZamFile(name)) {
        shell.println("  Type:   ZAM binary");

        // Try to parse
        if (loader.parseZamFile(buf[0..bytes])) |parsed| {
            shell.printInfoLine("  Parse:  OK");
            shell.print("  Entry:  0x");
            helpers.printHex64(parsed.elf.entryPoint());
            shell.newLine();
            shell.print("  Segs:   ");
            helpers.printDec(parsed.elf.load_count);
            shell.println(" LOAD segments");
            shell.print("  Trust:  ");
            printTrustLevel(parsed.zam.trust_level);
            shell.newLine();
            shell.print("  Hash:   ");
            if (loader.verifyZamIntegrity(buf[0..bytes])) {
                shell.printInfoLine("VERIFIED");
            } else {
                shell.printError("MISMATCH");
                shell.newLine();
            }
        } else {
            shell.printError("  Parse:  FAILED");
            shell.newLine();
        }
    } else if (isElfFile(name) or isElfMagic(buf[0..bytes])) {
        shell.println("  Type:   Raw ELF binary");

        if (elf_parser.parseElf(buf[0..bytes])) |parsed| {
            shell.printInfoLine("  Parse:  OK");
            shell.print("  Entry:  0x");
            helpers.printHex64(parsed.entryPoint());
            shell.newLine();
            shell.print("  Segs:   ");
            helpers.printDec(parsed.load_count);
            shell.println(" LOAD segments");

            const err = elf_parser.validateFull(buf[0..bytes]);
            shell.print("  Valid:  ");
            if (err == .None) {
                shell.printInfoLine("OK");
            } else {
                shell.printError(elf_parser.elfErrorName(err));
                shell.newLine();
            }
        } else {
            shell.printError("  Parse:  FAILED (invalid ELF)");
            shell.newLine();
        }
    } else {
        shell.println("  Type:   Unknown (not ZAM or ELF)");

        // Show first bytes
        shell.print("  Magic:  ");
        const show = @min(bytes, 8);
        var si: usize = 0;
        while (si < show) : (si += 1) {
            helpers.printHexByte(buf[si]);
            shell.print(" ");
        }
        shell.newLine();
    }

    shell.println("");
}

// ============================================================================
// F5.3: Execute .zam from disk
// ============================================================================

fn cmdExec(args: []const u8) void {
    shell.println("");

    if (args.len == 0) {
        shell.printError("Usage: zam exec <filename.zam>");
        shell.newLine();
        shell.println("  Example: zam exec HELLO.ZAM");
        shell.println("");
        return;
    }

    if (!fat32.isMounted()) {
        shell.printError("FAT32 not mounted");
        shell.newLine();
        shell.println("");
        return;
    }

    if (!elf_exec.isInitialized()) {
        shell.printError("ELF executor not initialized");
        shell.newLine();
        shell.println("");
        return;
    }

    // Find file
    const file_info = fat32.findInRoot(args) orelse {
        shell.printError("File not found: ");
        shell.print(args);
        shell.newLine();
        shell.println("");
        return;
    };

    // Validate
    if (file_info.size == 0 or file_info.size > MAX_FILE_SIZE) {
        shell.printError("Invalid file size");
        shell.newLine();
        shell.println("");
        return;
    }

    // Read file
    var buf: [FILE_BUF_SIZE]u8 = [_]u8{0} ** FILE_BUF_SIZE;
    const read_size = @min(@as(usize, file_info.size), FILE_BUF_SIZE);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    if (bytes < zam_header.ZAM_HEADER_SIZE) {
        shell.printError("File too small for .zam format");
        shell.newLine();
        shell.println("");
        return;
    }

    // Execute
    shell.printInfoLine("=== Executing .zam from /disk ===");
    shell.println("");

    const result = elf_exec.execZam(buf[0..bytes], args);

    if (result.err != .None) {
        shell.printError("Execution failed: ");
        shell.print(elf_exec.execErrorName(result.err));
        shell.newLine();
    } else {
        shell.printInfoLine("Process created successfully");
        shell.print("  PID:    ");
        helpers.printDec(result.pid);
        shell.newLine();
        shell.print("  Entry:  0x");
        helpers.printHex64(result.entry_point);
        shell.newLine();
        shell.print("  Caps:   0x");
        helpers.printHex32(result.caps_granted);
        shell.newLine();
        shell.print("  Pages:  ");
        helpers.printDec(result.pages_used);
        shell.newLine();
    }

    shell.println("");
}

// ============================================================================
// F5.3: Run raw ELF from disk
// ============================================================================

fn cmdRun(args: []const u8) void {
    shell.println("");

    if (args.len == 0) {
        shell.printError("Usage: zam run <filename>");
        shell.newLine();
        shell.println("  Example: zam run HELLO.ELF");
        shell.println("");
        return;
    }

    if (!fat32.isMounted()) {
        shell.printError("FAT32 not mounted");
        shell.newLine();
        shell.println("");
        return;
    }

    if (!elf_exec.isInitialized()) {
        shell.printError("ELF executor not initialized");
        shell.newLine();
        shell.println("");
        return;
    }

    // Find file
    const file_info = fat32.findInRoot(args) orelse {
        shell.printError("File not found: ");
        shell.print(args);
        shell.newLine();
        shell.println("");
        return;
    };

    if (file_info.size == 0 or file_info.size > MAX_FILE_SIZE) {
        shell.printError("Invalid file size");
        shell.newLine();
        shell.println("");
        return;
    }

    // Read file
    var buf: [FILE_BUF_SIZE]u8 = [_]u8{0} ** FILE_BUF_SIZE;
    const read_size = @min(@as(usize, file_info.size), FILE_BUF_SIZE);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    if (bytes < elf_parser.ELF64_HEADER_SIZE) {
        shell.printError("File too small for ELF format");
        shell.newLine();
        shell.println("");
        return;
    }

    // Check ELF magic
    if (!isElfMagic(buf[0..bytes])) {
        shell.printError("Not a valid ELF file");
        shell.newLine();
        shell.println("");
        return;
    }

    // Execute
    shell.printInfoLine("=== Running ELF from /disk ===");
    shell.println("");

    const result = elf_exec.execRawElf(buf[0..bytes], args, capability.CAP_USER_DEFAULT);

    if (result.err != .None) {
        shell.printError("Execution failed: ");
        shell.print(elf_exec.execErrorName(result.err));
        shell.newLine();
    } else {
        shell.printInfoLine("Process created successfully");
        shell.print("  PID:    ");
        helpers.printDec(result.pid);
        shell.newLine();
        shell.print("  Entry:  0x");
        helpers.printHex64(result.entry_point);
        shell.newLine();
        shell.print("  Pages:  ");
        helpers.printDec(result.pages_used);
        shell.newLine();
    }

    shell.println("");
}

// ============================================================================
// F5.3: List active ELF processes
// ============================================================================

fn cmdProcs() void {
    shell.println("");
    shell.printInfoLine("=== Active ELF Processes ===");
    shell.println("");

    const count = elf_exec.getProcessCount();
    if (count == 0) {
        shell.println("  No active ELF processes");
        shell.println("");
        return;
    }

    shell.println("  PID   Entry            Caps       Trust  Pages  Name");
    shell.println("  ─────────────────────────────────────────────────────");

    var i: usize = 0;
    while (i < 16) : (i += 1) {
        if (elf_exec.getProcessInfo(i)) |info| {
            shell.print("  ");
            helpers.printDecPadded(info.pid, 5);
            shell.print(" 0x");
            helpers.printHex64(info.entry);
            shell.print(" 0x");
            helpers.printHex32(info.caps);
            shell.print(" ");
            printTrustLevel(info.trust);
            shell.print("  ");
            helpers.printDecPadded(info.pages, 5);
            shell.print("  ");
            shell.print(info.name);
            shell.newLine();
        } else break;
    }

    shell.println("");
    shell.print("  Total: ");
    helpers.printDec(count);
    shell.println(" process(es)");
    shell.println("");
}

// ============================================================================
// F5.3: Kill ELF process
// ============================================================================

fn cmdKill(args: []const u8) void {
    shell.println("");

    if (args.len == 0) {
        shell.printError("Usage: zam kill <pid>");
        shell.newLine();
        shell.println("");
        return;
    }

    const pid = helpers.parseU32(args) orelse {
        shell.printError("Invalid PID");
        shell.newLine();
        shell.println("");
        return;
    };

    if (elf_exec.cleanupProcess(pid)) {
        shell.print("  Killed PID ");
        helpers.printDec(pid);
        shell.newLine();
    } else {
        shell.printError("PID not found or not an ELF process");
        shell.newLine();
    }

    shell.println("");
}

// ============================================================================
// Demo — build and parse a test .zam in-memory
// ============================================================================

fn cmdDemo() void {
    shell.println("");
    shell.printInfoLine("=== ZAM Demo: Build & Parse Test Binary ===");
    shell.println("");

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildDemoZam(&buf);

    if (size == 0) {
        shell.printError("Failed to build demo .zam binary");
        shell.newLine();
        return;
    }

    shell.print("  Built demo .zam: ");
    helpers.printDec(size);
    shell.println(" bytes");

    if (loader.parseZamFile(buf[0..size])) |parsed| {
        shell.printInfoLine("  Parse: OK");
        shell.print("  Entry point: 0x");
        helpers.printHex64(parsed.elf.entryPoint());
        shell.newLine();
        shell.print("  LOAD segments: ");
        helpers.printDec(parsed.elf.load_count);
        shell.newLine();
        shell.print("  Trust level: ");
        printTrustLevel(parsed.zam.trust_level);
        shell.newLine();
        shell.print("  Hash verify: ");
        if (loader.verifyZamIntegrity(buf[0..size])) {
            shell.printInfoLine("PASS");
        } else {
            shell.printError("FAIL");
            shell.newLine();
        }
    } else {
        shell.printError("  Parse: FAILED");
        shell.newLine();
    }

    shell.println("");
}

// ============================================================================
// ZAM Info
// ============================================================================

fn cmdZamInfo(_: []const u8) void {
    shell.println("");
    shell.printInfoLine("=== ZAM Header Info (test binary) ===");
    shell.println("");

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildDemoZam(&buf);
    if (size == 0) {
        shell.printError("Failed to build test binary");
        shell.newLine();
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        shell.print("  Magic:       ");
        shell.printChar(hdr.magic[0]);
        shell.printChar(hdr.magic[1]);
        shell.printChar(hdr.magic[2]);
        shell.printChar(hdr.magic[3]);
        shell.newLine();
        shell.print("  Version:     ");
        helpers.printDec(hdr.version);
        shell.newLine();
        shell.print("  Header size: ");
        helpers.printDec(hdr.header_size);
        shell.println(" bytes");
        shell.print("  Flags:       0x");
        helpers.printHex32(hdr.flags);
        shell.newLine();
        shell.print("  Trust:       ");
        printTrustLevel(hdr.trust_level);
        shell.newLine();
        shell.print("  ELF offset:  ");
        helpers.printDec(hdr.elf_offset);
        shell.newLine();
        shell.print("  ELF size:    ");
        helpers.printDec(hdr.elf_size);
        shell.println(" bytes");
    } else {
        shell.printError("Failed to parse ZAM header");
        shell.newLine();
    }
    shell.println("");
}

// ============================================================================
// ELF Info
// ============================================================================

fn cmdElfInfo(_: []const u8) void {
    shell.println("");
    shell.printInfoLine("=== ELF64 Header Info (test binary) ===");
    shell.println("");

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildDemoZam(&buf);
    if (size == 0) {
        shell.printError("Failed to build test binary");
        shell.newLine();
        return;
    }

    if (zam_header.getElfPayload(buf[0..size])) |elf_data| {
        if (elf_parser.parseElf(elf_data)) |parsed| {
            const hdr = &parsed.header;
            shell.print("  Magic:      0x");
            helpers.printHex8(hdr.magic[0]);
            shell.print(" ");
            shell.printChar(hdr.magic[1]);
            shell.printChar(hdr.magic[2]);
            shell.printChar(hdr.magic[3]);
            shell.newLine();
            shell.print("  Class:      ");
            if (hdr.is64Bit()) shell.println("ELF64") else shell.println("ELF32");
            shell.print("  Type:       ");
            if (hdr.isExecutable()) shell.println("EXEC") else shell.println("OTHER");
            shell.print("  Machine:    ");
            if (hdr.isX86_64()) shell.println("x86_64") else shell.println("other");
            shell.print("  Entry:      0x");
            helpers.printHex64(hdr.entry);
            shell.newLine();
            shell.print("  PH count:   ");
            helpers.printDec(hdr.phnum);
            shell.newLine();
            shell.print("  LOAD segs:  ");
            helpers.printDec(parsed.load_count);
            shell.newLine();
        } else {
            shell.printError("Failed to parse ELF");
            shell.newLine();
        }
    } else {
        shell.printError("Failed to extract ELF payload");
        shell.newLine();
    }
    shell.println("");
}

// ============================================================================
// Verify
// ============================================================================

fn cmdZamVerify(_: []const u8) void {
    shell.println("");
    shell.printInfoLine("=== ZAM Verify (test binary) ===");
    shell.println("");

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildDemoZam(&buf);
    if (size == 0) {
        shell.printError("Failed to build test binary");
        shell.newLine();
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        shell.print("  Structure:  ");
        const struct_err = hdr.validate();
        if (struct_err == .None) {
            shell.printInfoLine("OK");
        } else {
            shell.printError(zam_header.errorName(struct_err));
            shell.newLine();
        }

        const elf_start = hdr.elf_offset;
        const elf_end = elf_start + hdr.elf_size;
        if (elf_end <= size) {
            const elf_data = buf[elf_start..elf_end];
            shell.print("  Hash:       ");
            if (hdr.verifyHash(elf_data)) {
                shell.printInfoLine("PASS");
            } else {
                shell.printError("FAIL");
                shell.newLine();
            }

            shell.print("  ELF format: ");
            const elf_err = elf_parser.validateFull(elf_data);
            if (elf_err == .None) {
                shell.printInfoLine("OK");
            } else {
                shell.printError(elf_parser.elfErrorName(elf_err));
                shell.newLine();
            }
        }

        shell.print("  Integrity:  ");
        if (loader.verifyZamIntegrity(buf[0..size])) {
            shell.printInfoLine("VERIFIED");
        } else {
            shell.printError("COMPROMISED");
            shell.newLine();
        }
    } else {
        shell.printError("Failed to parse ZAM header");
        shell.newLine();
    }
    shell.println("");
}

// ============================================================================
// File type helpers
// ============================================================================

fn isZamFile(name: []const u8) bool {
    if (name.len < 4) return false;
    const ext = name[name.len - 4 ..];
    return (ext[0] == '.' and
        (ext[1] == 'Z' or ext[1] == 'z') and
        (ext[2] == 'A' or ext[2] == 'a') and
        (ext[3] == 'M' or ext[3] == 'm'));
}

fn isElfFile(name: []const u8) bool {
    if (name.len < 4) return false;
    const ext = name[name.len - 4 ..];
    return (ext[0] == '.' and
        (ext[1] == 'E' or ext[1] == 'e') and
        (ext[2] == 'L' or ext[2] == 'l') and
        (ext[3] == 'F' or ext[3] == 'f'));
}

fn isElfMagic(data: []const u8) bool {
    if (data.len < 4) return false;
    return data[0] == 0x7F and data[1] == 'E' and data[2] == 'L' and data[3] == 'F';
}

fn printTrustLevel(trust: u8) void {
    switch (trust) {
        zam_header.TRUST_UNTRUSTED => shell.print("UNTRUST"),
        zam_header.TRUST_USER => shell.print("USER   "),
        zam_header.TRUST_SYSTEM => shell.print("SYSTEM "),
        zam_header.TRUST_KERNEL => shell.print("KERNEL "),
        else => shell.print("???    "),
    }
}

// ============================================================================
// Build demo binaries
// ============================================================================

fn buildDemoZam(buf: []u8) usize {
    if (buf.len < zam_header.ZAM_HEADER_SIZE + 136) return 0;

    var elf_buf: [256]u8 = [_]u8{0} ** 256;
    const elf_size = buildMinimalElf(&elf_buf);
    if (elf_size == 0) return 0;

    const hdr_size = zam_header.buildHeader(buf, elf_buf[0..elf_size], 0x0000000F, zam_header.TRUST_USER, 64, 0);
    if (hdr_size == 0) return 0;

    var i: usize = 0;
    while (i < elf_size) : (i += 1) {
        buf[hdr_size + i] = elf_buf[i];
    }
    return hdr_size + elf_size;
}

fn buildMinimalElf(buf: []u8) usize {
    if (buf.len < 136) return 0;

    var i: usize = 0;
    while (i < buf.len and i < 256) : (i += 1) {
        buf[i] = 0;
    }

    buf[0] = 0x7F;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = elf_parser.ELFCLASS64;
    buf[5] = elf_parser.ELFDATA2LSB;
    buf[6] = 1;

    writeU16(buf, 16, elf_parser.ET_EXEC);
    writeU16(buf, 18, elf_parser.EM_X86_64);
    writeU32(buf, 20, 1);
    writeU64(buf, 24, 0x400000);
    writeU64(buf, 32, 64);
    writeU16(buf, 52, 64);
    writeU16(buf, 54, 56);
    writeU16(buf, 56, 1);
    writeU16(buf, 58, 64);

    writeU32(buf, 64, elf_parser.PT_LOAD);
    writeU32(buf, 68, elf_parser.PF_R | elf_parser.PF_X);
    writeU64(buf, 72, 0);
    writeU64(buf, 80, 0x400000);
    writeU64(buf, 88, 0x400000);
    writeU64(buf, 96, 136);
    writeU64(buf, 104, 136);
    writeU64(buf, 112, 0x1000);

    buf[120] = 0xB8;
    buf[121] = 0x3C;
    buf[122] = 0x00;
    buf[123] = 0x00;
    buf[124] = 0x00;
    buf[125] = 0x31;
    buf[126] = 0xFF;
    buf[127] = 0x0F;
    buf[128] = 0x05;

    return 136;
}

// ============================================================================
// Byte helpers
// ============================================================================

fn writeU16(buf: []u8, offset: usize, val: u16) void {
    buf[offset] = @intCast(val & 0xFF);
    buf[offset + 1] = @intCast((val >> 8) & 0xFF);
}

fn writeU32(buf: []u8, offset: usize, val: u32) void {
    buf[offset] = @intCast(val & 0xFF);
    buf[offset + 1] = @intCast((val >> 8) & 0xFF);
    buf[offset + 2] = @intCast((val >> 16) & 0xFF);
    buf[offset + 3] = @intCast((val >> 24) & 0xFF);
}

fn writeU64(buf: []u8, offset: usize, val: u64) void {
    var j: usize = 0;
    while (j < 8) : (j += 1) {
        buf[offset + j] = @intCast((val >> @intCast(j * 8)) & 0xFF);
    }
}
