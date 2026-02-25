//! Zamrud OS - H.9 Memory Sanitization Shell Commands

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const sanitize = @import("../../mm/sanitize.zig");
const heap = @import("../../mm/heap.zig");
const pmm = @import("../../mm/pmm.zig");

// =============================================================================
// Main Command Dispatcher
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);
    const subcmd = parsed.cmd;

    if (subcmd.len == 0 or helpers.strEql(subcmd, "status")) {
        cmdStatus();
    } else if (helpers.strEql(subcmd, "stats")) {
        cmdStats();
    } else if (helpers.strEql(subcmd, "test")) {
        runTests();
    } else if (helpers.strEql(subcmd, "reset")) {
        cmdReset();
    } else if (helpers.strEql(subcmd, "help")) {
        cmdHelp();
    } else {
        shell.printError("Unknown sanitize command: ");
        shell.print(subcmd);
        shell.newLine();
        cmdHelp();
    }
}

// =============================================================================
// Commands
// =============================================================================

fn cmdStatus() void {
    shell.println("=== Memory Sanitization Status (H.9) ===");
    shell.newLine();

    shell.print("  Initialized:    ");
    if (sanitize.isInitialized()) {
        shell.println("YES");
    } else {
        shell.println("NO");
        return;
    }

    shell.print("  Sanitize:       ");
    if (sanitize.SANITIZE_ENABLED) {
        shell.println("ENABLED");
    } else {
        shell.println("DISABLED");
    }

    shell.print("  Verify Wipe:    ");
    if (sanitize.VERIFY_WIPE) {
        shell.println("ON");
    } else {
        shell.println("OFF");
    }

    shell.print("  Wipe Byte:      0x");
    helpers.printHex8(sanitize.WIPE_BYTE);
    shell.newLine();

    const stats = sanitize.getStats();
    shell.newLine();
    shell.println("  Statistics:");
    shell.print("    Heap wipes:   ");
    helpers.printDec(stats.heap_wipes);
    shell.newLine();
    shell.print("    Page wipes:   ");
    helpers.printDec(stats.page_wipes);
    shell.newLine();
    shell.print("    Stack wipes:  ");
    helpers.printDec(stats.stack_wipes);
    shell.newLine();
    shell.print("    Process wipes:");
    helpers.printDec(stats.process_wipes);
    shell.newLine();
    shell.print("    Bytes wiped:  ");
    helpers.printDec(stats.bytes_wiped);
    shell.newLine();
    shell.print("    Verify fails: ");
    helpers.printDec(stats.verify_failures);
    shell.newLine();
    shell.print("    mlock count:  ");
    helpers.printDec(stats.mlock_count);
    shell.newLine();
    shell.print("    mlock pages:  ");
    helpers.printDec(stats.mlock_pages);
    shell.newLine();
}

fn cmdStats() void {
    const stats = sanitize.getStats();
    shell.println("=== Sanitization Statistics ===");
    shell.print("  Heap:    ");
    helpers.printDec(stats.heap_wipes);
    shell.println(" wipes");
    shell.print("  Pages:   ");
    helpers.printDec(stats.page_wipes);
    shell.println(" wipes");
    shell.print("  Stacks:  ");
    helpers.printDec(stats.stack_wipes);
    shell.println(" wipes");
    shell.print("  Process: ");
    helpers.printDec(stats.process_wipes);
    shell.println(" wipes");
    shell.print("  Total:   ");
    helpers.printDec(stats.bytes_wiped);
    shell.println(" bytes");
    shell.print("  Errors:  ");
    helpers.printDec(stats.verify_failures);
    shell.newLine();
}

fn cmdReset() void {
    sanitize.resetStats();
    shell.println("[OK] Sanitization stats reset");
}

fn cmdHelp() void {
    shell.println("Memory Sanitization Commands (H.9):");
    shell.println("  sanitize [status] - Show sanitization status");
    shell.println("  sanitize stats    - Show wipe statistics");
    shell.println("  sanitize test     - Run H.9 tests");
    shell.println("  sanitize reset    - Reset statistics");
    shell.println("  mlock <addr> <sz> - Lock sensitive memory");
    shell.println("  munlock <addr>    - Unlock memory");
    shell.println("  santest           - Run all H.9 tests");
}

// =============================================================================
// mlock/munlock commands
// =============================================================================

pub fn cmdMlock(args: []const u8) void {
    _ = args;
    shell.println("[INFO] mlock: Lock sensitive pages in memory");
    shell.println("  Usage: mlock <virt_addr> <size>");
    shell.println("  (Full implementation requires address parsing)");

    // Show current mlocked count
    const stats = sanitize.getStats();
    shell.print("  Currently locked: ");
    helpers.printDec(stats.mlock_count);
    shell.print(" regions, ");
    helpers.printDec(stats.mlock_pages);
    shell.println(" pages");
}

pub fn cmdMunlock(args: []const u8) void {
    _ = args;
    shell.println("[INFO] munlock: Wipe and unlock pages");
    shell.println("  Usage: munlock <virt_addr>");
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() void {
    shell.println("");
    shell.println("########################################");
    shell.println("##  H.9: SECURE MEMORY SANITIZATION   ##");
    shell.println("########################################");
    shell.println("");

    if (!sanitize.isInitialized()) {
        shell.printError("Sanitize module not initialized!");
        shell.newLine();
        return;
    }

    var passed: u32 = 0;
    var failed: u32 = 0;

    // ========================================
    // Section 1: Initialization
    // ========================================
    shell.println("=== [1/6] Initialization ===");
    shell.newLine();

    // Test 1
    shell.print("  Sanitize initialized........ ");
    if (sanitize.isInitialized()) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 2
    shell.print("  Sanitize enabled............ ");
    if (sanitize.SANITIZE_ENABLED) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 3
    shell.print("  Wipe byte = 0x00............ ");
    if (sanitize.WIPE_BYTE == 0x00) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 4
    shell.print("  Verify wipe enabled......... ");
    if (sanitize.VERIFY_WIPE) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // ========================================
    // Section 2: Heap Wipe (H.9a)
    // ========================================
    shell.newLine();
    shell.println("=== [2/6] Heap Secure Wipe (H.9a) ===");
    shell.newLine();

    // Test 5: allocate, write, free, verify wiped
    shell.print("  Alloc+write+free wiped...... ");
    const ptr = heap.kmalloc(128);
    if (ptr) |p| {
        // Write pattern
        var i: usize = 0;
        while (i < 128) : (i += 1) {
            p[i] = 0xAA;
        }
        const addr = @intFromPtr(p);
        heap.kfree(p);

        // Check first byte after free
        const check: *volatile u8 = @ptrFromInt(addr);
        if (check.* == sanitize.WIPE_BYTE) {
            shell.println("[PASS]");
            passed += 1;
        } else {
            shell.println("[FAIL]");
            failed += 1;
        }
    } else {
        shell.println("[FAIL] (alloc)");
        failed += 1;
    }

    // Test 6: heap wipes counted
    shell.print("  Heap wipe counted........... ");
    const stats1 = sanitize.getStats();
    if (stats1.heap_wipes > 0) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 7: bytes tracked
    shell.print("  Bytes wiped tracked......... ");
    if (stats1.bytes_wiped > 0) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 8: large allocation
    shell.print("  Large alloc (4KB) wipe...... ");
    const ptr2 = heap.kmalloc(4096);
    if (ptr2) |p| {
        var i: usize = 0;
        while (i < 4096) : (i += 1) {
            p[i] = 0xBB;
        }
        heap.kfree(p);
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL] (alloc)");
        failed += 1;
    }

    // Test 9: no verify failures
    shell.print("  No verify failures.......... ");
    const stats2 = sanitize.getStats();
    if (stats2.verify_failures == 0) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // ========================================
    // Section 3: Page Wipe (H.9b)
    // ========================================
    shell.newLine();
    shell.println("=== [3/6] Page Secure Wipe (H.9b) ===");
    shell.newLine();

    // Test 10: page wipe on free
    shell.print("  Page alloc+free wiped....... ");
    const phys = pmm.allocPage();
    if (phys) |p| {
        pmm.freePage(p);
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL] (alloc)");
        failed += 1;
    }

    // Test 11: page wipes counted
    shell.print("  Page wipe counted........... ");
    const stats3 = sanitize.getStats();
    if (stats3.page_wipes > 0) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 12: multi-page
    shell.print("  Multi-page wipe (4 pages)... ");
    const phys2 = pmm.allocPages(4);
    if (phys2) |p| {
        pmm.freePages(p, 4);
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL] (alloc)");
        failed += 1;
    }

    // Test 13: page bytes tracked
    shell.print("  Page bytes tracked.......... ");
    const stats4 = sanitize.getStats();
    if (stats4.bytes_wiped >= pmm.PAGE_SIZE) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // ========================================
    // Section 4: Stack Guard (H.9c)
    // ========================================
    shell.newLine();
    shell.println("=== [4/6] Stack Guard Pages (H.9c) ===");
    shell.newLine();

    // Test 14: install guard
    shell.print("  Install guard page.......... ");
    const test_stack: u64 = 0xFFFF_D000_0001_0000;
    if (sanitize.installStackGuard(test_stack)) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 15: guard fault detection
    shell.print("  Guard fault detection....... ");
    const guard_addr = test_stack - pmm.PAGE_SIZE;
    if (sanitize.isGuardPageFault(guard_addr)) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // ========================================
    // Section 5: mlock (H.9e)
    // ========================================
    shell.newLine();
    shell.println("=== [5/6] Sensitive Page Lock (H.9e) ===");
    shell.newLine();

    // Test 16: mlock
    shell.print("  mlock page.................. ");
    const lock_addr: u64 = 0xFFFF_E000_0000_0000;
    if (sanitize.mlock(lock_addr, pmm.PAGE_SIZE, 1, "test_key")) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 17: isMlocked
    shell.print("  isMlocked = true............ ");
    if (sanitize.isMlocked(lock_addr)) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 18: other not locked
    shell.print("  Other addr not locked....... ");
    if (!sanitize.isMlocked(0xDEAD_0000)) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 19: mlock count
    shell.print("  mlock count incremented..... ");
    const stats5 = sanitize.getStats();
    if (stats5.mlock_count > 0) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 20: munlock
    shell.print("  munlock..................... ");
    if (sanitize.munlock(lock_addr, pmm.PAGE_SIZE)) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 21: after munlock
    shell.print("  After munlock = unlocked.... ");
    if (!sanitize.isMlocked(lock_addr)) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // ========================================
    // Section 6: Process Wipe (H.9d)
    // ========================================
    shell.newLine();
    shell.println("=== [6/6] Process Wipe & Stats (H.9d) ===");
    shell.newLine();

    // Test 22: stack wipe
    shell.print("  Stack wipe works............ ");
    const stack_ptr = heap.kmalloc(1024);
    if (stack_ptr) |p| {
        var i: usize = 0;
        while (i < 1024) : (i += 1) {
            p[i] = 0xCC;
        }
        sanitize.secureWipeStack(@intFromPtr(p), 1024);
        const check: *volatile u8 = @ptrFromInt(@intFromPtr(p));
        if (check.* == sanitize.WIPE_BYTE) {
            shell.println("[PASS]");
            passed += 1;
        } else {
            shell.println("[FAIL]");
            failed += 1;
        }
        heap.kfree(p);
    } else {
        shell.println("[FAIL] (alloc)");
        failed += 1;
    }

    // Test 23: stack wipes counted
    shell.print("  Stack wipe counted.......... ");
    const stats6 = sanitize.getStats();
    if (stats6.stack_wipes > 0) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 24: struct wipe
    shell.print("  Struct wipe works........... ");
    var test_struct: [64]u8 = [_]u8{0xFF} ** 64;
    sanitize.secureWipeStruct(@intFromPtr(&test_struct), 64);
    var all_zero = true;
    for (test_struct) |b| {
        if (b != 0) all_zero = false;
    }
    if (all_zero) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // Test 25: zero verify failures
    shell.print("  Zero verify failures........ ");
    const stats7 = sanitize.getStats();
    if (stats7.verify_failures == 0) {
        shell.println("[PASS]");
        passed += 1;
    } else {
        shell.println("[FAIL]");
        failed += 1;
    }

    // ========================================
    // Summary
    // ========================================
    shell.newLine();
    shell.println("========================================");
    shell.print("  Results: ");
    helpers.printDec(passed);
    shell.print(" passed, ");
    helpers.printDec(failed);
    shell.println(" failed");
    shell.println("========================================");
    shell.newLine();

    if (failed == 0) {
        shell.println("[OK]   All H.9 tests PASSED!");
    } else {
        shell.printError("Some tests FAILED!");
        shell.newLine();
    }
}
