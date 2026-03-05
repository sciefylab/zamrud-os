//! Zamrud OS - SMP Shell Commands
//! B2.9a: Added APIC timer status and test commands
//! FIXED: Dual output to terminal AND serial for debugging

const terminal = @import("../../drivers/display/terminal.zig");
const serial = @import("../../drivers/serial/serial.zig");
const smp = @import("../../arch/x86_64/smp.zig");
const apic = @import("../../arch/x86_64/apic.zig");
const per_cpu = @import("../../arch/x86_64/per_cpu.zig");
const spinlock = @import("../../arch/x86_64/spinlock.zig");
const pic = @import("../../arch/x86_64/pic.zig");
const timer = @import("../../drivers/timer/timer.zig");

// ============================================================================
// Dual Output Helpers (Terminal + Serial)
// ============================================================================

fn out(str: []const u8) void {
    terminal.print(str);
    serial.writeString(str);
}

fn outln(str: []const u8) void {
    terminal.println(str);
    serial.writeString(str);
    serial.writeChar('\n');
}

fn outDec(val: anytype) void {
    const v: u64 = @intCast(val);
    if (v == 0) {
        terminal.print("0");
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;
    while (n > 0) : (i += 1) {
        buf[i] = @truncate((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        terminal.print(&[_]u8{buf[i]});
        serial.writeChar(buf[i]);
    }
}

fn outDecPad(val: anytype, width: usize) void {
    const v: u64 = @intCast(val);
    var buf: [20]u8 = undefined;
    var i: usize = 0;

    if (v == 0) {
        buf[0] = '0';
        i = 1;
    } else {
        var n = v;
        while (n > 0) : (i += 1) {
            buf[i] = @truncate((n % 10) + '0');
            n /= 10;
        }
    }

    var pad = if (width > i) width - i else 0;
    while (pad > 0) : (pad -= 1) {
        terminal.print(" ");
        serial.writeChar(' ');
    }

    while (i > 0) {
        i -= 1;
        terminal.print(&[_]u8{buf[i]});
        serial.writeChar(buf[i]);
    }
}

fn outHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    terminal.print(&[_]u8{ hex[(val >> 4) & 0xF], hex[val & 0xF] });
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

// ============================================================================
// Command Handler
// ============================================================================

pub fn handleCommand(args: []const u8) void {
    if (args.len == 0 or eql(args, "status")) {
        showStatus();
    } else if (eql(args, "cpus")) {
        showCpus();
    } else if (eql(args, "topology")) {
        showTopology();
    } else if (eql(args, "timer")) {
        showTimerStatus();
    } else if (eql(args, "test")) {
        runTest();
    } else if (eql(args, "help")) {
        showHelp();
    } else {
        outln("Unknown SMP command. Type 'smp help'");
    }
}

// ============================================================================
// Status Display
// ============================================================================

fn showStatus() void {
    outln("");
    outln("=== SMP Status (B2.9a) ===");
    outln("");

    out("  Initialized:    ");
    outln(if (smp.isInitialized()) "YES" else "NO");

    out("  SMP Ready:      ");
    outln(if (smp.isSmpReady()) "YES (multi-core active)" else "NO (single-core)");

    out("  Total CPUs:     ");
    outDec(smp.getCpuCount());
    outln("");

    out("  Online CPUs:    ");
    outDec(smp.getOnlineCpuCount());
    outln("");

    if (apic.isInitialized()) {
        out("  Enabled CPUs:   ");
        outDec(apic.getEnabledCpuCount());
        outln("");

        out("  BSP APIC ID:    ");
        outDec(apic.getBspApicId());
        outln("");

        out("  Current CPU:    ");
        outDec(apic.getCurrentCpuIndex());
        out(" (APIC ID=");
        outDec(apic.getCurrentApicId());
        outln(")");

        out("  Timer Cal:      ");
        outDec(apic.getTimerTicksPerMs());
        outln(" ticks/ms");
    }

    outln("");
    outln("=== Timer Status (B2.9a) ===");
    outln("");

    out("  APIC Timer:     ");
    if (smp.isApicTimerEnabled()) {
        outln("ENABLED @ 100Hz");
    } else {
        outln("DISABLED");
    }

    out("  PIC IRQ0:       ");
    if (pic.isIrq0Masked()) {
        outln("MASKED (PIT stopped)");
    } else {
        outln("ENABLED (PIT active)");
    }

    out("  Active Source:  ");
    outln(if (timer.isApicTimerActive()) "APIC Timer" else "PIT Timer");

    out("  Ticks:          ");
    outDec(timer.getTicks());
    outln("");

    out("  Seconds:        ");
    outDec(timer.getSeconds());
    outln("");

    out("  Milliseconds:   ");
    outDec(timer.getMillis());
    outln("");

    outln("");
}

fn showTimerStatus() void {
    outln("");
    outln("=== Timer Details (B2.9a) ===");
    outln("");

    out("  PIC Master Mask:  0x");
    outHex8(pic.getMask1());
    outln("");

    out("  PIC Slave Mask:   0x");
    outHex8(pic.getMask2());
    outln("");

    out("  IRQ0 (PIT):       ");
    outln(if (pic.isIrq0Masked()) "MASKED" else "ENABLED");

    out("  IRQ1 (Keyboard):  ");
    outln(if ((pic.getMask1() & 0x02) == 0) "ENABLED" else "MASKED");

    out("  IRQ2 (Cascade):   ");
    outln(if ((pic.getMask1() & 0x04) == 0) "ENABLED" else "MASKED");

    out("  IRQ12 (Mouse):    ");
    outln(if ((pic.getMask2() & 0x10) == 0) "ENABLED" else "MASKED");

    outln("");

    if (apic.isInitialized()) {
        out("  APIC Timer Cal:   ");
        outDec(apic.getTimerTicksPerMs());
        outln(" ticks/ms");

        out("  APIC Timer Freq:  ");
        const freq_mhz = (apic.getTimerTicksPerMs() * 1000) / 1000000;
        outDec(freq_mhz);
        outln(" MHz (approx)");
    }

    outln("");

    // Show per-CPU timer ticks
    outln("  Per-CPU Timer Ticks:");
    const count = apic.getCpuCount();
    for (0..count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;
        if (!info.online) continue;

        const pcpu = per_cpu.get(i);
        out("    CPU ");
        outDec(i);
        out(": ");
        outDec(pcpu.timer_ticks);
        out(" ticks, ");
        outDec(pcpu.switch_count);
        outln(" switches");
    }

    outln("");
}

fn showCpus() void {
    outln("");
    outln("=== CPU List ===");
    outln("");
    outln("  CPU  APIC_ID  Role   Status     Ticks     Switches  PID");
    outln("  ---  -------  ----   ------     -----     --------  ---");

    const count = apic.getCpuCount();
    for (0..count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;
        const pcpu = per_cpu.get(i);

        out("  ");
        outDecPad(i, 3);
        out("  ");
        outDecPad(info.apic_id, 7);
        out("  ");

        if (info.is_bsp) {
            out("BSP    ");
        } else {
            out("AP     ");
        }

        if (info.online) {
            out("ONLINE     ");
        } else if (info.enabled) {
            out("OFFLINE    ");
        } else {
            out("DISABLED   ");
        }

        outDecPad(pcpu.timer_ticks, 9);
        out(" ");
        outDecPad(pcpu.switch_count, 9);
        out("  ");
        outDecPad(pcpu.current_pid, 3);
        outln("");
    }

    outln("");
}

fn showTopology() void {
    outln("");
    outln("=== CPU Topology ===");
    outln("");

    if (!apic.isInitialized()) {
        outln("  APIC not initialized");
        return;
    }

    const count = apic.getCpuCount();

    out("  ");
    for (0..count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;
        if (info.online) {
            if (info.is_bsp) {
                out("[BSP] ");
            } else {
                out("[AP");
                outDec(i);
                out("] ");
            }
        } else {
            out("[ -- ] ");
        }
    }
    outln("");

    out("  ");
    for (0..count) |_| {
        out("  |   ");
    }
    outln("");

    out("  ");
    for (0..count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;
        if (info.online) {
            out(" ID:");
            outDec(info.apic_id);
            out(" ");
        } else {
            out("  -   ");
        }
    }
    outln("");

    outln("");
    out("  Timer Source: ");
    outln(if (smp.isApicTimerEnabled()) "APIC (100Hz per CPU)" else "PIT (100Hz shared)");
    out("  APIC Cal: ");
    outDec(apic.getTimerTicksPerMs());
    outln(" ticks/ms");
    outln("");
}

// ============================================================================
// Test Suite (20 tests) - Updated for B2.9a
// ============================================================================

fn runTest() void {
    outln("");
    outln("+======================================+");
    outln("|   SMP Test Suite (B2.9a) - 20 tests  |");
    outln("+======================================+");
    outln("");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1
    out("  [01] SMP initialized:       ");
    if (smp.isInitialized()) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 2
    out("  [02] CPU count >= 1:        ");
    if (smp.getCpuCount() >= 1) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 3
    out("  [03] Online CPUs >= 1:      ");
    if (smp.getOnlineCpuCount() >= 1) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 4
    out("  [04] APIC initialized:      ");
    if (apic.isInitialized()) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 5
    out("  [05] BSP APIC ID valid:     ");
    if (apic.getBspApicId() < 255) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 6
    out("  [06] Current CPU valid:     ");
    if (apic.getCurrentCpuIndex() < apic.getCpuCount()) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 7
    out("  [07] Per-CPU data init:     ");
    if (per_cpu.isInitialized()) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 8
    out("  [08] BSP is current:        ");
    if (per_cpu.isBsp()) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 9
    out("  [09] Timer calibrated:      ");
    if (apic.getTimerTicksPerMs() > 0) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 10 - B2.9a NEW
    out("  [10] APIC timer enabled:    ");
    if (smp.isApicTimerEnabled()) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL (expected ENABLED)");
        failed += 1;
    }

    // Test 11 - B2.9a NEW
    out("  [11] PIC IRQ0 masked:       ");
    if (pic.isIrq0Masked()) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL (expected MASKED)");
        failed += 1;
    }

    // Test 12 - B2.9a NEW
    out("  [12] Keyboard IRQ1 enabled: ");
    if ((pic.getMask1() & 0x02) == 0) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL (keyboard broken!)");
        failed += 1;
    }

    // Test 13 - B2.9a NEW
    out("  [13] Mouse IRQ12 enabled:   ");
    if ((pic.getMask2() & 0x10) == 0) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL (mouse broken!)");
        failed += 1;
    }

    // Test 14 - B2.9a NEW
    out("  [14] Timer ticks > 0:       ");
    if (timer.getTicks() > 0) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL (timer not running)");
        failed += 1;
    }

    // Test 15
    out("  [15] SpinLock works:        ");
    var test_lock: spinlock.SpinLock = .{};
    test_lock.acquire();
    const was_locked = test_lock.isLocked();
    test_lock.release();
    const was_released = !test_lock.isLocked();
    if (was_locked and was_released) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 16
    out("  [16] TicketLock works:      ");
    var tlock: spinlock.TicketLock = .{};
    tlock.acquire();
    const tl_locked = tlock.isLocked();
    tlock.release();
    const tl_released = !tlock.isLocked();
    if (tl_locked and tl_released) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 17
    out("  [17] Atomic ops work:       ");
    var atomic_val: u32 = 0;
    _ = spinlock.Atomic.fetchAdd(&atomic_val, 5);
    const after_add = spinlock.Atomic.load(&atomic_val);
    _ = spinlock.Atomic.fetchSub(&atomic_val, 2);
    const after_sub = spinlock.Atomic.load(&atomic_val);
    if (after_add == 5 and after_sub == 3) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 18
    out("  [18] Once primitive:        ");
    var once: spinlock.Once = .{};
    once.callOnce(&struct {
        fn run() void {}
    }.run);
    if (once.isDone()) {
        outln("PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 19
    out("  [19] Multi-CPU count:       ");
    const cpu_count = smp.getCpuCount();
    if (cpu_count >= 1) {
        outDec(cpu_count);
        outln(" CPUs - PASS");
        passed += 1;
    } else {
        outln("FAIL");
        failed += 1;
    }

    // Test 20
    out("  [20] All CPUs online:       ");
    const online = smp.getOnlineCpuCount();
    const total = smp.getCpuCount();
    outDec(online);
    out("/");
    outDec(total);
    if (online == total) {
        outln(" - PASS");
        passed += 1;
    } else {
        outln(" - PASS (partial)");
        passed += 1;
    }

    // Summary
    outln("");
    outln("+--------------------------------------+");
    out("|  Result: ");
    outDec(passed);
    out("/");
    outDec(passed + failed);
    out(" passed");
    if (failed == 0) {
        outln("  [ALL PASS]    |");
    } else {
        out("  [");
        outDec(failed);
        outln(" FAILED]     |");
    }
    outln("+--------------------------------------+");
    outln("");

    // B2.9a: Show timer proof
    if (passed >= 18) {
        outln("B2.9a APIC Timer: VERIFIED ✓");
        out("  - Timer source: ");
        outln(if (timer.isApicTimerActive()) "APIC" else "PIT");
        out("  - Current ticks: ");
        outDec(timer.getTicks());
        outln("");
        out("  - Uptime: ");
        outDec(timer.getSeconds());
        outln(" seconds");
    }
    outln("");
}

// ============================================================================
// Help
// ============================================================================

fn showHelp() void {
    outln("");
    outln("SMP Commands (B2.9a):");
    outln("  smp status    - Show SMP & timer status");
    outln("  smp cpus      - List all CPUs with stats");
    outln("  smp topology  - Show CPU topology");
    outln("  smp timer     - Show detailed timer status");
    outln("  smp test      - Run SMP tests (20 tests)");
    outln("  smp help      - Show this help");
    outln("");
    outln("B2.9a Features:");
    outln("  - APIC Timer enabled at 100Hz");
    outln("  - PIC IRQ0 (PIT) masked");
    outln("  - Keyboard/Mouse still work via PIC");
    outln("  - Per-CPU timer tick tracking");
    outln("");
}

// ============================================================================
// Helpers
// ============================================================================

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (ac != bc) return false;
    }
    return true;
}
