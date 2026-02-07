//! Zamrud OS - Main Kernel with Security Integration

const cpu = @import("core/cpu.zig");
const limine = @import("core/limine.zig");
const config = @import("config.zig");

const serial = @import("drivers/serial/serial.zig");
const framebuffer = @import("drivers/display/framebuffer.zig");
const terminal = @import("drivers/display/terminal.zig");
const keyboard = @import("drivers/input/keyboard.zig");
const timer = @import("drivers/timer/timer.zig");

const gdt = @import("arch/x86_64/gdt.zig");
const idt = @import("arch/x86_64/idt.zig");

const pmm = @import("mm/pmm.zig");
const vmm = @import("mm/vmm.zig");
const memory = @import("mm/memory.zig");
const heap = @import("mm/heap.zig");

const process = @import("proc/process.zig");
const scheduler = @import("proc/scheduler.zig");
const user = @import("proc/user.zig");

const vfs = @import("fs/vfs.zig");
const ramfs = @import("fs/ramfs.zig");
const devfs = @import("fs/devfs.zig");

const syscall_mod = @import("syscall/syscall.zig");
const shell = @import("shell/shell.zig");

const crypto = @import("crypto/crypto.zig");
const chain = @import("chain/chain.zig");
const integrity = @import("integrity/integrity.zig");
const identity = @import("identity/identity.zig");

const boot_verify = @import("boot/verify.zig");
const net = @import("net/net.zig");
const firewall = @import("net/firewall.zig");
const p2p = @import("p2p/p2p.zig");
const gateway = @import("gateway/gateway.zig");

const smoke = @import("tests/smoke.zig");

const storage = @import("drivers/storage/storage.zig");

// ============================================================================
// Limine Requests
// ============================================================================

pub export var memmap_request: limine.MemoryMapRequest linksection(".limine_requests") = .{};
pub export var hhdm_request: limine.HhdmRequest linksection(".limine_requests") = .{};
pub export var framebuffer_request: limine.FramebufferRequest linksection(".limine_requests") = .{};

// ============================================================================
// Kernel Entry Point
// ============================================================================

export fn kernel_main() noreturn {
    cpu.enableSSE();

    // Simple ASCII banner
    serial.writeString("\n");
    serial.writeString("  ______                             _    ___  ____  \n");
    serial.writeString(" |___  /                            | |  / _ \\/ ___| \n");
    serial.writeString("    / / __ _ _ __ ___  _ __ _   _  __| | | | | \\___ \\ \n");
    serial.writeString("   / / / _` | '_ ` _ \\| '__| | | |/ _` | | | | |___) |\n");
    serial.writeString("  / /_| (_| | | | | | | |  | |_| | (_| | | |_| |____/ \n");
    serial.writeString(" /_____\\__,_|_| |_| |_|_|   \\__,_|\\__,_|  \\___/      \n");
    serial.writeString("\n");
    serial.writeString("  Kernel v");
    serial.writeString(config.version);
    serial.writeString(" | Mode: ");
    serial.writeString(config.getBuildMode());
    serial.writeString("\n");
    printLine();

    // === Initialization ===
    serial.writeString("[INIT] SSE: ");
    serial.writeString(if (cpu.hasSSE()) "Enabled\n" else "Not available\n");

    serial.writeString("[INIT] Boot Verification...\n");
    boot_verify.init();
    const verify_result = boot_verify.verify();
    if (verify_result.success) {
        serial.writeString("[OK]   Boot verified (");
        printDecSerial(verify_result.checks_passed);
        serial.writeString("/");
        printDecSerial(verify_result.checks_total);
        serial.writeString(")\n");
    } else {
        serial.writeString("[WARN] Boot verification failed\n");
    }

    serial.writeString("[INIT] GDT...\n");
    gdt.init();
    gdt.loadTSS();
    serial.writeString("[OK]   GDT loaded\n");

    serial.writeString("[INIT] IDT...\n");
    idt.init();
    serial.writeString("[OK]   IDT loaded\n");

    serial.writeString("[INIT] Keyboard...\n");
    keyboard.init();
    serial.writeString("[OK]   Keyboard ready\n");

    serial.writeString("[INIT] Timer...\n");
    timer.init();
    serial.writeString("[OK]   Timer ready\n");

    serial.writeString("[INIT] Interrupts...\n");
    idt.enableInterrupts();
    serial.writeString("[OK]   Interrupts enabled\n");

    printLine();
    serial.writeString("[MEMORY]\n");

    memory.init(&memmap_request, &hhdm_request);
    serial.writeString("[OK]   Memory map parsed\n");

    pmm.init(&memmap_request, &hhdm_request);
    serial.writeString("[OK]   PMM initialized\n");

    vmm.init();
    serial.writeString("[OK]   VMM initialized\n");

    heap.init();
    serial.writeString("[OK]   Heap initialized\n");

    printLine();
    serial.writeString("[SECURITY]\n");

    crypto.init();
    serial.writeString("[OK]   Crypto ready\n");

    integrity.init();
    serial.writeString("[OK]   Integrity ready\n");

    if (chain.init()) {
        serial.writeString("[OK]   Blockchain ready\n");
    } else {
        serial.writeString("[WARN] Blockchain failed\n");
    }

    identity.init();
    serial.writeString("[OK]   Identity ready\n");

    printLine();
    serial.writeString("[PROCESS]\n");

    process.init();
    process.createIdleProcess();
    serial.writeString("[OK]   Process manager ready\n");

    scheduler.init();
    serial.writeString("[OK]   Scheduler ready\n");

    printLine();
    serial.writeString("[FILESYSTEM]\n");

    vfs.init();
    serial.writeString("[OK]   VFS ready\n");

    if (ramfs.init()) {
        serial.writeString("[OK]   RAMFS ready\n");
    } else {
        serial.writeString("[WARN] RAMFS failed\n");
    }

    if (devfs.init()) {
        if (vfs.mount("/dev", devfs.getFilesystem())) {
            serial.writeString("[OK]   DevFS mounted\n");
        }
    }

    printLine();
    serial.writeString("[NETWORK]\n");

    net.init();
    serial.writeString("[OK]   Network stack ready\n");

    configureSecurityForEnvironment();
    serial.writeString("[OK]   Firewall configured\n");

    p2p.init();
    serial.writeString("[OK]   P2P ready\n");

    gateway.init();
    serial.writeString("[OK]   Gateway ready\n");

    printLine();
    serial.writeString("[USERSPACE]\n");

    syscall_mod.init();
    serial.writeString("[OK]   Syscall ready\n");

    user.init();
    serial.writeString("[OK]   User mode ready\n");

    framebuffer.init(&framebuffer_request);
    if (framebuffer.isInitialized()) {
        serial.writeString("[OK]   Framebuffer ready\n");

        terminal.init(
            framebuffer.getAddress(),
            framebuffer.getWidth(),
            framebuffer.getHeight(),
            framebuffer.getPitch(),
        );
        serial.writeString("[OK]   Terminal ready\n");
    }

    // Initialize storage
    storage.init();
    serial.writeString("[OK]   Storage ready\n");

    printLine();
    printSystemSummary();
    printLine();
    // ========================================
    // Smoke Tests (optional)
    // ========================================
    if (config.ENABLE_SMOKE_TEST) {
        smoke.runSmokeTests();
    }

    serial.writeString("[INIT] Starting shell...\n");
    shell.init();
    shell.run();

    serial.writeString("\n[HALT] System halted.\n");
    cpu.halt();
}

// ============================================================================
// Helpers
// ============================================================================

fn printLine() void {
    serial.writeString("----------------------------------------\n");
}

fn configureSecurityForEnvironment() void {
    const is_qemu = net.isVirtioAvailable() or net.isE1000Available();

    if (is_qemu) {
        firewall.config.p2p_only_mode = false;
        firewall.config.block_icmp = false;
        firewall.config.stealth_mode = false;
        firewall.config.log_blocked = true;
        firewall.setState(.enforcing);
    } else {
        firewall.config.p2p_only_mode = true;
        firewall.config.block_icmp = true;
        firewall.config.stealth_mode = true;
        firewall.config.auto_blacklist = true;
        firewall.setState(.enforcing);
    }
}

fn printSystemSummary() void {
    serial.writeString("\n");
    serial.writeString("  SYSTEM READY\n");
    serial.writeString("  -----------------------------\n");
    serial.writeString("  SSE:        ");
    serial.writeString(if (cpu.hasSSE()) "OK\n" else "NO\n");
    serial.writeString("  Boot:       ");
    serial.writeString(if (boot_verify.isVerified()) "Verified\n" else "Unverified\n");
    serial.writeString("  Crypto:     ");
    serial.writeString(if (crypto.isInitialized()) "OK\n" else "NO\n");
    serial.writeString("  Network:    ");
    serial.writeString(if (net.isInitialized()) "OK\n" else "NO\n");
    serial.writeString("  Firewall:   ");
    serial.writeString(if (firewall.isInitialized()) "Active\n" else "NO\n");
    serial.writeString("  Processes:  ");
    printDecSerial(process.getCount());
    serial.writeString("\n");
    serial.writeString("  -----------------------------\n");
    serial.writeString("  Type 'help' for commands\n\n");
}

// ============================================================================
// Panic Handler
// ============================================================================

pub fn panic(msg: []const u8, _: ?*@import("std").builtin.StackTrace, _: ?usize) noreturn {
    cpu.cli();

    serial.writeString("\n\n");
    serial.writeString("========================================\n");
    serial.writeString("  KERNEL PANIC\n");
    serial.writeString("========================================\n");
    serial.writeString("  Error: ");
    serial.writeString(msg);
    serial.writeString("\n");
    serial.writeString("  Uptime: ");
    printDecSerial(timer.getSeconds());
    serial.writeString("s\n");
    serial.writeString("========================================\n");
    serial.writeString("  System halted.\n");

    if (terminal.isInitialized()) {
        terminal.setFgColor(0xFF4444);
        terminal.clear();
        terminal.println("");
        terminal.println("  KERNEL PANIC");
        terminal.print("  ");
        terminal.println(msg);
        terminal.println("");
        terminal.println("  System halted. Please reboot.");
    }

    cpu.halt();
}

fn printDecSerial(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;

    while (v > 0) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
