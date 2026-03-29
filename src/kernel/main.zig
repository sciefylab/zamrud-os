//! Zamrud OS - Main Kernel with Security Integration
//! Phases A-F4.2 + SC1 + H.7 + B2.9 SMP Complete
//! FIXED: Terminal init BEFORE ceremony so UI renders on screen

const cpu = @import("core/cpu.zig");
const limine = @import("core/limine.zig");
const config = @import("config.zig");

const serial = @import("drivers/serial/serial.zig");
const framebuffer = @import("drivers/display/framebuffer.zig");
const terminal = @import("drivers/display/terminal.zig");
const keyboard = @import("drivers/input/keyboard.zig");
const mouse = @import("drivers/input/mouse.zig");
const timer = @import("drivers/timer/timer.zig");

const gdt = @import("arch/x86_64/gdt.zig");
const idt = @import("arch/x86_64/idt.zig");
const smp = @import("arch/x86_64/smp.zig");

const pmm = @import("mm/pmm.zig");
const vmm = @import("mm/vmm.zig");
const memory = @import("mm/memory.zig");
const heap = @import("mm/heap.zig");
const sanitize = @import("mm/sanitize.zig");

const process = @import("proc/process.zig");
const scheduler = @import("proc/scheduler.zig");
const user = @import("proc/user.zig");

const vfs = @import("fs/vfs.zig");
const ramfs = @import("fs/ramfs.zig");
const devfs = @import("fs/devfs.zig");
const fat32 = @import("fs/fat32.zig");

const syscall_mod = @import("syscall/table.zig");
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

// D3: Config & Identity Persistence
const config_store = @import("persist/config_store.zig");
const identity_store = @import("persist/identity_store.zig");

// E3.1: Process Capabilities
const capability = @import("security/capability.zig");

// E3.2: Filesystem Sandbox
const unveil = @import("security/unveil.zig");

// E3.3: Binary Verification
const binaryverify = @import("security/binaryverify.zig");

// E3.4: Network Capability
const net_capability = @import("security/net_capability.zig");

// E3.5: Unified Violation Handler
const violation = @import("security/violation.zig");

// F1: IPC
const ipc = @import("ipc/ipc.zig");

// F3: User/Group Permissions
const users = @import("security/users.zig");
const user_chain = @import("security/user_chain.zig");

// F4: Encrypted Filesystem
const encryptfs = @import("fs/encryptfs.zig");

// F4.1: Encryption Integration
const enc_integration = @import("fs/enc_integration.zig");

// F4.2: System Data Encryption
const sys_encrypt = @import("crypto/sys_encrypt.zig");

// F5.0: ZAM Binary Loader
const loader = @import("loader/loader.zig");

// H.7: Trust Ceremony
const trust_ceremony = @import("boot/trust_ceremony.zig");

const acpi = @import("drivers/acpi/acpi.zig");

const rtc = @import("drivers/timer/rtc.zig");

const usb_core = @import("drivers/usb/usb.zig");
const usb_hid = @import("drivers/usb/hid.zig");

const audio = @import("drivers/audio/audio.zig");

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

    // =====================================================================
    // INPUT DRIVERS: Keyboard FIRST, then Mouse LAST
    // =====================================================================

    serial.writeString("[INIT] Keyboard...\n");
    keyboard.init();
    serial.writeString("[OK]   Keyboard ready\n");

    serial.writeString("[INIT] Mouse...\n");
    mouse.init();
    serial.writeString("[OK]   Mouse ready\n");

    serial.writeString("[INIT] Timer...\n");
    timer.init();
    serial.writeString("[OK]   Timer ready\n");

    serial.writeString("[INIT] RTC...\n");
    rtc.init();
    serial.writeString("[OK]   RTC ready\n");

    fixupPS2Config();

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

    // Initialize ACPI (setelah PMM dan VMM)
    _ = acpi.init();
    serial.writeString("[OK]   ACPI initialized\n");

    heap.init();
    serial.writeString("[OK]   Heap initialized\n");

    sanitize.init();
    serial.writeString("[OK]   Memory sanitization ready (H.9)\n");

    // =====================================================================
    // B2.9: SMP Initialization (after memory & ACPI, before security)
    // =====================================================================
    printLine();
    serial.writeString("[SMP]\n");

    if (smp.init()) {
        serial.writeString("[OK]   SMP: ");
        printDecSerial(smp.getOnlineCpuCount());
        serial.writeString(" CPUs online\n");
    } else {
        serial.writeString("[WARN] SMP init failed, single-CPU mode\n");
    }

    printLine();
    serial.writeString("[SECURITY]\n");

    capability.init();
    serial.writeString("[OK]   Capabilities ready (E3.1)\n");

    unveil.init();
    serial.writeString("[OK]   Unveil sandbox ready (E3.2)\n");

    binaryverify.init();
    serial.writeString("[OK]   Binary verify ready (E3.3)\n");

    violation.init();
    serial.writeString("[OK]   Violation handler ready (E3.5)\n");

    crypto.init();
    serial.writeString("[OK]   Crypto ready\n");

    sys_encrypt.init();
    serial.writeString("[OK]   System encryption ready (F4.2)\n");

    integrity.init();
    serial.writeString("[OK]   Integrity ready\n");

    identity.init();
    serial.writeString("[OK]   Identity ready\n");

    printLine();
    serial.writeString("[PROCESS]\n");

    process.init();
    process.createIdleProcess();
    serial.writeString("[OK]   Process manager ready\n");

    scheduler.init();
    serial.writeString("[OK]   Scheduler ready\n");

    // B2.9a: Now safe to call scheduler from APIC timer handler
    smp.enableSchedulerCalls();

    ipc.init();
    serial.writeString("[OK]   IPC ready (F1)\n");

    encryptfs.init();
    serial.writeString("[OK]   EncryptFS ready (F4.0)\n");

    enc_integration.init();
    serial.writeString("[OK]   EncFS Integration ready (F4.1)\n");

    printLine();
    serial.writeString("[FILESYSTEM]\n");

    vfs.init();
    serial.writeString("[OK]   VFS ready\n");

    if (ramfs.init()) {
        serial.writeString("[OK]   RAMFS ready\n");
    } else {
        serial.writeString("[WARN] RAMFS failed\n");
    }

    if (vfs.ensureDir("/home")) {
        serial.writeString("[OK]   /home created\n");
    }
    if (vfs.ensureDir("/tmp")) {
        serial.writeString("[OK]   /tmp created\n");
    }

    if (devfs.init()) {
        if (vfs.mount("/dev", devfs.getFilesystem())) {
            serial.writeString("[OK]   DevFS mounted\n");
        }
    }

    printLine();
    serial.writeString("[STORAGE]\n");

    storage.init();
    serial.writeString("[OK]   Storage ready\n");

    // === USB Subsystem (B2.11) ===
    printLine();
    serial.writeString("[USB]\n");

    if (usb_core.init()) {
        serial.writeString("[OK]   USB: ");
        printDecSerial(usb_core.getControllerCount());
        serial.writeString(" controller(s), ");
        printDecSerial(usb_core.getDeviceCount());
        serial.writeString(" device(s)\n");

        // Initialize HID driver
        usb_hid.init();
        serial.writeString("[OK]   USB HID: ");
        printDecSerial(usb_hid.getKeyboardCount());
        serial.writeString(" keyboard(s), ");
        printDecSerial(usb_hid.getMouseCount());
        serial.writeString(" mouse(s)\n");
    } else {
        serial.writeString("[INFO] USB: No controllers found\n");
    }

    // === Audio Subsystem (B2.10) ===
    printLine();
    serial.writeString("[AUDIO]\n");

    if (audio.init()) {
        serial.writeString("[OK]   Audio: ");
        serial.writeString(audio.getBackendName());
        serial.writeString(" backend\n");
    } else {
        serial.writeString("[INFO] Audio: No sound device found\n");
    }

    fat32.init();
    if (fat32.isMounted()) {
        serial.writeString("[OK]   FAT32 mounted\n");

        if (fat32.mountToVfs()) {
            serial.writeString("[OK]   FAT32 -> VFS /disk\n");
        } else {
            serial.writeString("[WARN] FAT32 VFS mount failed\n");
        }
    } else {
        serial.writeString("[WARN] FAT32 not mounted\n");
    }

    if (chain.init()) {
        serial.writeString("[OK]   Blockchain ready");
        if (chain.hasSavedChain()) {
            serial.writeString(" (restored from disk)");
        }
        serial.writeString("\n");
    } else {
        serial.writeString("[WARN] Blockchain failed\n");
    }

    // =====================================================================
    // DISPLAY: Framebuffer & Terminal — MUST be before ceremony!
    // =====================================================================
    printLine();
    serial.writeString("[DISPLAY]\n");

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

        mouse.setScreenSize(framebuffer.getWidth(), framebuffer.getHeight());
        serial.writeString("[OK]   Mouse screen size set\n");
    }

    // =========================================================================
    // H.7: Persistence & Ceremony (terminal is now available for UI!)
    // =========================================================================
    printLine();
    serial.writeString("[PERSISTENCE & CEREMONY]\n");

    // Step 1: Initialize stores
    config_store.init();
    identity_store.init();

    // Step 2: Initialize ceremony (before checking files)
    trust_ceremony.init();

    // Step 3: Check if valid saved data exists
    const has_valid_identities = identity_store.hasSavedIdentities();
    const has_config_file = config_store.hasSavedConfig();
    const has_identity_file = identity_store.hasIdentityFile();

    serial.writeString("[DEBUG] Valid identities on disk: ");
    serial.writeString(if (has_valid_identities) "YES\n" else "NO\n");
    serial.writeString("[DEBUG] Config file exists: ");
    serial.writeString(if (has_config_file) "YES\n" else "NO\n");

    // Step 4: Determine boot mode
    if (!has_valid_identities and !has_identity_file) {
        // FIRST BOOT: No identity file at all
        serial.writeString("\n[CEREMONY] First boot detected!\n");

        if (trust_ceremony.runCeremony()) {
            serial.writeString("[CEREMONY] Completed successfully\n");
            trust_ceremony.setJustCompleted(true);
        } else {
            serial.writeString("[CEREMONY] Cancelled or failed\n");
        }
    } else if (!has_valid_identities and has_identity_file) {
        // CORRUPTED: File exists but invalid
        serial.writeString("\n[BOOT] Identity file exists but invalid!\n");
        serial.writeString("[BOOT] Load error: ");

        const err = identity_store.getLastLoadError();
        switch (err) {
            .invalid_magic => serial.writeString("invalid magic\n"),
            .unsupported_version => serial.writeString("unsupported version\n"),
            .checksum_mismatch => serial.writeString("checksum mismatch\n"),
            else => serial.writeString("unknown\n"),
        }

        serial.writeString("[BOOT] Options:\n");
        serial.writeString("  1. Run 'ceremony reset' then 'ceremony start'\n");
        serial.writeString("  2. Or restore from backup\n");

        trust_ceremony.setJustCompleted(false);
    } else {
        // RETURNING USER: Valid identity file
        serial.writeString("[BOOT] Returning user detected\n");

        trust_ceremony.setReturningUser(true);

        if (has_config_file) {
            if (config_store.loadFromDisk()) {
                serial.writeString("[OK]   Config: ");
                printDecSerial(config_store.getEntryCount());
                serial.writeString(" entries\n");
            } else {
                serial.writeString("[INFO] Config encrypted - will load after login\n");
            }
        }
    }

    // === F3: User/Group System ===
    printLine();
    serial.writeString("[USER SYSTEM]\n");

    user_chain.init();
    serial.writeString("[OK]   User/Chain bridge ready\n");

    users.init();
    serial.writeString("[OK]   User/Group system ready (F3)\n");

    // Auto-create root user from first identity if exists
    if (identity.getIdentityCount() > 0) {
        const first_id = identity.getCurrentIdentity();
        if (first_id != null and first_id.?.has_name) {
            const id_name = first_id.?.getName();
            if (users.findUserByName(id_name) == null) {
                if (users.createUser(id_name) != null) {
                    serial.writeString("[OK]   Root user auto-created from identity: ");
                    serial.writeString(id_name);
                    serial.writeString("\n");
                }
            } else {
                serial.writeString("[OK]   User already exists: ");
                serial.writeString(id_name);
                serial.writeString("\n");
            }
        }
    }

    serial.writeString("[OK]   Users: ");
    printDecSerial(users.getUserCount());
    serial.writeString(", Groups: ");
    printDecSerial(users.getGroupCount());
    serial.writeString("\n");

    printLine();
    serial.writeString("[NETWORK]\n");

    net.init();
    serial.writeString("[OK]   Network stack ready\n");

    configureSecurityForEnvironment();
    serial.writeString("[OK]   Firewall configured\n");

    net_capability.init();
    serial.writeString("[OK]   Network capability ready (E3.4)\n");

    p2p.init();
    serial.writeString("[OK]   P2P ready\n");

    gateway.init();
    serial.writeString("[OK]   Gateway ready\n");

    // === USERSPACE (framebuffer/terminal already initialized above) ===
    printLine();
    serial.writeString("[USERSPACE]\n");

    syscall_mod.init();
    serial.writeString("[OK]   Syscall ready (SC1 unified)\n");

    user.init();
    serial.writeString("[OK]   User mode ready\n");

    // === F5.0: ZAM Binary Loader ===
    printLine();
    serial.writeString("[LOADER]\n");

    loader.init();
    serial.writeString("[OK]   ZAM binary loader ready (F5.0)\n");

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

    // B2.9b: Enable AP scheduling after all init complete
    smp.enableApScheduling();
    serial.writeString("[OK]   AP scheduling enabled\n");

    shell.run();

    serial.writeString("\n[HALT] System halted.\n");

    // B2.9: Halt all CPUs on shutdown
    if (smp.isSmpReady()) {
        smp.sendHaltIpiAll();
    }

    cpu.halt();
}

// ============================================================================
// PS/2 Controller Config Fixup
// ============================================================================

fn fixupPS2Config() void {
    ps2WaitWrite();
    cpu.outb(0x64, 0x20);
    ps2WaitRead();
    var cfg = cpu.inb(0x60);

    const old_cfg = cfg;

    cfg |= 0x01;
    cfg |= 0x02;
    cfg &= ~@as(u8, 0x10);
    cfg &= ~@as(u8, 0x20);

    if (cfg != old_cfg) {
        ps2WaitWrite();
        cpu.outb(0x64, 0x60);
        ps2WaitWrite();
        cpu.outb(0x60, cfg);

        serial.writeString("[OK]   PS/2 config fixed: 0x");
        printHexByte(old_cfg);
        serial.writeString(" -> 0x");
        printHexByte(cfg);
        serial.writeString("\n");
    } else {
        serial.writeString("[OK]   PS/2 config OK: 0x");
        printHexByte(cfg);
        serial.writeString("\n");
    }

    ps2WaitWrite();
    cpu.outb(0x64, 0x20);
    ps2WaitRead();
    const verify = cpu.inb(0x60);

    if ((verify & 0x02) == 0 or (verify & 0x20) != 0) {
        serial.writeString("[WARN] PS/2 config verify FAILED: 0x");
        printHexByte(verify);
        serial.writeString("\n");
    }
}

fn ps2WaitWrite() void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(0x64) & 0x02) == 0) return;
    }
}

fn ps2WaitRead() void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(0x64) & 0x01) != 0) return;
    }
}

fn printHexByte(value: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(value >> 4) & 0x0F]);
    serial.writeChar(hex[value & 0x0F]);
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

    // B2.9: SMP status
    serial.writeString("  SMP(B2.9):  ");
    if (smp.isInitialized()) {
        printDecSerial(smp.getOnlineCpuCount());
        serial.writeString("/");
        printDecSerial(smp.getCpuCount());
        serial.writeString(" CPUs online");
        if (smp.isSmpReady()) {
            serial.writeString(" [ACTIVE]");
        } else {
            serial.writeString(" [SINGLE]");
        }
        serial.writeString("\n");
    } else {
        serial.writeString("Not initialized\n");
    }

    serial.writeString("  Crypto:     ");
    serial.writeString(if (crypto.isInitialized()) "OK\n" else "NO\n");
    serial.writeString("  Caps(E3.1): ");
    serial.writeString(if (capability.isInitialized()) "ACTIVE\n" else "NO\n");
    serial.writeString("  Unveil(E3.2):");
    serial.writeString(if (unveil.isInitialized()) "ACTIVE\n" else "NO\n");
    serial.writeString("  BinVerify:  ");
    if (binaryverify.isInitialized()) {
        serial.writeString(if (binaryverify.isEnforcing()) "ENFORCING" else "WARN");
        serial.writeString(" (");
        printDecSerial(binaryverify.getTrustCount());
        serial.writeString(" trusted)\n");
    } else {
        serial.writeString("NO\n");
    }
    serial.writeString("  NetCap(E3.4):");
    if (net_capability.isInitialized()) {
        serial.writeString("ACTIVE (");
        printDecSerial(net_capability.getProcessCount());
        serial.writeString(" procs, ");
        printDecSerial(net_capability.getActiveSocketCount());
        serial.writeString(" socks)\n");
    } else {
        serial.writeString("NO\n");
    }
    serial.writeString("  ViolHdl(E3.5):");
    if (violation.isInitialized()) {
        printDecSerial(violation.getStats().total_incidents);
        serial.writeString(" incidents (");
        printDecSerial(violation.getStats().kills);
        serial.writeString(" kills, ");
        printDecSerial(violation.getStats().blacklists);
        serial.writeString(" bans)\n");
    } else {
        serial.writeString("Not initialized\n");
    }
    serial.writeString("  IPC(F1):    ");
    if (ipc.isInitialized()) {
        serial.writeString("OK (");
        printDecSerial(ipc.message.getMailboxCount());
        serial.writeString(" mbox, ");
        printDecSerial(ipc.pipe.getActivePipeCount());
        serial.writeString(" pipes, ");
        printDecSerial(ipc.signal.getRegisteredCount());
        serial.writeString(" sig)\n");
    } else {
        serial.writeString("Not initialized\n");
    }
    serial.writeString("  Users(F3):  ");
    if (users.isInitialized()) {
        serial.writeString("OK (");
        printDecSerial(users.getUserCount());
        serial.writeString(" users, ");
        printDecSerial(users.getGroupCount());
        serial.writeString(" groups");
        if (users.isLoggedIn()) {
            serial.writeString(", logged in: ");
            serial.writeString(users.getCurrentSession().getName());
        }
        serial.writeString(")\n");
    } else {
        serial.writeString("Not initialized\n");
    }

    serial.writeString("  EncFS(F4.0):");
    if (encryptfs.isInitialized()) {
        serial.writeString("OK (");
        printDecSerial(encryptfs.getStats().files);
        serial.writeString(" files, ");
        serial.writeString(if (encryptfs.isKeySet()) "unlocked" else "locked");
        serial.writeString(")\n");
    } else {
        serial.writeString("Not initialized\n");
    }

    serial.writeString("  EncInt(F4.1):");
    if (enc_integration.isInitialized()) {
        serial.writeString("OK (");
        serial.writeString(if (enc_integration.isKeyActive()) "active" else "locked");
        serial.writeString(", role=");
        serial.writeString(enc_integration.getCurrentOwnerRole().toString());
        serial.writeString(")\n");
    } else {
        serial.writeString("Not initialized\n");
    }

    serial.writeString("  SysEnc(F4.2):");
    if (sys_encrypt.isInitialized()) {
        serial.writeString("OK (");
        serial.writeString(if (sys_encrypt.isMasterKeySet()) "key SET" else "no key");
        serial.writeString(", enc=");
        printDecSerial(sys_encrypt.getStats().encrypts);
        serial.writeString(", dec=");
        printDecSerial(sys_encrypt.getStats().decrypts);
        serial.writeString(")\n");
    } else {
        serial.writeString("Not initialized\n");
    }

    serial.writeString("  MemSan(H.9):");
    if (sanitize.isInitialized()) {
        const san_stats = sanitize.getStats();
        serial.writeString("OK (");
        printDecSerial(san_stats.heap_wipes);
        serial.writeString(" heap, ");
        printDecSerial(san_stats.page_wipes);
        serial.writeString(" page, ");
        printDecSerial(san_stats.mlock_count);
        serial.writeString(" locked)\n");
    } else {
        serial.writeString("Not initialized\n");
    }

    serial.writeString("  Ceremony:   ");
    if (trust_ceremony.isInitialized()) {
        if (trust_ceremony.isCeremonyComplete()) {
            serial.writeString("COMPLETE (v");
            printDecSerial(trust_ceremony.getCeremonyVersion());
            serial.writeString(")\n");
        } else {
            serial.writeString("INCOMPLETE\n");
        }
    } else {
        serial.writeString("Not initialized\n");
    }

    serial.writeString("  Syscall(SC1):");
    if (syscall_mod.isInitialized()) {
        serial.writeString("OK (");
        printDecSerial(syscall_mod.getSyscallCount());
        serial.writeString(" calls)\n");
    } else {
        serial.writeString("Not initialized\n");
    }

    serial.writeString("  Storage:    ");
    serial.writeString(if (storage.isInitialized()) "OK\n" else "NO\n");
    serial.writeString("  FAT32:      ");
    serial.writeString(if (fat32.isMounted()) "Mounted\n" else "Not mounted\n");
    serial.writeString("  Blockchain: ");
    if (chain.isInitialized()) {
        serial.writeString("OK (height=");
        printDecSerial(chain.getHeight());
        serial.writeString(", blocks=");
        printDecSerial(chain.getBlockCount());
        serial.writeString(")\n");
    } else {
        serial.writeString("Not initialized\n");
    }
    serial.writeString("  USB(B2.11): ");
    if (usb_core.isInitialized()) {
        printDecSerial(usb_core.getControllerCount());
        serial.writeString(" ctrl, ");
        printDecSerial(usb_core.getDeviceCount());
        serial.writeString(" dev");
        if (usb_core.hasUhci()) serial.writeString(" [UHCI]");
        if (usb_core.hasEhci()) serial.writeString(" [EHCI]");
        serial.writeString("\n");
    } else {
        serial.writeString("Not initialized\n");
    }
    serial.writeString("  Audio(B2.10):");
    if (audio.isInitialized()) {
        serial.writeString(audio.getBackendName());
        serial.writeString(" (");
        if (audio.isPlaying()) serial.writeString("PLAYING") else serial.writeString("idle");
        serial.writeString(", vol=");
        printDecSerial(audio.getVolumePercent());
        serial.writeString("%)\n");
    } else {
        serial.writeString("Not found\n");
    }
    serial.writeString("  Config:     ");
    if (config_store.isInitialized()) {
        serial.writeString("OK (");
        printDecSerial(config_store.getEntryCount());
        serial.writeString(" entries");
        if (config_store.wasLoadedFromDisk()) {
            serial.writeString(", from disk");
        }
        if (config_store.isEncryptionActive()) {
            serial.writeString(", ENCRYPTED");
        }
        serial.writeString(")\n");
    } else {
        serial.writeString("Not initialized\n");
    }
    serial.writeString("  Identities: ");
    if (identity.isInitialized()) {
        printDecSerial(identity.getIdentityCount());
        if (identity_store.wasLoadedFromDisk()) {
            serial.writeString(" (from disk)");
        }
        if (identity_store.isEncryptionActive()) {
            serial.writeString(" [ENCRYPTED]");
        }
        serial.writeString("\n");
    } else {
        serial.writeString("Not initialized\n");
    }
    serial.writeString("  Network:    ");
    serial.writeString(if (net.isInitialized()) "OK\n" else "NO\n");
    serial.writeString("  Firewall:   ");
    serial.writeString(if (firewall.isInitialized()) "Active\n" else "NO\n");
    serial.writeString("  Processes:  ");
    printDecSerial(process.getCount());
    serial.writeString("\n");
    serial.writeString("  Violations: ");
    printDecSerial(capability.getTotalViolations());
    serial.writeString("\n");
    serial.writeString("  FS Sandbox: ");
    printDecSerial(unveil.getTableCount());
    serial.writeString(" tables, ");
    printDecSerial(unveil.getViolationCount());
    serial.writeString(" violations\n");
    serial.writeString("  Net Viols:  ");
    printDecSerial(net_capability.getStats().violations_total);
    serial.writeString(" (");
    printDecSerial(net_capability.getStats().processes_killed);
    serial.writeString(" killed)\n");
    serial.writeString("  Sec Pipeline:");
    printDecSerial(violation.getStats().total_incidents);
    serial.writeString(" total, ");
    printDecSerial(violation.getStats().warns);
    serial.writeString(" warn, ");
    printDecSerial(violation.getStats().kills);
    serial.writeString(" kill, ");
    printDecSerial(violation.getStats().blacklists);
    serial.writeString(" ban\n");
    serial.writeString("  -----------------------------\n");
    serial.writeString("  Type 'help' for commands\n\n");
}

// ============================================================================
// Panic Handler
// ============================================================================

pub fn panic(msg: []const u8, _: ?*@import("std").builtin.StackTrace, _: ?usize) noreturn {
    cpu.cli();

    // B2.9: Halt all other CPUs on panic
    if (smp.isInitialized()) {
        smp.sendHaltIpiAll();
    }

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
