//! Zamrud OS - SMP (Symmetric Multiprocessing) Bootstrap
//! B2.9a: APIC Timer on BSP only, APs idle safely
//! FIXED v3: Don't start APIC timer on APs (no IDT loaded)

const cpu = @import("../../core/cpu.zig");
const serial = @import("../../drivers/serial/serial.zig");
const limine = @import("../../core/limine.zig");
const apic = @import("apic.zig");
const per_cpu = @import("per_cpu.zig");
const spinlock = @import("spinlock.zig");
const gdt = @import("gdt.zig");
const idt = @import("idt.zig");
const pmm = @import("../../mm/pmm.zig");
const pic = @import("pic.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const scheduler = @import("../../proc/scheduler.zig");

pub export var smp_request: limine.SmpRequest linksection(".limine_requests") = .{};

var initialized: bool = false;
var ap_boot_lock: spinlock.SpinLock = .{};
var aps_online: u32 = 0;
var smp_ready: bool = false;
var ap_boot_complete: [apic.MAX_CPUS]bool = [_]bool{false} ** apic.MAX_CPUS;

pub const APIC_TIMER_VECTOR: u8 = 48;
pub const IPI_RESCHEDULE_VECTOR: u8 = 49;
pub const IPI_HALT_VECTOR: u8 = 50;

// B2.9a: APIC Timer ENABLED (BSP only)
const ENABLE_APIC_TIMER: bool = true;
const APIC_TIMER_HZ: u32 = 100;

// B2.9a: Track APIC timer ticks for time-keeping
var apic_ticks: u64 = 0;
var apic_seconds: u64 = 0;

// B2.9a: Flag to indicate scheduler is ready
var scheduler_ready: bool = false;

pub fn init() bool {
    serial.writeString("[SMP] Initializing Symmetric Multiprocessing...\n");

    if (!apic.init()) {
        serial.writeString("[SMP] APIC init failed, single-CPU mode\n");
        initialized = true;
        return true;
    }

    per_cpu.init();

    const smp_response = smp_request.response orelse {
        serial.writeString("[SMP] No Limine SMP response, single-CPU mode\n");
        setupBspOnly();
        initialized = true;
        return true;
    };

    const limine_cpu_count = smp_response.cpu_count;
    serial.writeString("[SMP] Limine reports ");
    printDec(limine_cpu_count);
    serial.writeString(" CPUs\n");

    if (limine_cpu_count <= 1) {
        serial.writeString("[SMP] Single CPU system\n");
        setupBspOnly();
        initialized = true;
        return true;
    }

    // Boot APs first (before enabling APIC timer)
    const cpus = smp_response.getCpus();
    var aps_started: u32 = 0;

    for (cpus) |cpu_info| {
        if (cpu_info.lapic_id == smp_response.bsp_lapic_id) {
            serial.writeString("[SMP] Skipping BSP (LAPIC ID=");
            printDec(cpu_info.lapic_id);
            serial.writeString(")\n");
            continue;
        }

        const cpu_index = findCpuIndex(cpu_info.lapic_id);
        if (cpu_index == null) {
            serial.writeString("[SMP] Unknown LAPIC ID ");
            printDec(cpu_info.lapic_id);
            serial.writeString(", skipping\n");
            continue;
        }

        if (!per_cpu.allocApStacks(cpu_index.?)) {
            serial.writeString("[SMP] Failed to allocate stacks for CPU ");
            printDec(cpu_index.?);
            serial.writeString("\n");
            continue;
        }

        serial.writeString("[SMP] Starting AP: LAPIC_ID=");
        printDec(cpu_info.lapic_id);
        serial.writeString(" (CPU ");
        printDec(cpu_index.?);
        serial.writeString(")...\n");

        @atomicStore(u64, &cpu_info.goto_address, @intFromPtr(&apEntry), .release);
        aps_started += 1;
    }

    if (aps_started > 0) {
        serial.writeString("[SMP] Waiting for ");
        printDec(aps_started);
        serial.writeString(" APs to come online...\n");

        var timeout: u32 = 0;
        while (spinlock.Atomic.load(&aps_online) < aps_started and timeout < 10000000) : (timeout += 1) {
            cpu.pause();
        }

        const online = spinlock.Atomic.load(&aps_online);
        serial.writeString("[SMP] ");
        printDec(online);
        serial.writeString("/");
        printDec(aps_started);
        serial.writeString(" APs online\n");

        if (online < aps_started) {
            serial.writeString("[SMP] WARNING: Some APs failed to start\n");
        }
    }

    // B2.9a: Enable APIC timer on BSP ONLY
    setupBspApicTimer();

    smp_ready = true;
    initialized = true;

    serial.writeString("[SMP] ═══════════════════════════\n");
    serial.writeString("[SMP] SMP initialized: ");
    printDec(apic.getOnlineCpuCount());
    serial.writeString(" CPUs online\n");
    serial.writeString("[SMP] APIC Timer: ");
    serial.writeString(if (ENABLE_APIC_TIMER) "ENABLED @ 100Hz (BSP only)\n" else "DISABLED\n");
    serial.writeString("[SMP] PIC IRQ0: ");
    serial.writeString(if (pic.isIrq0Masked()) "MASKED\n" else "ENABLED\n");
    serial.writeString("[SMP] Scheduler calls: DEFERRED (until scheduler.init)\n");
    serial.writeString("[SMP] ═══════════════════════════\n");

    return true;
}

/// B2.9a: Called by main.zig AFTER scheduler.init()
pub fn enableSchedulerCalls() void {
    @atomicStore(bool, &scheduler_ready, true, .release);
    serial.writeString("[SMP] Scheduler calls ENABLED in APIC timer handler\n");
}

fn setupBspOnly() void {
    serial.writeString("[SMP] Setting up BSP-only mode\n");
    setupBspApicTimer();
}

fn setupBspApicTimer() void {
    if (!ENABLE_APIC_TIMER) {
        serial.writeString("[SMP] BSP APIC timer DISABLED\n");
        return;
    }

    if (apic.getTimerTicksPerMs() == 0) {
        serial.writeString("[SMP] APIC timer not calibrated, keeping PIT\n");
        return;
    }

    serial.writeString("[SMP] Transitioning from PIT to APIC timer...\n");

    // Step 1: Disable interrupts during transition
    cpu.cli();

    // Step 2: Mask PIC IRQ0 (PIT timer stops)
    pic.maskIrq0Only();

    // Step 3: Start APIC timer on BSP ONLY
    apic.startTimer(APIC_TIMER_VECTOR, APIC_TIMER_HZ);

    // Step 4: Re-enable interrupts
    cpu.sti();

    serial.writeString("[SMP] BSP APIC timer started at ");
    printDec(APIC_TIMER_HZ);
    serial.writeString("Hz (vector ");
    printDec(APIC_TIMER_VECTOR);
    serial.writeString(")\n");
    serial.writeString("[SMP] PIT IRQ0 masked, keyboard/mouse still working\n");
}

fn apEntry(smp_info: *limine.SmpInfo) callconv(.c) noreturn {
    const lapic_id = smp_info.lapic_id;
    const cpu_index = findCpuIndex(@truncate(lapic_id)) orelse {
        while (true) cpu.hlt();
    };

    ap_boot_lock.acquire();
    cpu.enableSSE();
    apic.enableLocalApicAP();

    const pcpu = per_cpu.get(cpu_index);
    pcpu.tss.rsp0 = pcpu.kernel_stack_top;
    pcpu.online = true;
    apic.markCpuOnline(pcpu.apic_id);

    // B2.9a FIX: Do NOT start APIC timer on APs
    // APs don't have their own IDT loaded, so timer interrupt
    // would triple-fault. APs just idle with interrupts DISABLED.

    _ = spinlock.Atomic.fetchAdd(&aps_online, 1);
    @atomicStore(bool, &ap_boot_complete[cpu_index], true, .release);
    ap_boot_lock.release();

    // APs: interrupts DISABLED, just halt
    // They are "online" for CPU count but don't process interrupts yet
    // Future B2.9b will load IDT per-AP and enable scheduling
    cpu.cli();
    while (true) cpu.hlt();
}

/// B2.9a: APIC Timer interrupt handler (BSP only)
pub fn handleApicTimer() void {
    // Increment tick counters (always safe)
    _ = spinlock.Atomic.fetchAdd64(&apic_ticks, 1);

    // Update seconds counter
    const ticks = spinlock.Atomic.load64(&apic_ticks);
    if ((ticks % 100) == 0) {
        _ = spinlock.Atomic.fetchAdd64(&apic_seconds, 1);
    }

    // Per-CPU tick tracking
    if (per_cpu.isInitialized()) {
        per_cpu.incrementTimerTicks();

        const pcpu = per_cpu.current();
        pcpu.preempt_counter += 1;

        if (pcpu.preempt_counter >= 10) {
            pcpu.preempt_counter = 0;
            if (!pcpu.in_switch) {
                pcpu.preempt_pending = true;
            }
        }
    }

    // Only call scheduler/terminal after they're initialized
    if (@atomicLoad(bool, &scheduler_ready, .acquire)) {
        if (terminal.isInitialized()) {
            terminal.tick();
        }

        scheduler.tick();

        if (scheduler.isRunning()) {
            scheduler.checkPreempt();
        }
    }

    // Send EOI (ALWAYS)
    apic.sendEoi();
}

pub fn handleRescheduleIpi() void {
    per_cpu.setPreemptPending(true);
    apic.sendEoi();
}

pub fn handleHaltIpi() noreturn {
    apic.sendEoi();
    cpu.cli();
    while (true) cpu.hlt();
}

// ============================================================================
// Time-keeping (B2.9a)
// ============================================================================

pub fn getTicks() u64 {
    return spinlock.Atomic.load64(&apic_ticks);
}

pub fn getSeconds() u64 {
    return spinlock.Atomic.load64(&apic_seconds);
}

pub fn getMillis() u64 {
    return spinlock.Atomic.load64(&apic_ticks) * 10;
}

// ============================================================================
// IPI Functions
// ============================================================================

pub fn sendRescheduleIpi(cpu_index: usize) void {
    if (!initialized or !smp_ready) return;
    const info = apic.getCpuInfo(cpu_index) orelse return;
    if (!info.online) return;
    apic.sendIpi(info.apic_id, IPI_RESCHEDULE_VECTOR);
}

pub fn sendRescheduleIpiAll() void {
    if (!initialized or !smp_ready) return;
    apic.sendIpiAllExSelf(IPI_RESCHEDULE_VECTOR);
}

pub fn sendHaltIpiAll() void {
    if (!initialized) return;
    apic.sendIpiAllExSelf(IPI_HALT_VECTOR);
}

fn findCpuIndex(lapic_id: u32) ?usize {
    const count = apic.getCpuCount();
    for (0..count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;
        if (info.apic_id == @as(u8, @truncate(lapic_id))) return i;
    }
    return null;
}

// ============================================================================
// Status Functions
// ============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn isSmpReady() bool {
    return smp_ready;
}

pub fn getOnlineCpuCount() usize {
    return apic.getOnlineCpuCount();
}

pub fn getCpuCount() usize {
    return apic.getCpuCount();
}

pub fn isApicTimerEnabled() bool {
    return ENABLE_APIC_TIMER and pic.isIrq0Masked();
}

pub fn isSchedulerReady() bool {
    return @atomicLoad(bool, &scheduler_ready, .acquire);
}

pub fn printStatus() void {
    serial.writeString("\n[SMP] ─── Status ───\n");
    serial.writeString("[SMP] CPUs: ");
    printDec(apic.getOnlineCpuCount());
    serial.writeString("/");
    printDec(apic.getCpuCount());
    serial.writeString(" online\n");
    serial.writeString("[SMP] APIC Timer: ");
    serial.writeString(if (isApicTimerEnabled()) "ON @ 100Hz (BSP)" else "OFF");
    serial.writeString(", PIC IRQ0: ");
    serial.writeString(if (pic.isIrq0Masked()) "MASKED" else "ENABLED");
    serial.writeString("\n");
    serial.writeString("[SMP] Scheduler: ");
    serial.writeString(if (isSchedulerReady()) "ENABLED" else "DEFERRED");
    serial.writeString("\n");
    serial.writeString("[SMP] APIC Ticks: ");
    printDec(getTicks());
    serial.writeString(", Seconds: ");
    printDec(getSeconds());
    serial.writeString("\n");
}

fn printDec(value: anytype) void {
    const v: u64 = @intCast(value);
    if (v == 0) {
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
        serial.writeChar(buf[i]);
    }
}
