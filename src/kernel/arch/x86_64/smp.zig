//! Zamrud OS - SMP (Symmetric Multiprocessing) Bootstrap
//! B2.9b: Multi-CPU Scheduler - STABLE VERSION
//! B2.10: Audio timer poll integration
//! APs online with timer but idle until full scheduler integration

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
const process = @import("../../proc/process.zig");
const hid = @import("../../drivers/usb/hid.zig");
const audio = @import("../../drivers/audio/audio.zig");

pub export var smp_request: limine.SmpRequest linksection(".limine_requests") = .{};

var initialized: bool = false;
var ap_boot_lock: spinlock.SpinLock = .{};
var aps_online: u32 = 0;
var smp_ready: bool = false;
var ap_boot_complete: [apic.MAX_CPUS]bool = [_]bool{false} ** apic.MAX_CPUS;

// B2.9b: Flags
var aps_can_schedule: bool = false;
var scheduler_ready: bool = false;

pub const APIC_TIMER_VECTOR: u8 = 48;
pub const IPI_RESCHEDULE_VECTOR: u8 = 49;
pub const IPI_HALT_VECTOR: u8 = 50;

// B2.9b: APIC Timer - BSP only for stability
const ENABLE_APIC_TIMER_BSP: bool = true;
const ENABLE_APIC_TIMER_AP: bool = false;
const APIC_TIMER_HZ: u32 = 100;

// Time-keeping
var apic_ticks: u64 = 0;
var apic_seconds: u64 = 0;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() bool {
    serial.writeString("[SMP] Initializing Symmetric Multiprocessing (B2.9b)...\n");

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

    // Boot APs
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

    // Enable APIC timer on BSP
    setupBspApicTimer();

    smp_ready = true;
    initialized = true;

    serial.writeString("[SMP] ═══════════════════════════\n");
    serial.writeString("[SMP] SMP initialized (B2.9b): ");
    printDec(apic.getOnlineCpuCount());
    serial.writeString(" CPUs online\n");
    serial.writeString("[SMP] APIC Timer: BSP @ 100Hz\n");
    serial.writeString("[SMP] APs: Idle (ready for future work)\n");
    serial.writeString("[SMP] Per-CPU Runqueues: READY\n");
    serial.writeString("[SMP] ═══════════════════════════\n");

    return true;
}

pub fn enableSchedulerCalls() void {
    @atomicStore(bool, &scheduler_ready, true, .release);
    serial.writeString("[SMP] Scheduler calls ENABLED\n");
}

pub fn enableApScheduling() void {
    @atomicStore(bool, &aps_can_schedule, true, .release);
    serial.writeString("[SMP] AP scheduling flag SET (APs remain idle for now)\n");
}

fn setupBspOnly() void {
    serial.writeString("[SMP] Setting up BSP-only mode\n");
    setupBspApicTimer();
}

fn setupBspApicTimer() void {
    if (!ENABLE_APIC_TIMER_BSP) {
        serial.writeString("[SMP] BSP APIC timer DISABLED\n");
        return;
    }

    if (apic.getTimerTicksPerMs() == 0) {
        serial.writeString("[SMP] APIC timer not calibrated, keeping PIT\n");
        return;
    }

    serial.writeString("[SMP] Transitioning from PIT to APIC timer...\n");

    cpu.cli();
    pic.maskIrq0Only();
    apic.startTimer(APIC_TIMER_VECTOR, APIC_TIMER_HZ);
    cpu.sti();

    serial.writeString("[SMP] BSP APIC timer started at ");
    printDec(APIC_TIMER_HZ);
    serial.writeString("Hz\n");
}

// ============================================================================
// AP Entry Point
// ============================================================================

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

    _ = spinlock.Atomic.fetchAdd(&aps_online, 1);
    @atomicStore(bool, &ap_boot_complete[cpu_index], true, .release);

    ap_boot_lock.release();

    // AP idle loop — interrupts disabled for stability
    cpu.cli();
    while (true) {
        cpu.hlt();
    }
}

// ============================================================================
// APIC Timer Handler (BSP only)
// B2.10: audio.timerPoll() for zero-gap continuous playback
// ============================================================================

pub fn handleApicTimer() void {
    // Increment global tick counters
    _ = spinlock.Atomic.fetchAdd64(&apic_ticks, 1);

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

    // Scheduler integration
    if (@atomicLoad(bool, &scheduler_ready, .acquire)) {
        if (terminal.isInitialized()) {
            terminal.tick();
        }
        scheduler.tick();
        if (scheduler.isRunning()) {
            scheduler.checkPreempt();
        }
    }

    // B2.11b: USB HID polling trigger (non-blocking, sets flag only)
    hid.timerTick();

    // B2.10: Audio DMA poll — every 2nd tick (50Hz)
    // poll() has re-entrancy guard — safe from IRQ context
    if ((ticks & 1) == 0) {
        audio.timerPoll();
    }

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

pub fn wakeApForWork(cpu_index: usize) void {
    if (!initialized or !smp_ready) return;
    if (cpu_index == 0) return;
    const info = apic.getCpuInfo(cpu_index) orelse return;
    if (!info.online) return;
    apic.sendIpi(info.apic_id, IPI_RESCHEDULE_VECTOR);
}

// ============================================================================
// Time-keeping
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
// Status
// ============================================================================

fn findCpuIndex(lapic_id: u32) ?usize {
    const count = apic.getCpuCount();
    for (0..count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;
        if (info.apic_id == @as(u8, @truncate(lapic_id))) return i;
    }
    return null;
}

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
    return ENABLE_APIC_TIMER_BSP and pic.isIrq0Masked();
}

pub fn isSchedulerReady() bool {
    return @atomicLoad(bool, &scheduler_ready, .acquire);
}

pub fn isApSchedulingEnabled() bool {
    return @atomicLoad(bool, &aps_can_schedule, .acquire);
}

pub fn printStatus() void {
    serial.writeString("\n[SMP] --- Status (B2.9b) ---\n");
    serial.writeString("[SMP] CPUs: ");
    printDec(apic.getOnlineCpuCount());
    serial.writeString("/");
    printDec(apic.getCpuCount());
    serial.writeString(" online\n");
    serial.writeString("[SMP] APIC Timer: BSP @ 100Hz\n");
    serial.writeString("[SMP] Scheduler: ");
    serial.writeString(if (isSchedulerReady()) "ENABLED" else "DEFERRED");
    serial.writeString("\n");
    serial.writeString("[SMP] Ticks: ");
    printDec(getTicks());
    serial.writeString(", Seconds: ");
    printDec(getSeconds());
    serial.writeString("\n");

    const cpu_count = apic.getCpuCount();
    serial.writeString("[SMP] Per-CPU:\n");
    for (0..cpu_count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;
        if (!info.online) continue;

        const pcpu = per_cpu.get(i);
        serial.writeString("  CPU");
        printDec(i);
        serial.writeString(": ticks=");
        printDec(pcpu.timer_ticks);
        serial.writeString(" switches=");
        printDec(pcpu.switch_count);
        if (info.is_bsp) serial.writeString(" (BSP)") else serial.writeString(" (idle)");
        serial.writeString("\n");
    }
}

// ============================================================================
// Helpers
// ============================================================================

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
