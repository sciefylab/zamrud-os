//! Zamrud OS - SMP (Symmetric Multiprocessing) Bootstrap
//! B2.9b: Application Processor startup
//! FIXED: Don't disable PIC (keyboard needs it)

const cpu = @import("../../core/cpu.zig");
const serial = @import("../../drivers/serial/serial.zig");
const limine = @import("../../core/limine.zig");
const apic = @import("apic.zig");
const per_cpu = @import("per_cpu.zig");
const spinlock = @import("spinlock.zig");
const gdt = @import("gdt.zig");
const idt = @import("idt.zig");
const pmm = @import("../../mm/pmm.zig");

pub export var smp_request: limine.SmpRequest linksection(".limine_requests") = .{};

var initialized: bool = false;
var ap_boot_lock: spinlock.SpinLock = .{};
var aps_online: u32 = 0;
var smp_ready: bool = false;
var ap_boot_complete: [apic.MAX_CPUS]bool = [_]bool{false} ** apic.MAX_CPUS;

pub const APIC_TIMER_VECTOR: u8 = 48;
pub const IPI_RESCHEDULE_VECTOR: u8 = 49;
pub const IPI_HALT_VECTOR: u8 = 50;

const ENABLE_APIC_TIMER: bool = false;
const DISABLE_LEGACY_PIC: bool = false; // Keep PIC for keyboard!

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

    setupBspApicTimer();

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

    // DON'T disable PIC - keyboard needs it!
    if (DISABLE_LEGACY_PIC) {
        apic.disableLegacyPic();
    } else {
        serial.writeString("[SMP] Legacy PIC: KEPT (keyboard needs IRQ1)\n");
    }

    smp_ready = true;
    initialized = true;

    serial.writeString("[SMP] ═══════════════════════════\n");
    serial.writeString("[SMP] SMP initialized: ");
    printDec(apic.getOnlineCpuCount());
    serial.writeString(" CPUs online\n");
    if (!ENABLE_APIC_TIMER) {
        serial.writeString("[SMP] APIC Timer: DISABLED\n");
    }
    if (!DISABLE_LEGACY_PIC) {
        serial.writeString("[SMP] Legacy PIC: ENABLED\n");
    }
    serial.writeString("[SMP] ═══════════════════════════\n");

    return true;
}

fn setupBspOnly() void {
    serial.writeString("[SMP] Setting up BSP-only mode\n");
    if (ENABLE_APIC_TIMER and apic.getTimerTicksPerMs() > 0) {
        setupBspApicTimer();
    }
}

fn setupBspApicTimer() void {
    if (!ENABLE_APIC_TIMER) {
        serial.writeString("[SMP] BSP APIC timer DISABLED\n");
        return;
    }
    apic.startTimer(APIC_TIMER_VECTOR, 100);
    serial.writeString("[SMP] BSP APIC timer started at 100Hz\n");
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

    if (ENABLE_APIC_TIMER) {
        apic.startTimer(APIC_TIMER_VECTOR, 100);
    }

    _ = spinlock.Atomic.fetchAdd(&aps_online, 1);
    @atomicStore(bool, &ap_boot_complete[cpu_index], true, .release);
    ap_boot_lock.release();

    cpu.sti();
    while (true) cpu.hlt();
}

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

pub fn handleApicTimer() void {
    if (!ENABLE_APIC_TIMER) {
        apic.sendEoi();
        return;
    }
    const pcpu = per_cpu.current();
    pcpu.timer_ticks += 1;
    pcpu.preempt_counter += 1;
    if (pcpu.preempt_counter >= 10) {
        pcpu.preempt_counter = 0;
        if (!pcpu.in_switch) pcpu.preempt_pending = true;
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
    return ENABLE_APIC_TIMER;
}

pub fn printStatus() void {
    serial.writeString("\n[SMP] ─── Status ───\n");
    serial.writeString("[SMP] CPUs: ");
    printDec(apic.getOnlineCpuCount());
    serial.writeString("/");
    printDec(apic.getCpuCount());
    serial.writeString(" online\n");
    serial.writeString("[SMP] APIC Timer: ");
    serial.writeString(if (ENABLE_APIC_TIMER) "ON" else "OFF");
    serial.writeString(", PIC: ");
    serial.writeString(if (DISABLE_LEGACY_PIC) "OFF" else "ON");
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
