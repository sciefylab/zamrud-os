//! Zamrud OS - Intel AC97 Audio Controller Driver
//! PCI Class 0x04 (Multimedia), Subclass 0x01 (Audio)
//! I/O Port based access (NAM + NABM BARs)
//! B2.10: Sound Driver — Production Ready for Voice AI
//!
//! AC97 Architecture:
//!   NAM BAR (BAR0): Mixer registers (volume, mute, codec ID)
//!   NABM BAR (BAR1): Bus Master registers (DMA control, BDL)
//!   Buffer Descriptor List: 32 entries, each 8 bytes
//!   DMA: Scatter-gather via BDL -> PCM output / PCM input
//!
//! Continuous Playback Strategy (B2.10 FIX):
//!   Timer-driven poll @ 50Hz — pre-emptive circular LVI
//!   NO CR_LVBIE — timer is sole DMA controller
//!   poll_in_progress atomic guard — prevents IRQ/poll race
//!   DMA never halts → zero-gap continuous audio
//!
//! Three poll paths (priority order):
//!   1. APIC Timer (primary)   — audio.timerPoll() every 20ms
//!   2. Shell idle (secondary) — audio.poll() in readInput()
//!   3. Hardware IRQ (status)  — handleInterrupt() clears status only

const serial = @import("../serial/serial.zig");
const pci = @import("../pci/pci.zig");
const pmm = @import("../../mm/pmm.zig");

// =============================================================================
// PCI IDs
// =============================================================================

pub const AC97_VENDOR_INTEL: u16 = 0x8086;
pub const AC97_DEVICE_ICH: u16 = 0x2415;
pub const AC97_DEVICE_ICH0: u16 = 0x2425;
pub const AC97_DEVICE_ICH2: u16 = 0x2445;
pub const AC97_DEVICE_ICH3: u16 = 0x2485;
pub const AC97_DEVICE_ICH4: u16 = 0x24C5;
pub const AC97_DEVICE_ICH5: u16 = 0x24D5;
pub const AC97_DEVICE_ICH6: u16 = 0x266E;
pub const AC97_DEVICE_ICH7: u16 = 0x27DE;

// =============================================================================
// NAM (Native Audio Mixer) Register Offsets — BAR0
// =============================================================================

pub const NAM_RESET: u16 = 0x00;
pub const NAM_MASTER_VOL: u16 = 0x02;
pub const NAM_AUX_OUT_VOL: u16 = 0x04;
pub const NAM_MONO_VOL: u16 = 0x06;
pub const NAM_MASTER_TONE: u16 = 0x08;
pub const NAM_PC_BEEP_VOL: u16 = 0x0A;
pub const NAM_PHONE_VOL: u16 = 0x0C;
pub const NAM_MIC_VOL: u16 = 0x0E;
pub const NAM_LINE_IN_VOL: u16 = 0x10;
pub const NAM_CD_VOL: u16 = 0x12;
pub const NAM_VIDEO_VOL: u16 = 0x14;
pub const NAM_AUX_IN_VOL: u16 = 0x16;
pub const NAM_PCM_OUT_VOL: u16 = 0x18;
pub const NAM_RECORD_SELECT: u16 = 0x1A;
pub const NAM_RECORD_GAIN: u16 = 0x1C;
pub const NAM_RECORD_GAIN_MIC: u16 = 0x1E;
pub const NAM_GENERAL_PURPOSE: u16 = 0x20;
pub const NAM_3D_CONTROL: u16 = 0x22;
pub const NAM_AUDIO_INT_PAGING: u16 = 0x24;
pub const NAM_POWERDOWN_CTRL: u16 = 0x26;
pub const NAM_EXT_AUDIO_ID: u16 = 0x28;
pub const NAM_EXT_AUDIO_CTRL: u16 = 0x2A;
pub const NAM_PCM_FRONT_DAC_RATE: u16 = 0x2C;
pub const NAM_PCM_SURR_DAC_RATE: u16 = 0x2E;
pub const NAM_PCM_LFE_DAC_RATE: u16 = 0x30;
pub const NAM_PCM_LR_ADC_RATE: u16 = 0x32;
pub const NAM_MIC_ADC_RATE: u16 = 0x34;
pub const NAM_VENDOR_ID1: u16 = 0x7C;
pub const NAM_VENDOR_ID2: u16 = 0x7E;

// =============================================================================
// NABM (Native Audio Bus Master) Register Offsets — BAR1
// =============================================================================

pub const NABM_PI_BDBAR: u16 = 0x00;
pub const NABM_PI_CIV: u16 = 0x04;
pub const NABM_PI_LVI: u16 = 0x05;
pub const NABM_PI_SR: u16 = 0x06;
pub const NABM_PI_PICB: u16 = 0x08;
pub const NABM_PI_PIV: u16 = 0x0A;
pub const NABM_PI_CR: u16 = 0x0B;

pub const NABM_PO_BDBAR: u16 = 0x10;
pub const NABM_PO_CIV: u16 = 0x14;
pub const NABM_PO_LVI: u16 = 0x15;
pub const NABM_PO_SR: u16 = 0x16;
pub const NABM_PO_PICB: u16 = 0x18;
pub const NABM_PO_PIV: u16 = 0x1A;
pub const NABM_PO_CR: u16 = 0x1B;

pub const NABM_MC_BDBAR: u16 = 0x20;
pub const NABM_MC_CIV: u16 = 0x24;
pub const NABM_MC_LVI: u16 = 0x25;
pub const NABM_MC_SR: u16 = 0x26;
pub const NABM_MC_PICB: u16 = 0x28;
pub const NABM_MC_PIV: u16 = 0x2A;
pub const NABM_MC_CR: u16 = 0x2B;

pub const NABM_GLOB_CNT: u16 = 0x2C;
pub const NABM_GLOB_STA: u16 = 0x30;

// =============================================================================
// Control/Status bits
// =============================================================================

pub const CR_RPBM: u8 = 0x01;
pub const CR_RR: u8 = 0x02;
pub const CR_LVBIE: u8 = 0x04;
pub const CR_FEIE: u8 = 0x08;
pub const CR_IOCE: u8 = 0x10;

pub const SR_DCH: u16 = 0x0001;
pub const SR_CELV: u16 = 0x0002;
pub const SR_LVBCI: u16 = 0x0004;
pub const SR_BCIS: u16 = 0x0008;
pub const SR_FIFOE: u16 = 0x0010;

pub const GC_COLD_RESET: u32 = 0x00000002;
pub const GC_WARM_RESET: u32 = 0x00000004;
pub const GC_2CH_MODE: u32 = 0x00000000;

pub const GS_POINT: u32 = 0x00000002;
pub const GS_PIINT: u32 = 0x00000004;
pub const GS_MCINT: u32 = 0x00000008;
pub const GS_PCR: u32 = 0x00000100;

// =============================================================================
// Buffer Descriptor List
// =============================================================================

pub const NUM_BDL_ENTRIES: usize = 32;
pub const SAMPLE_RATE_DEFAULT: u16 = 48000;
pub const SAMPLE_RATE_VOICE: u16 = 16000;

pub const PCM_BUFFER_SIZE: usize = 4096;
pub const NUM_PCM_BUFFERS: usize = 32;

pub const BdlEntry = extern struct {
    addr: u32 align(1),
    length: u16 align(1),
    flags: u16 align(1),
};

pub const BDL_FLAG_IOC: u16 = 0x8000;
pub const BDL_FLAG_BUP: u16 = 0x4000;

// =============================================================================
// Types
// =============================================================================

pub const AudioFormat = struct {
    sample_rate: u16,
    channels: u8,
    bits_per_sample: u8,
};

pub const DriverStats = struct {
    interrupts: u64,
    buffers_played: u64,
    underruns: u64,
    overruns: u64,
    bytes_played: u64,
    playback_started: u64,
    playback_stopped: u64,
};

pub const PlaybackState = enum {
    stopped,
    playing,
    paused,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var detected: bool = false;
var nam_base: u16 = 0;
var nabm_base: u16 = 0;
var irq_line: u8 = 0;
var hhdm_offset: u64 = 0;

var codec_vendor_id: u32 = 0;
var codec_ready: bool = false;
var variable_rate_supported: bool = false;

var current_format: AudioFormat = .{
    .sample_rate = SAMPLE_RATE_DEFAULT,
    .channels = 2,
    .bits_per_sample = 16,
};

var master_volume: u16 = 0x0000;
var pcm_volume: u16 = 0x0808;
var playback_state: PlaybackState = .stopped;

// DMA buffers
var bdl_phys: u64 = 0;
var bdl_virt: u64 = 0;
var pcm_buffers_phys: [NUM_PCM_BUFFERS]u64 = [_]u64{0} ** NUM_PCM_BUFFERS;
var pcm_buffers_virt: [NUM_PCM_BUFFERS]u64 = [_]u64{0} ** NUM_PCM_BUFFERS;
var dma_initialized: bool = false;

// Capture state (Voice AI)
var capture_active: bool = false;
var capture_buffers_filled: u64 = 0;
var capture_bytes_captured: u64 = 0;
var capture_overruns: u64 = 0;

// Polling stats
var poll_count: u64 = 0;
var restart_count: u64 = 0;

// Re-entrancy guard for poll/IRQ race prevention
var poll_in_progress: bool = false;

// IRQ stats
var irq_fired_count: u64 = 0;

var stats: DriverStats = .{
    .interrupts = 0,
    .buffers_played = 0,
    .underruns = 0,
    .overruns = 0,
    .bytes_played = 0,
    .playback_started = 0,
    .playback_stopped = 0,
};

// =============================================================================
// Address Conversion
// =============================================================================

inline fn physToVirt(phys: u64) u64 {
    return hhdm_offset + phys;
}

// =============================================================================
// I/O Port Access
// =============================================================================

inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

inline fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "N{dx}" (port),
    );
}

inline fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "N{dx}" (port),
    );
}

inline fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

inline fn outw(port: u16, value: u16) void {
    asm volatile ("outw %[value], %[port]"
        :
        : [value] "{ax}" (value),
          [port] "N{dx}" (port),
    );
}

inline fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "N{dx}" (port),
    );
}

inline fn readNam16(reg: u16) u16 {
    return inw(nam_base + reg);
}

inline fn writeNam16(reg: u16, value: u16) void {
    outw(nam_base + reg, value);
}

inline fn readNabm8(reg: u16) u8 {
    return inb(nabm_base + reg);
}

inline fn readNabm16(reg: u16) u16 {
    return inw(nabm_base + reg);
}

inline fn readNabm32(reg: u16) u32 {
    return inl(nabm_base + reg);
}

inline fn writeNabm8(reg: u16, value: u8) void {
    outb(nabm_base + reg, value);
}

inline fn writeNabm16(reg: u16, value: u16) void {
    outw(nabm_base + reg, value);
}

inline fn writeNabm32(reg: u16, value: u32) void {
    outl(nabm_base + reg, value);
}

// =============================================================================
// Raw Memory Write
// =============================================================================

fn writeU8ToPhys(virt_addr: u64, offset: usize, value: u8) void {
    const ptr: [*]volatile u8 = @ptrFromInt(virt_addr);
    ptr[offset] = value;
}

fn readU8FromPhys(virt_addr: u64, offset: usize) u8 {
    const ptr: [*]volatile u8 = @ptrFromInt(virt_addr);
    return ptr[offset];
}

// =============================================================================
// IRQ Configuration
// =============================================================================

fn enableAc97Irq() void {
    if (irq_line == 0) return;

    serial.writeString("[AC97] IRQ line from PCI: ");
    printDec(@intCast(irq_line));
    serial.writeString("\n");

    // Setelah APIC init, PIC sudah masked semua.
    // IRQ routing sudah dilakukan via I/O APIC di apic.zig setupIoApic().
    // Tidak perlu unmask PIC lagi — I/O APIC yang handle.
    // Hanya log saja untuk debug.

    serial.writeString("[AC97] Audio IRQ routed via I/O APIC (vector ");
    const vec: u8 = switch (irq_line) {
        5 => 37,
        9 => 41,
        10 => 42,
        else => 32 + irq_line,
    };
    printDec(@intCast(vec));
    serial.writeString(")\n");
}

pub fn disableAc97Irq() void {
    if (irq_line == 0) return;

    const PIC1_DATA: u16 = 0x21;
    const PIC2_DATA: u16 = 0xA1;

    if (irq_line < 8) {
        const mask = inb(PIC1_DATA);
        outb(PIC1_DATA, mask | (@as(u8, 1) << @intCast(irq_line)));
    } else {
        const mask2 = inb(PIC2_DATA);
        const irq_bit: u3 = @intCast(irq_line - 8);
        outb(PIC2_DATA, mask2 | (@as(u8, 1) << irq_bit));
    }
}

// =============================================================================
// DMA Buffer Management
// =============================================================================

fn allocateDmaBuffers() bool {
    serial.writeString("[AC97] Allocating DMA buffers...\n");

    hhdm_offset = pmm.getHhdmOffset();

    bdl_phys = pmm.allocPage() orelse {
        serial.writeString("[AC97] Failed to allocate BDL!\n");
        return false;
    };
    bdl_virt = physToVirt(bdl_phys);

    var i: usize = 0;
    while (i < 4096) : (i += 1) {
        writeU8ToPhys(bdl_virt, i, 0);
    }

    serial.writeString("[AC97] BDL phys=0x");
    printHex32(@truncate(bdl_phys));
    serial.writeString(" virt=0x");
    printHex64(bdl_virt);
    serial.writeString("\n");

    for (0..NUM_PCM_BUFFERS) |idx| {
        pcm_buffers_phys[idx] = pmm.allocPage() orelse {
            serial.writeString("[AC97] Failed to allocate PCM buffer!\n");
            freeDmaBuffers();
            return false;
        };
        pcm_buffers_virt[idx] = physToVirt(pcm_buffers_phys[idx]);

        var j: usize = 0;
        while (j < PCM_BUFFER_SIZE) : (j += 1) {
            writeU8ToPhys(pcm_buffers_virt[idx], j, 0);
        }

        if (pcm_buffers_phys[idx] > 0xFFFFFFFF) {
            serial.writeString("[AC97] ERROR: Buffer above 4GB!\n");
            freeDmaBuffers();
            return false;
        }
    }

    for (0..NUM_PCM_BUFFERS) |idx| {
        const entry_offset = idx * 8;
        const phys32: u32 = @truncate(pcm_buffers_phys[idx]);

        writeU8ToPhys(bdl_virt, entry_offset + 0, @truncate(phys32 & 0xFF));
        writeU8ToPhys(bdl_virt, entry_offset + 1, @truncate((phys32 >> 8) & 0xFF));
        writeU8ToPhys(bdl_virt, entry_offset + 2, @truncate((phys32 >> 16) & 0xFF));
        writeU8ToPhys(bdl_virt, entry_offset + 3, @truncate((phys32 >> 24) & 0xFF));

        const sample_count: u16 = @intCast(PCM_BUFFER_SIZE / 2);
        writeU8ToPhys(bdl_virt, entry_offset + 4, @truncate(sample_count & 0xFF));
        writeU8ToPhys(bdl_virt, entry_offset + 5, @truncate((sample_count >> 8) & 0xFF));

        // IOC flag on every buffer for completion tracking
        const flags: u16 = BDL_FLAG_IOC;
        writeU8ToPhys(bdl_virt, entry_offset + 6, @truncate(flags & 0xFF));
        writeU8ToPhys(bdl_virt, entry_offset + 7, @truncate((flags >> 8) & 0xFF));
    }

    serial.writeString("[AC97] BDL[0]: addr=0x");
    printHex32(@truncate(pcm_buffers_phys[0]));
    serial.writeString(" len=");
    printDec(PCM_BUFFER_SIZE / 2);
    serial.writeString(" samples\n");

    asm volatile ("mfence" ::: .{ .memory = true });

    dma_initialized = true;
    serial.writeString("[AC97] DMA ready (");
    printDec(@intCast(NUM_PCM_BUFFERS));
    serial.writeString(" x ");
    printDec(PCM_BUFFER_SIZE);
    serial.writeString("B)\n");
    return true;
}

fn freeDmaBuffers() void {
    if (bdl_phys != 0) {
        pmm.freePage(bdl_phys);
        bdl_phys = 0;
        bdl_virt = 0;
    }
    for (0..NUM_PCM_BUFFERS) |idx| {
        if (pcm_buffers_phys[idx] != 0) {
            pmm.freePage(pcm_buffers_phys[idx]);
            pcm_buffers_phys[idx] = 0;
            pcm_buffers_virt[idx] = 0;
        }
    }
    dma_initialized = false;
}

// =============================================================================
// Probe & Init
// =============================================================================

pub fn probe() bool {
    if (!pci.isInitialized()) return false;

    if (pci.findByClass(0x04, 0x01)) |dev| {
        return setupFromPci(dev);
    }

    const device_ids = [_]u16{
        AC97_DEVICE_ICH,  AC97_DEVICE_ICH0, AC97_DEVICE_ICH2,
        AC97_DEVICE_ICH3, AC97_DEVICE_ICH4, AC97_DEVICE_ICH5,
        AC97_DEVICE_ICH6, AC97_DEVICE_ICH7,
    };
    for (device_ids) |dev_id| {
        if (pci.findDevice(AC97_VENDOR_INTEL, dev_id)) |dev| {
            return setupFromPci(dev);
        }
    }
    return false;
}

fn setupFromPci(dev: *const pci.PciDevice) bool {
    if ((dev.bar0 & 0x01) == 0 or (dev.bar1 & 0x01) == 0) {
        serial.writeString("[AC97] BARs not I/O!\n");
        if ((dev.bar0 & 0x01) != 0) {
            nam_base = @truncate(dev.bar0 & 0xFFFC);
            nabm_base = @truncate(dev.bar1 & 0xFFFC);
            if (nabm_base == 0) nabm_base = nam_base + 0x100;
        } else {
            return false;
        }
    } else {
        nam_base = @truncate(dev.bar0 & 0xFFFC);
        nabm_base = @truncate(dev.bar1 & 0xFFFC);
    }

    irq_line = dev.irq_line;
    detected = true;

    pci.enableBusMaster(dev);
    pci.enableIoSpace(dev);

    serial.writeString("[AC97] Found: NAM=0x");
    printHex16(nam_base);
    serial.writeString(" NABM=0x");
    printHex16(nabm_base);
    serial.writeString(" IRQ=");
    printDec(@intCast(irq_line));
    serial.writeString(" PCI=0x");
    printHex16(dev.vendor_id);
    serial.writeString(":0x");
    printHex16(dev.device_id);
    serial.writeString("\n");

    return true;
}

pub fn init() bool {
    if (!detected) {
        if (!probe()) {
            serial.writeString("[AC97] No AC97 device found\n");
            return false;
        }
    }

    serial.writeString("[AC97] Initializing...\n");

    if (!allocateDmaBuffers()) {
        serial.writeString("[AC97] DMA allocation failed\n");
    }

    if (nam_base != 0 and nabm_base != 0) {
        initHardware();
    }

    initialized = true;
    serial.writeString("[AC97] Initialized\n");
    return true;
}

fn initHardware() void {
    // Step 1: Cold reset
    serial.writeString("[AC97] Cold reset...\n");
    var gc = readNabm32(NABM_GLOB_CNT);
    gc |= GC_COLD_RESET;
    writeNabm32(NABM_GLOB_CNT, gc);
    busyWait(100000);

    // Step 2: Wait codec ready
    var timeout: u32 = 0;
    while (timeout < 1000) : (timeout += 1) {
        if ((readNabm32(NABM_GLOB_STA) & GS_PCR) != 0) {
            codec_ready = true;
            break;
        }
        busyWait(1000);
    }

    if (!codec_ready) {
        serial.writeString("[AC97] Codec not ready, warm reset...\n");
        gc = readNabm32(NABM_GLOB_CNT);
        gc |= GC_WARM_RESET;
        writeNabm32(NABM_GLOB_CNT, gc);
        busyWait(100000);

        timeout = 0;
        while (timeout < 1000) : (timeout += 1) {
            if ((readNabm32(NABM_GLOB_STA) & GS_PCR) != 0) {
                codec_ready = true;
                break;
            }
            busyWait(1000);
        }
    }

    if (codec_ready) {
        serial.writeString("[AC97] Codec ready\n");
    } else {
        serial.writeString("[AC97] Codec not ready, continuing\n");
    }

    // Step 3: Reset codec
    writeNam16(NAM_RESET, 0x0000);
    busyWait(50000);

    // Step 4: Read codec vendor
    const vid1 = readNam16(NAM_VENDOR_ID1);
    const vid2 = readNam16(NAM_VENDOR_ID2);
    codec_vendor_id = (@as(u32, vid1) << 16) | @as(u32, vid2);
    serial.writeString("[AC97] Codec vendor: 0x");
    printHex32(codec_vendor_id);
    serial.writeString("\n");

    // Step 5: Variable rate audio
    const ext_id = readNam16(NAM_EXT_AUDIO_ID);
    variable_rate_supported = (ext_id & 0x0001) != 0;
    if (variable_rate_supported) {
        var ext_ctrl = readNam16(NAM_EXT_AUDIO_CTRL);
        ext_ctrl |= 0x0001;
        writeNam16(NAM_EXT_AUDIO_CTRL, ext_ctrl);
        serial.writeString("[AC97] Variable rate audio enabled\n");
    } else {
        serial.writeString("[AC97] Fixed rate 48kHz\n");
    }

    // Step 6: Set sample rate
    setSampleRate(current_format.sample_rate);

    // Step 7: Set volumes — UNMUTE everything
    writeNam16(NAM_MASTER_VOL, 0x0000);
    writeNam16(NAM_PCM_OUT_VOL, 0x0000);
    writeNam16(NAM_AUX_OUT_VOL, 0x0000);
    writeNam16(NAM_MONO_VOL, 0x0000);
    writeNam16(NAM_LINE_IN_VOL, 0x0000);
    writeNam16(NAM_CD_VOL, 0x0000);

    // Step 8: Set 2ch mode
    gc = readNabm32(NABM_GLOB_CNT);
    gc &= ~@as(u32, 0xC0);
    gc |= GC_2CH_MODE;
    writeNabm32(NABM_GLOB_CNT, gc);

    // Step 9: Reset PO channel
    writeNabm8(NABM_PO_CR, CR_RR);
    busyWait(10000);
    timeout = 0;
    while (timeout < 1000) : (timeout += 1) {
        if ((readNabm8(NABM_PO_CR) & CR_RR) == 0) break;
        busyWait(100);
    }

    // Step 10: Set BDL address
    if (dma_initialized) {
        const bdl_phys32: u32 = @truncate(bdl_phys);
        writeNabm32(NABM_PO_BDBAR, bdl_phys32);

        const verify_bdbar = readNabm32(NABM_PO_BDBAR);
        serial.writeString("[AC97] BDBAR set=0x");
        printHex32(bdl_phys32);
        serial.writeString(" read=0x");
        printHex32(verify_bdbar);
        if (verify_bdbar == bdl_phys32) {
            serial.writeString(" OK\n");
        } else {
            serial.writeString(" MISMATCH!\n");
        }
    }

    // Step 11: Clear status
    writeNabm16(NABM_PO_SR, SR_LVBCI | SR_BCIS | SR_FIFOE);

    // Step 12: Enable AC97 IRQ in PIC (for status clearing)
    enableAc97Irq();

    serial.writeString("[AC97] IRQ line: ");
    printDec(@intCast(irq_line));
    serial.writeString(" (vector ");
    printDec(@intCast(@as(u16, 32) + @as(u16, irq_line)));
    serial.writeString(")\n");

    serial.writeString("[AC97] Hardware ready\n");
}

// =============================================================================
// Playback Control
// =============================================================================

pub fn play() bool {
    if (!initialized or !dma_initialized) return false;
    if (nam_base == 0 or nabm_base == 0) return false;

    // Reset PO channel clean
    writeNabm8(NABM_PO_CR, 0);
    busyWait(1000);
    writeNabm8(NABM_PO_CR, CR_RR);
    busyWait(10000);

    var timeout: u32 = 0;
    while (timeout < 1000) : (timeout += 1) {
        if ((readNabm8(NABM_PO_CR) & CR_RR) == 0) break;
        busyWait(100);
    }

    // Set BDBAR
    writeNabm32(NABM_PO_BDBAR, @truncate(bdl_phys));

    // Clear ALL status bits
    writeNabm16(NABM_PO_SR, SR_LVBCI | SR_BCIS | SR_FIFOE);

    // Set initial LVI = 31
    writeNabm8(NABM_PO_LVI, @intCast(NUM_PCM_BUFFERS - 1));

    // Memory fence before DMA start
    asm volatile ("mfence" ::: .{ .memory = true });

    // Start DMA — NO CR_LVBIE!
    // Timer poll handles circular LVI exclusively.
    // CR_LVBIE would cause AC97 IRQ at CIV=LVI which races with timer poll.
    // CR_IOCE: buffer completion interrupt (stats tracking)
    // CR_FEIE: FIFO error interrupt (underrun tracking)
    writeNabm8(NABM_PO_CR, CR_RPBM | CR_IOCE | CR_FEIE);

    serial.writeString("[AC97] Play: CR=0x");
    printHex8(readNabm8(NABM_PO_CR));
    serial.writeString(" SR=0x");
    printHex16(readNabm16(NABM_PO_SR));
    serial.writeString(" CIV=");
    printDec(@intCast(readNabm8(NABM_PO_CIV)));
    serial.writeString(" LVI=");
    printDec(@intCast(readNabm8(NABM_PO_LVI)));
    serial.writeString("\n");

    playback_state = .playing;
    stats.playback_started += 1;

    serial.writeString("[AC97] Playback started (continuous)\n");
    return true;
}

pub fn stop() void {
    if (!initialized) return;
    if (nabm_base == 0) return;

    // Wait for poll to finish if in progress
    var guard: u32 = 0;
    while (@atomicLoad(bool, &poll_in_progress, .acquire) and guard < 10000) : (guard += 1) {
        asm volatile ("pause");
    }

    writeNabm8(NABM_PO_CR, 0);
    writeNabm8(NABM_PO_CR, CR_RR);
    busyWait(10000);

    var timeout: u32 = 0;
    while (timeout < 1000) : (timeout += 1) {
        if ((readNabm8(NABM_PO_CR) & CR_RR) == 0) break;
        busyWait(100);
    }

    writeNabm16(NABM_PO_SR, SR_LVBCI | SR_BCIS | SR_FIFOE);

    playback_state = .stopped;
    stats.playback_stopped += 1;

    serial.writeString("[AC97] Playback stopped\n");
}

pub fn pause() void {
    if (!initialized or playback_state != .playing) return;
    if (nabm_base == 0) return;

    var cr = readNabm8(NABM_PO_CR);
    cr &= ~CR_RPBM;
    writeNabm8(NABM_PO_CR, cr);

    playback_state = .paused;
}

pub fn resume_playback() void {
    if (!initialized or playback_state != .paused) return;
    if (nabm_base == 0) return;

    var cr = readNabm8(NABM_PO_CR);
    cr |= CR_RPBM;
    writeNabm8(NABM_PO_CR, cr);

    playback_state = .playing;
}

// =============================================================================
// Volume Control
// =============================================================================

pub fn setMasterVolume(left: u8, right: u8, mute: bool) void {
    const l: u16 = @as(u16, left & 0x3F);
    const r: u16 = @as(u16, right & 0x3F);
    master_volume = (l << 8) | r;
    if (mute) master_volume |= 0x8000;
    if (nam_base != 0) writeNam16(NAM_MASTER_VOL, master_volume);
}

pub fn setPcmVolume(left: u8, right: u8, mute: bool) void {
    const l: u16 = @as(u16, left & 0x1F);
    const r: u16 = @as(u16, right & 0x1F);
    pcm_volume = (l << 8) | r;
    if (mute) pcm_volume |= 0x8000;
    if (nam_base != 0) writeNam16(NAM_PCM_OUT_VOL, pcm_volume);
}

pub fn setVolumePercent(percent: u8) void {
    const p = if (percent > 100) 100 else percent;
    const val: u8 = @intCast(31 - (@as(u16, p) * 31 / 100));
    setPcmVolume(val, val, p == 0);
    setMasterVolume(val, val, p == 0);
}

pub fn getMasterVolume() u16 {
    if (nam_base != 0) return readNam16(NAM_MASTER_VOL);
    return master_volume;
}

pub fn getPcmVolume() u16 {
    if (nam_base != 0) return readNam16(NAM_PCM_OUT_VOL);
    return pcm_volume;
}

pub fn isMuted() bool {
    return (getMasterVolume() & 0x8000) != 0;
}

pub fn toggleMute() void {
    master_volume ^= 0x8000;
    if (nam_base != 0) writeNam16(NAM_MASTER_VOL, master_volume);
}

// =============================================================================
// Sample Rate
// =============================================================================

pub fn setSampleRate(rate: u16) void {
    current_format.sample_rate = rate;
    if (nam_base == 0) return;
    if (variable_rate_supported) {
        writeNam16(NAM_PCM_FRONT_DAC_RATE, rate);
        writeNam16(NAM_PCM_LR_ADC_RATE, rate);
        const actual = readNam16(NAM_PCM_FRONT_DAC_RATE);
        if (actual != rate) {
            current_format.sample_rate = actual;
        }
    } else {
        current_format.sample_rate = SAMPLE_RATE_DEFAULT;
    }
}

pub fn getSampleRate() u16 {
    if (nam_base != 0 and variable_rate_supported) {
        return readNam16(NAM_PCM_FRONT_DAC_RATE);
    }
    return current_format.sample_rate;
}

// =============================================================================
// Tone Generation
// =============================================================================

pub fn generateTone(freq_hz: u16, duration_buffers: u8) void {
    if (!dma_initialized) return;

    const num_bufs = if (duration_buffers > NUM_PCM_BUFFERS)
        NUM_PCM_BUFFERS
    else
        @as(usize, duration_buffers);

    const frames_per_buf = PCM_BUFFER_SIZE / 4;
    const rate: u32 = @as(u32, current_format.sample_rate);
    const freq: u32 = if (freq_hz > 0) @as(u32, freq_hz) else 440;
    const period: u32 = if (freq > 0) rate / freq else 100;

    serial.writeString("[AC97] Generating ");
    printDec(@intCast(freq));
    serial.writeString("Hz, ");
    printDec(@intCast(num_bufs));
    serial.writeString(" bufs, period=");
    printDec(@intCast(period));
    serial.writeString(" frames\n");

    for (0..num_bufs) |buf_idx| {
        const virt = pcm_buffers_virt[buf_idx];
        if (virt == 0) continue;

        var frame: usize = 0;
        while (frame < frames_per_buf) : (frame += 1) {
            const global_frame = buf_idx * frames_per_buf + frame;
            const pos = if (period > 0) global_frame % period else 0;

            const high: bool = period > 0 and pos < period / 2;
            const amplitude: i16 = if (high) 24000 else -24000;

            const sample_u16: u16 = @bitCast(amplitude);
            const lo: u8 = @truncate(sample_u16 & 0xFF);
            const hi: u8 = @truncate((sample_u16 >> 8) & 0xFF);

            const offset = frame * 4;
            writeU8ToPhys(virt, offset + 0, lo);
            writeU8ToPhys(virt, offset + 1, hi);
            writeU8ToPhys(virt, offset + 2, lo);
            writeU8ToPhys(virt, offset + 3, hi);
        }
    }

    for (num_bufs..NUM_PCM_BUFFERS) |buf_idx| {
        const virt = pcm_buffers_virt[buf_idx];
        if (virt == 0) continue;
        var j: usize = 0;
        while (j < PCM_BUFFER_SIZE) : (j += 1) {
            writeU8ToPhys(virt, j, 0);
        }
    }

    asm volatile ("mfence" ::: .{ .memory = true });
}

pub fn fillSilence() void {
    if (!dma_initialized) return;
    for (0..NUM_PCM_BUFFERS) |idx| {
        const virt = pcm_buffers_virt[idx];
        if (virt == 0) continue;
        var j: usize = 0;
        while (j < PCM_BUFFER_SIZE) : (j += 1) {
            writeU8ToPhys(virt, j, 0);
        }
    }
    asm volatile ("mfence" ::: .{ .memory = true });
}

// =============================================================================
// Pre-emptive Circular DMA Polling (B2.10 — zero-gap playback)
// =============================================================================
//
// This function is called from TWO contexts:
//   1. APIC Timer interrupt (50Hz) — via audio.timerPoll()
//   2. Shell idle loop — via audio.poll()
//
// poll_in_progress atomic guard prevents concurrent access.
//
// Strategy: Set LVI = (CIV - 1) mod 32
//   DMA gets ~31 buffers of runway (~650ms at 48kHz stereo)
//   Timer calls every 20ms, so LVI is always updated in time
//   DMA never halts → zero gaps
//

pub fn poll() void {
    if (!initialized or nabm_base == 0) return;
    if (playback_state != .playing) return;

    // Re-entrancy guard: prevent timer IRQ and shell from
    // accessing AC97 registers simultaneously
    if (@atomicLoad(bool, &poll_in_progress, .acquire)) return;
    @atomicStore(bool, &poll_in_progress, true, .release);

    defer @atomicStore(bool, &poll_in_progress, false, .release);

    poll_count += 1;

    const sr = readNabm16(NABM_PO_SR);
    const cr = readNabm8(NABM_PO_CR);

    // Track buffer completions from status bits
    if ((sr & SR_BCIS) != 0) {
        stats.buffers_played += 1;
        stats.bytes_played += PCM_BUFFER_SIZE;
    }
    if ((sr & SR_FIFOE) != 0) {
        stats.underruns += 1;
    }

    // Clear pending status bits (write-1-to-clear, only defined bits)
    const clear_bits = sr & (SR_LVBCI | SR_BCIS | SR_FIFOE);
    if (clear_bits != 0) {
        writeNabm16(NABM_PO_SR, clear_bits);
    }

    // Pre-emptive circular LVI: set one position behind CIV
    const civ = readNabm8(NABM_PO_CIV);
    const new_lvi: u8 = if (civ == 0)
        @as(u8, @intCast(NUM_PCM_BUFFERS - 1))
    else
        civ - 1;

    // Only write LVI if changed (reduce I/O port writes)
    const current_lvi = readNabm8(NABM_PO_LVI);
    if (current_lvi != new_lvi) {
        writeNabm8(NABM_PO_LVI, new_lvi);
    }

    // If DMA halted (DCH set or RPBM cleared), restart
    if ((sr & SR_DCH) != 0 or (cr & CR_RPBM) == 0) {
        // Clear all status for clean restart
        writeNabm16(NABM_PO_SR, SR_LVBCI | SR_BCIS | SR_FIFOE);
        // Ensure LVI is set
        writeNabm8(NABM_PO_LVI, new_lvi);
        // Restart DMA — NO CR_LVBIE (timer handles LVI)
        writeNabm8(NABM_PO_CR, CR_RPBM | CR_IOCE | CR_FEIE);
        restart_count += 1;
    }
}

pub fn needsPoll() bool {
    return initialized and playback_state == .playing;
}

pub fn getPollStats() struct { polls: u64, restarts: u64 } {
    return .{ .polls = poll_count, .restarts = restart_count };
}

pub fn resetPollStats() void {
    poll_count = 0;
    restart_count = 0;
    irq_fired_count = 0;
}

// =============================================================================
// Microphone Capture (Voice AI Production Ready)
// =============================================================================

pub fn startCapture() bool {
    if (!initialized or !dma_initialized) return false;
    if (nabm_base == 0) return false;

    writeNabm8(NABM_PI_CR, CR_RR);
    busyWait(10000);
    var timeout: u32 = 0;
    while (timeout < 1000) : (timeout += 1) {
        if ((readNabm8(NABM_PI_CR) & CR_RR) == 0) break;
        busyWait(100);
    }

    writeNabm32(NABM_PI_BDBAR, @truncate(bdl_phys));
    writeNabm8(NABM_PI_LVI, @intCast(NUM_PCM_BUFFERS - 1));
    writeNabm16(NABM_PI_SR, SR_LVBCI | SR_BCIS | SR_FIFOE);
    writeNabm8(NABM_PI_CR, CR_RPBM | CR_LVBIE | CR_IOCE);

    capture_active = true;
    serial.writeString("[AC97] Capture started\n");
    return true;
}

pub fn stopCapture() void {
    if (nabm_base == 0) return;
    writeNabm8(NABM_PI_CR, 0);
    writeNabm8(NABM_PI_CR, CR_RR);
    busyWait(10000);
    var timeout: u32 = 0;
    while (timeout < 1000) : (timeout += 1) {
        if ((readNabm8(NABM_PI_CR) & CR_RR) == 0) break;
        busyWait(100);
    }
    writeNabm16(NABM_PI_SR, SR_LVBCI | SR_BCIS | SR_FIFOE);
    capture_active = false;
    serial.writeString("[AC97] Capture stopped\n");
}

pub fn isCaptureActive() bool {
    return capture_active;
}

pub fn isCaptureDataReady() bool {
    if (nabm_base == 0) return false;
    return (readNabm16(NABM_PI_SR) & SR_BCIS) != 0;
}

pub fn getCapturePosition() u16 {
    if (nabm_base == 0) return 0;
    return readNabm16(NABM_PI_PICB);
}

pub fn getCaptureIndex() u8 {
    if (nabm_base == 0) return 0;
    return readNabm8(NABM_PI_CIV);
}

pub fn getCaptureStats() struct { buffers: u64, bytes: u64, overruns: u64, active: bool } {
    return .{
        .buffers = capture_buffers_filled,
        .bytes = capture_bytes_captured,
        .overruns = capture_overruns,
        .active = capture_active,
    };
}

fn handleCaptureInterrupt() void {
    const sr = readNabm16(NABM_PI_SR);
    if ((sr & SR_BCIS) != 0) {
        capture_buffers_filled += 1;
        capture_bytes_captured += PCM_BUFFER_SIZE;
    }
    if ((sr & SR_LVBCI) != 0) {
        writeNabm8(NABM_PI_LVI, @intCast(NUM_PCM_BUFFERS - 1));
    }
    if ((sr & SR_FIFOE) != 0) {
        capture_overruns += 1;
    }
    writeNabm16(NABM_PI_SR, sr);
}

pub fn setCaptureSampleRate(rate: u16) void {
    if (nam_base == 0) return;
    if (variable_rate_supported) writeNam16(NAM_PCM_LR_ADC_RATE, rate);
}

pub fn getCaptureSampleRate() u16 {
    if (nam_base == 0) return SAMPLE_RATE_DEFAULT;
    if (variable_rate_supported) return readNam16(NAM_PCM_LR_ADC_RATE);
    return SAMPLE_RATE_DEFAULT;
}

pub fn setRecordSource(source: u8) void {
    if (nam_base == 0) return;
    const src: u16 = @as(u16, source & 0x07);
    writeNam16(NAM_RECORD_SELECT, (src << 8) | src);
}

pub fn getRecordSource() u8 {
    if (nam_base == 0) return 0;
    return @intCast(readNam16(NAM_RECORD_SELECT) & 0x07);
}

pub fn setMicVolume(volume: u8, boost: bool) void {
    if (nam_base == 0) return;
    var val: u16 = @as(u16, volume & 0x1F);
    if (boost) val |= 0x0040;
    writeNam16(NAM_MIC_VOL, val);
}

pub fn getMicVolume() u16 {
    if (nam_base == 0) return 0;
    return readNam16(NAM_MIC_VOL);
}

pub fn setRecordGain(left: u8, right: u8) void {
    if (nam_base == 0) return;
    const l: u16 = @as(u16, left & 0x0F);
    const r: u16 = @as(u16, right & 0x0F);
    writeNam16(NAM_RECORD_GAIN, (l << 8) | r);
}

pub fn getRecordGain() u16 {
    if (nam_base == 0) return 0;
    return readNam16(NAM_RECORD_GAIN);
}

pub fn configureForVoiceAI() void {
    serial.writeString("[AC97] Configuring for Voice AI...\n");
    setRecordSource(0);
    setCaptureSampleRate(SAMPLE_RATE_VOICE);
    setMicVolume(0, true);
    setRecordGain(8, 8);
    if (nam_base != 0) {
        var mic_vol = readNam16(NAM_MIC_VOL);
        mic_vol &= ~@as(u16, 0x8000);
        writeNam16(NAM_MIC_VOL, mic_vol);
    }
    serial.writeString("[AC97] Voice AI: Mic, 16kHz, +20dB, gain=12dB\n");
}

// =============================================================================
// Interrupt Handling (Status clearing only — DMA control via poll())
// =============================================================================

pub fn handleInterrupt() void {
    irq_fired_count += 1;

    if (nabm_base == 0) return;

    // Re-entrancy guard: don't touch registers if poll() is running
    if (@atomicLoad(bool, &poll_in_progress, .acquire)) {
        return;
    }

    const gs = readNabm32(NABM_GLOB_STA);

    // PCM Output interrupt — just clear status, don't touch CR/LVI
    if ((gs & GS_POINT) != 0) {
        const sr = readNabm16(NABM_PO_SR);

        if ((sr & SR_BCIS) != 0) {
            stats.buffers_played += 1;
            stats.bytes_played += PCM_BUFFER_SIZE;
        }

        if ((sr & SR_FIFOE) != 0) {
            stats.underruns += 1;
        }

        // Clear only defined status bits
        writeNabm16(NABM_PO_SR, sr & (SR_LVBCI | SR_BCIS | SR_FIFOE));
        stats.interrupts += 1;
    }

    // PCM Input interrupt (Voice AI)
    if ((gs & GS_PIINT) != 0) {
        handleCaptureInterrupt();
        stats.interrupts += 1;
    }

    // Microphone channel
    if ((gs & GS_MCINT) != 0) {
        writeNabm16(NABM_MC_SR, readNabm16(NABM_MC_SR));
        stats.interrupts += 1;
    }
}

pub fn getIrqFiredCount() u64 {
    return irq_fired_count;
}

// =============================================================================
// Query Functions
// =============================================================================

pub fn isInitialized() bool {
    return initialized;
}
pub fn isDetected() bool {
    return detected;
}
pub fn isCodecReady() bool {
    return codec_ready;
}
pub fn isDmaReady() bool {
    return dma_initialized;
}
pub fn isVariableRate() bool {
    return variable_rate_supported;
}
pub fn getPlaybackState() PlaybackState {
    return playback_state;
}
pub fn isPlaying() bool {
    return playback_state == .playing;
}
pub fn getFormat() AudioFormat {
    return current_format;
}
pub fn getNamBase() u16 {
    return nam_base;
}
pub fn getNabmBase() u16 {
    return nabm_base;
}
pub fn getIrq() u8 {
    return irq_line;
}
pub fn getCodecVendorId() u32 {
    return codec_vendor_id;
}
pub fn getStats() DriverStats {
    return stats;
}

pub fn getCurrentBufferIndex() u8 {
    if (nabm_base == 0) return 0;
    return readNabm8(NABM_PO_CIV);
}

pub fn getLastValidIndex() u8 {
    if (nabm_base == 0) return 0;
    return readNabm8(NABM_PO_LVI);
}

pub fn getPositionInBuffer() u16 {
    if (nabm_base == 0) return 0;
    return readNabm16(NABM_PO_PICB);
}

pub fn getGlobalStatus() u32 {
    if (nabm_base == 0) return 0;
    return readNabm32(NABM_GLOB_STA);
}

pub fn getOutputStatus() u16 {
    if (nabm_base == 0) return 0;
    return readNabm16(NABM_PO_SR);
}

pub fn deinit() void {
    stop();
    stopCapture();
    disableAc97Irq();
    freeDmaBuffers();
    initialized = false;
    detected = false;
    codec_ready = false;
}

// =============================================================================
// Utilities
// =============================================================================

fn busyWait(cycles: u32) void {
    var i: u32 = 0;
    while (i < cycles) : (i += 1) {
        asm volatile ("pause");
    }
}

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 12) & 0xF]);
    serial.writeChar(hex[(val >> 8) & 0xF]);
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    var i: u5 = 28;
    while (true) : (i -= 4) {
        const nibble: u4 = @intCast((val >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
    }
}

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) : (i -= 4) {
        const nibble: u4 = @intCast((val >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
    }
}

fn printDec(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
