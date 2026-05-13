//! Zamrud OS - Intel High Definition Audio (HDA) Driver
//! B2.10b: Intel HDA — Real Hardware + QEMU intel-hda
//! PCI Class 0x04, Subclass 0x03
//!
//! Fix B2.10b v8:
//!   1. FIXED: HDA_ICIS is a 16-bit register! (Was mistakenly 32-bit, causing all Verbs to fail).
//!   2. Forced use_immediate = true for 100% reliable codec initialization.
//!   3. Removed STATESTS premature clearing that hid the codec.

const serial = @import("../serial/serial.zig");
const pci = @import("../pci/pci.zig");
const pmm = @import("../../mm/pmm.zig");

// =============================================================================
// PCI IDs & Offsets
// =============================================================================

pub const HDA_VENDOR_INTEL: u16 = 0x8086;
pub const HDA_DEVICE_ICH6: u16 = 0x2668;
pub const HDA_DEVICE_ICH7: u16 = 0x27D8;
pub const HDA_DEVICE_ICH8: u16 = 0x284B;
pub const HDA_DEVICE_ICH9: u16 = 0x293E;
pub const HDA_DEVICE_ICH10: u16 = 0x3A3E;
pub const HDA_DEVICE_PCH: u16 = 0x1C20;
pub const HDA_DEVICE_PCH2: u16 = 0x1E20;
pub const HDA_DEVICE_PCH3: u16 = 0x8C20;

const HDA_GCAP: u32 = 0x00;
const HDA_VMIN: u32 = 0x02;
const HDA_VMAJ: u32 = 0x03;
const HDA_GCTL: u32 = 0x08;
const HDA_STATESTS: u32 = 0x0E;
const HDA_INTCTL: u32 = 0x20;
const HDA_INTSTS: u32 = 0x24;

const HDA_CORBLBASE: u32 = 0x40;
const HDA_CORBUBASE: u32 = 0x44;
const HDA_CORBWP: u32 = 0x48;
const HDA_CORBRP: u32 = 0x4A;
const HDA_CORBCTL: u32 = 0x4C;
const HDA_CORBSTS: u32 = 0x4D;
const HDA_CORBSIZE: u32 = 0x4E;

const HDA_RIRBLBASE: u32 = 0x50;
const HDA_RIRBUBASE: u32 = 0x54;
const HDA_RIRBWP: u32 = 0x58;
const HDA_RINTCNT: u32 = 0x5A;
const HDA_RIRBCTL: u32 = 0x5C;
const HDA_RIRBSTS: u32 = 0x5D;
const HDA_RIRBSIZE: u32 = 0x5E;

const HDA_ICOI: u32 = 0x60; // 32-bit
const HDA_ICII: u32 = 0x64; // 32-bit
const HDA_ICIS: u32 = 0x68; // 16-bit!

const SD_CTL: u32 = 0x00;
const SD_STS: u32 = 0x03;
const SD_LPIB: u32 = 0x04;
const SD_CBL: u32 = 0x08;
const SD_LVI: u32 = 0x0C;
const SD_FMT: u32 = 0x12;
const SD_BDLPL: u32 = 0x18;
const SD_BDLPU: u32 = 0x1C;

const GCTL_CRST: u32 = 1 << 0;
const GCTL_UNSOL: u32 = 1 << 8;

const SD_CTL_SRST: u32 = 1 << 0;
const SD_CTL_RUN: u32 = 1 << 1;
const SD_CTL_IOCE: u32 = 1 << 2;
const SD_CTL_FEIE: u32 = 1 << 3;
const SD_CTL_DEIE: u32 = 1 << 4;

const SD_STS_BCIS: u8 = 1 << 2;
const SD_STS_FIFOE: u8 = 1 << 3;
const SD_STS_DESE: u8 = 1 << 4;
const SD_STS_ALL: u8 = SD_STS_BCIS | SD_STS_FIFOE | SD_STS_DESE;

const ICIS_ICB: u16 = 1 << 0;
const ICIS_IRV: u16 = 1 << 1;

const FMT_48KHZ_16BIT_STEREO: u32 = 0x0011;
const BDL_FLAG_IOC: u32 = 1 << 0;

const PARAM_VENDOR_ID: u32 = 0x00;
const PARAM_NODE_COUNT: u32 = 0x04;
const PARAM_FUNC_TYPE: u32 = 0x05;
const PARAM_WIDGET_CAP: u32 = 0x09;
const PARAM_PIN_CAPS: u32 = 0x0C;

const VERB_GET_PARAM: u32 = 0xF0000;
const VERB_GET_CONN_SELECT: u32 = 0xF0100;
const VERB_SET_CONN_SELECT: u32 = 0x70100;
const VERB_GET_POWER_STATE: u32 = 0xF0500;
const VERB_SET_POWER_STATE: u32 = 0x70500;
const VERB_GET_CONV_FORMAT: u32 = 0xA0000;
const VERB_SET_CONV_FORMAT: u32 = 0x20000;
const VERB_GET_CONV_STREAM: u32 = 0xF0600;
const VERB_SET_CONV_STREAM: u32 = 0x70600;
const VERB_GET_PIN_CTRL: u32 = 0xF0700;
const VERB_SET_PIN_CTRL: u32 = 0x70700;
const VERB_GET_EAPD: u32 = 0xF0C00;
const VERB_SET_EAPD: u32 = 0x70C00;
const VERB_GET_AMP_GAIN: u32 = 0xB0000;
const VERB_SET_AMP_GAIN: u32 = 0x30000;

const WIDGET_AUDIO_OUT: u8 = 0x0;
const WIDGET_PIN: u8 = 0x4;

// =============================================================================
// Structs & State
// =============================================================================

pub const BdlEntry = extern struct {
    addr_lo: u32 align(1),
    addr_hi: u32 align(1),
    length: u32 align(1),
    flags: u32 align(1),
};

pub const NUM_BDL_ENTRIES: usize = 32;
pub const PCM_BUFFER_SIZE: usize = 4096;
pub const NUM_PCM_BUFFERS: usize = 32;

pub const PlaybackState = enum { stopped, playing, paused };

pub const DriverStats = struct {
    interrupts: u64,
    buffers_played: u64,
    underruns: u64,
    bytes_played: u64,
    corb_commands: u64,
    corb_get_commands: u64,
    corb_set_commands: u64,
    rirb_responses: u64,
    rirb_timeouts: u64,
    descriptor_errors: u64,
    stream_restarts: u64,
};

var initialized: bool = false;
var detected: bool = false;
var mmio_phys: u64 = 0;
var mmio_base: u64 = 0;
var irq_line: u8 = 0;
var hhdm_offset: u64 = 0;

var codec_addr: u8 = 0;
var codec_vendor: u32 = 0;
var num_input_sd: u8 = 0;
var num_output_sd: u8 = 0;
var output_sd_base: u32 = 0;

var dac_nid: u8 = 0;
var mixer_nid: u8 = 0;
var pin_nid: u8 = 0;
var fg_nid: u8 = 0;

var use_immediate: bool = true; // FORCE IMMEDIATE VERBS FOR STABILITY!

var bdl_phys: u64 = 0;
var bdl_virt: u64 = 0;
var pcm_phys: [NUM_PCM_BUFFERS]u64 = [_]u64{0} ** NUM_PCM_BUFFERS;
var pcm_virt: [NUM_PCM_BUFFERS]u64 = [_]u64{0} ** NUM_PCM_BUFFERS;
var dma_ready: bool = false;

var playback_state: PlaybackState = .stopped;
var poll_in_progress: bool = false;
var poll_count: u64 = 0;
var restart_count: u64 = 0;
var last_lpib: u32 = 0;

var stats: DriverStats = .{
    .interrupts = 0,
    .buffers_played = 0,
    .underruns = 0,
    .bytes_played = 0,
    .corb_commands = 0,
    .corb_get_commands = 0,
    .corb_set_commands = 0,
    .rirb_responses = 0,
    .rirb_timeouts = 0,
    .descriptor_errors = 0,
    .stream_restarts = 0,
};

// =============================================================================
// MMIO Access
// =============================================================================

inline fn physToVirt(phys: u64) u64 {
    return hhdm_offset + phys;
}
inline fn mmioRead8(offset: u32) u8 {
    const ptr: *volatile u8 = @ptrFromInt(mmio_base + offset);
    return ptr.*;
}
inline fn mmioRead16(offset: u32) u16 {
    const ptr: *volatile u16 = @ptrFromInt(mmio_base + offset);
    return ptr.*;
}
inline fn mmioRead32(offset: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + offset);
    return ptr.*;
}
inline fn mmioWrite8(offset: u32, value: u8) void {
    const ptr: *volatile u8 = @ptrFromInt(mmio_base + offset);
    ptr.* = value;
}
inline fn mmioWrite16(offset: u32, value: u16) void {
    const ptr: *volatile u16 = @ptrFromInt(mmio_base + offset);
    ptr.* = value;
}
inline fn mmioWrite32(offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + offset);
    ptr.* = value;
}

fn sdRead8(sd_offset: u32) u8 {
    return mmioRead8(output_sd_base + sd_offset);
}
fn sdRead16(sd_offset: u32) u16 {
    return mmioRead16(output_sd_base + sd_offset);
}
fn sdRead32(sd_offset: u32) u32 {
    return mmioRead32(output_sd_base + sd_offset);
}
fn sdWrite8(sd_offset: u32, value: u8) void {
    mmioWrite8(output_sd_base + sd_offset, value);
}
fn sdWrite16(sd_offset: u32, value: u16) void {
    mmioWrite16(output_sd_base + sd_offset, value);
}
fn sdWrite32(sd_offset: u32, value: u32) void {
    mmioWrite32(output_sd_base + sd_offset, value);
}
fn sdWrite64(sd_offset: u32, value: u64) void {
    sdWrite32(sd_offset, @truncate(value & 0xFFFFFFFF));
    sdWrite32(sd_offset + 4, @truncate(value >> 32));
}

fn busyWait(cycles: u32) void {
    var i: u32 = 0;
    while (i < cycles) : (i += 1) {
        asm volatile ("pause");
    }
}

// =============================================================================
// Initialization
// =============================================================================

pub fn probe() bool {
    if (!pci.isInitialized()) return false;
    if (pci.findByClass(0x04, 0x03)) |dev| return setupFromPci(dev);
    return false;
}

fn setupFromPci(dev: *const pci.PciDevice) bool {
    const bar0 = dev.bar0;
    const bar1 = dev.bar1;
    if ((bar0 & 0x01) != 0) return false;

    const bar_type = (bar0 >> 1) & 0x3;
    if (bar_type == 0x2) {
        mmio_phys = (@as(u64, bar1) << 32) | (bar0 & 0xFFFFFFF0);
    } else {
        mmio_phys = bar0 & 0xFFFFFFF0;
    }

    if (mmio_phys == 0) return false;
    irq_line = dev.irq_line;
    detected = true;
    pci.enableBusMaster(dev);
    pci.enableMemorySpace(dev);
    return true;
}

pub fn init() bool {
    if (!detected) {
        if (!probe()) return false;
    }

    serial.writeString("[HDA] Initializing...\n");
    hhdm_offset = pmm.getHhdmOffset();
    mmio_base = hhdm_offset + mmio_phys;
    use_immediate = true; // FORCE IMMEDIATE MODE

    if (!resetController()) return false;
    readCapabilities();

    const stream_bit: u32 = @as(u32, 1) << @as(u5, @truncate(num_input_sd));
    mmioWrite32(HDA_INTCTL, (1 << 31) | stream_bit);

    if (!allocDmaBuffers()) return false;

    enumerateCodecs();

    initialized = true;
    serial.writeString("[HDA] Init OK\n");
    return true;
}

fn resetController() bool {
    mmioWrite32(HDA_GCTL, 0);
    busyWait(1000000);

    mmioWrite32(HDA_GCTL, GCTL_CRST);
    var timeout: u32 = 0;
    while (timeout < 1000000) : (timeout += 1) {
        if ((mmioRead32(HDA_GCTL) & GCTL_CRST) != 0) break;
        busyWait(10);
    }

    if ((mmioRead32(HDA_GCTL) & GCTL_CRST) == 0) return false;

    // Tunggu 50ms agar codec bangun dan set SDI bits di STATESTS
    busyWait(5000000);

    // NOTE: DILARANG membersihkan STATESTS di sini, biarkan enumerateCodecs membacanya!
    return true;
}

fn readCapabilities() void {
    const gcap = mmioRead16(HDA_GCAP);
    num_output_sd = @truncate((gcap >> 12) & 0xF);
    num_input_sd = @truncate((gcap >> 8) & 0xF);
    output_sd_base = 0x80 + (@as(u32, num_input_sd) * 0x20);

    if (num_output_sd == 0) {
        num_output_sd = 1;
        output_sd_base = 0x80;
    }
}

// =============================================================================
// Verb Transmit (FIXED ICIS REGISTER SIZE)
// =============================================================================

fn sendVerbImmediate(codec: u8, nid: u8, verb: u32) u32 {
    const command: u32 = (@as(u32, codec) << 28) | (@as(u32, nid) << 20) | (verb & 0xFFFFF);

    // Tunggu ICB = 0
    var timeout: u32 = 0;
    while (timeout < 1000000) : (timeout += 1) {
        if ((mmioRead16(HDA_ICIS) & ICIS_ICB) == 0) break; // ICIS is u16!
        busyWait(10);
    }

    // Bersihkan IRV sebelum mengirim
    mmioWrite16(HDA_ICIS, ICIS_IRV);

    // Kirim command
    mmioWrite32(HDA_ICOI, command);
    mmioWrite16(HDA_ICIS, mmioRead16(HDA_ICIS) | ICIS_ICB); // Start ICB

    // Tunggu balasan IRV = 1
    timeout = 0;
    while (timeout < 5000000) : (timeout += 1) {
        if ((mmioRead16(HDA_ICIS) & ICIS_IRV) != 0) {
            const result = mmioRead32(HDA_ICII);
            mmioWrite16(HDA_ICIS, ICIS_IRV); // Bersihkan IRV setelah dibaca
            stats.corb_commands += 1;
            stats.corb_get_commands += 1;
            stats.rirb_responses += 1;
            return result;
        }
        if ((timeout % 100) == 0) asm volatile ("pause");
    }
    stats.rirb_timeouts += 1;
    return 0xFFFFFFFF;
}

fn sendVerb(codec: u8, nid: u8, verb: u32) void {
    _ = sendVerbImmediate(codec, nid, verb);
}

fn sendVerbGetResponse(codec: u8, nid: u8, verb: u32) u32 {
    return sendVerbImmediate(codec, nid, verb);
}

// =============================================================================
// Codec Enumeration
// =============================================================================

fn enumerateCodecs() void {
    serial.writeString("[HDA] Enumerating codecs...\n");

    const statests = mmioRead16(HDA_STATESTS);
    serial.writeString("[HDA] STATESTS=0x");
    printHex16(statests);
    serial.writeString("\n");

    if (statests != 0) {
        var c: u8 = 0;
        while (c < 15) : (c += 1) {
            if ((statests & (@as(u16, 1) << @intCast(c))) != 0) {
                codec_addr = c;
                serial.writeString("[HDA] Codec at SDI ");
                printDec(c);
                serial.writeString("\n");
                setupCodec(c);
                return;
            }
        }
    }

    serial.writeString("[HDA] No SDI bits, probe addr 0\n");
    codec_addr = 0;
    setupCodec(0);
}

fn setupCodec(codec: u8) void {
    codec_vendor = sendVerbGetResponse(codec, 0, VERB_GET_PARAM | PARAM_VENDOR_ID);
    serial.writeString("[HDA] Vendor=0x");
    printHex32(codec_vendor);
    serial.writeString("\n");

    if (codec_vendor == 0xFFFFFFFF or codec_vendor == 0) {
        serial.writeString("[HDA] Failed to read vendor, using defaults\n");
        setupDefaultPath();
        return;
    }

    const root_nodes = sendVerbGetResponse(codec, 0, VERB_GET_PARAM | PARAM_NODE_COUNT);
    const start_nid: u8 = @truncate((root_nodes >> 16) & 0xFF);
    const node_count: u8 = @truncate(root_nodes & 0xFF);

    var found_fg: u8 = 0;
    var n: u8 = 0;
    while (n < node_count) : (n += 1) {
        const nid = start_nid + n;
        const func_type = sendVerbGetResponse(codec, nid, VERB_GET_PARAM | PARAM_FUNC_TYPE);
        if (func_type != 0xFFFFFFFF and (func_type & 0xFF) == 0x01) {
            found_fg = nid;
            fg_nid = nid;
            break;
        }
    }

    if (found_fg == 0) {
        found_fg = 1;
        fg_nid = 1;
    }

    sendVerb(codec, found_fg, VERB_SET_POWER_STATE | 0x00);
    busyWait(500000);

    const fg_nodes = sendVerbGetResponse(codec, found_fg, VERB_GET_PARAM | PARAM_NODE_COUNT);
    const widget_start: u8 = @truncate((fg_nodes >> 16) & 0xFF);
    const widget_count: u8 = @truncate(fg_nodes & 0xFF);

    findOutputPath(codec, widget_start, widget_count);

    if (dac_nid != 0 and pin_nid != 0) {
        configureOutputPath(codec);
    } else {
        setupDefaultPath();
    }
}

fn findOutputPath(codec: u8, start: u8, count: u8) void {
    var i: u8 = 0;
    while (i < count) : (i += 1) {
        const nid = start + i;
        const wcaps = sendVerbGetResponse(codec, nid, VERB_GET_PARAM | PARAM_WIDGET_CAP);
        if (wcaps == 0xFFFFFFFF) continue;

        const wtype: u8 = @truncate((wcaps >> 20) & 0xF);
        if (wtype == WIDGET_AUDIO_OUT and dac_nid == 0) dac_nid = nid;
        if (wtype == WIDGET_PIN and pin_nid == 0) pin_nid = nid;
    }
}

fn configureOutputPath(codec: u8) void {
    serial.writeString("[HDA] Config: DAC=");
    printDec(dac_nid);
    serial.writeString(" Pin=");
    printDec(pin_nid);
    serial.writeString("\n");

    sendVerb(codec, dac_nid, VERB_SET_POWER_STATE | 0x00);
    sendVerb(codec, pin_nid, VERB_SET_POWER_STATE | 0x00);
    busyWait(200000);

    sendVerb(codec, dac_nid, VERB_SET_CONV_FORMAT | FMT_48KHZ_16BIT_STEREO);
    sendVerb(codec, dac_nid, VERB_SET_CONV_STREAM | (1 << 4) | 0);
    sendVerb(codec, pin_nid, VERB_SET_CONN_SELECT | 0x00);
    sendVerb(codec, pin_nid, VERB_SET_PIN_CTRL | 0xC0);
    sendVerb(codec, pin_nid, VERB_SET_EAPD | 0x02);

    // Unmute & Full Gain
    sendVerb(codec, dac_nid, VERB_SET_AMP_GAIN | 0xB04F);
    sendVerb(codec, pin_nid, VERB_SET_AMP_GAIN | 0xB04F);
}

fn setupDefaultPath() void {
    if (fg_nid == 0) fg_nid = 1;
    if (dac_nid == 0) dac_nid = 2;
    if (pin_nid == 0) pin_nid = 4; // hda-micro default pin is usually 4

    serial.writeString("[HDA] Blind config DAC=");
    printDec(dac_nid);
    serial.writeString(" Pin=");
    printDec(pin_nid);
    serial.writeString("\n");

    sendVerb(codec_addr, fg_nid, VERB_SET_POWER_STATE | 0x00);
    sendVerb(codec_addr, dac_nid, VERB_SET_POWER_STATE | 0x00);
    sendVerb(codec_addr, pin_nid, VERB_SET_POWER_STATE | 0x00);
    busyWait(200000);

    sendVerb(codec_addr, dac_nid, VERB_SET_CONV_FORMAT | FMT_48KHZ_16BIT_STEREO);
    sendVerb(codec_addr, dac_nid, VERB_SET_CONV_STREAM | (1 << 4) | 0);
    sendVerb(codec_addr, pin_nid, VERB_SET_CONN_SELECT | 0x00);
    sendVerb(codec_addr, pin_nid, VERB_SET_PIN_CTRL | 0xC0);
    sendVerb(codec_addr, pin_nid, VERB_SET_EAPD | 0x02);

    sendVerb(codec_addr, dac_nid, VERB_SET_AMP_GAIN | 0xB04F);
    sendVerb(codec_addr, pin_nid, VERB_SET_AMP_GAIN | 0xB04F);
}

// =============================================================================
// DMA Buffer Allocation
// =============================================================================

fn allocDmaBuffers() bool {
    bdl_phys = pmm.allocPage() orelse return false;
    bdl_virt = physToVirt(bdl_phys);
    zeroMemory(bdl_virt, 4096);

    for (0..NUM_PCM_BUFFERS) |i| {
        pcm_phys[i] = pmm.allocPage() orelse return false;
        pcm_virt[i] = physToVirt(pcm_phys[i]);
        zeroMemory(pcm_virt[i], PCM_BUFFER_SIZE);
    }

    for (0..NUM_PCM_BUFFERS) |i| {
        const off = i * @sizeOf(BdlEntry);
        const e: *volatile BdlEntry = @ptrFromInt(bdl_virt + off);
        e.addr_lo = @truncate(pcm_phys[i] & 0xFFFFFFFF);
        e.addr_hi = @truncate(pcm_phys[i] >> 32);
        e.length = PCM_BUFFER_SIZE;
        e.flags = BDL_FLAG_IOC;
    }
    dma_ready = true;
    return true;
}

// =============================================================================
// Playback
// =============================================================================

pub fn play() bool {
    if (!initialized or !dma_ready) return false;

    // Reset Stream
    sdWrite32(SD_CTL, SD_CTL_SRST);
    busyWait(10000);
    sdWrite32(SD_CTL, 0);
    busyWait(10000);

    // Setup BDL
    sdWrite64(SD_BDLPL, bdl_phys);
    sdWrite32(SD_CBL, @intCast(NUM_PCM_BUFFERS * PCM_BUFFER_SIZE));
    sdWrite16(SD_LVI, @intCast(NUM_BDL_ENTRIES - 1));
    sdWrite16(SD_FMT, @truncate(FMT_48KHZ_16BIT_STEREO));
    sdWrite8(SD_STS, SD_STS_ALL);

    // Tag=1
    const ctl_base: u32 = (1 << 20) | SD_CTL_IOCE | SD_CTL_FEIE | SD_CTL_DEIE;
    sdWrite32(SD_CTL, ctl_base);
    busyWait(100000);

    // Re-apply codec routing right before RUN
    sendVerb(codec_addr, dac_nid, VERB_SET_CONV_STREAM | (1 << 4) | 0);
    busyWait(50000);

    // RUN!
    sdWrite32(SD_CTL, ctl_base | SD_CTL_RUN);
    playback_state = .playing;
    return true;
}

pub fn stop() void {
    if (!initialized) return;
    sdWrite32(SD_CTL, sdRead32(SD_CTL) & ~SD_CTL_RUN);
    busyWait(10000);
    sdWrite32(SD_CTL, SD_CTL_SRST);
    busyWait(10000);
    sdWrite32(SD_CTL, 0);
    playback_state = .stopped;
}

pub fn pause() void {
    if (!initialized) return;
    sdWrite32(SD_CTL, sdRead32(SD_CTL) & ~SD_CTL_RUN);
    playback_state = .paused;
}

pub fn resume_playback() void {
    if (!initialized) return;
    sdWrite32(SD_CTL, sdRead32(SD_CTL) | SD_CTL_RUN);
    playback_state = .playing;
}

// =============================================================================
// Tone Generation
// =============================================================================

pub fn generateTone(freq_hz: u16, duration_buffers: u8) void {
    if (!dma_ready) return;
    const num_bufs: usize = @min(@as(usize, duration_buffers), NUM_PCM_BUFFERS);
    const frames_per_buf: usize = PCM_BUFFER_SIZE / 4;
    const freq: u32 = if (freq_hz > 0) @as(u32, freq_hz) else 440;
    const period: u32 = 48000 / freq;

    for (0..num_bufs) |bi| {
        const ptr: [*]volatile u8 = @ptrFromInt(pcm_virt[bi]);
        var frame: usize = 0;
        while (frame < frames_per_buf) : (frame += 1) {
            const pos = (bi * frames_per_buf + frame) % period;
            const amp: i16 = if (pos < (period / 2)) 16384 else -16384;
            const smp: u16 = @bitCast(amp);
            const off = frame * 4;
            ptr[off + 0] = @truncate(smp & 0xFF);
            ptr[off + 1] = @truncate((smp >> 8) & 0xFF);
            ptr[off + 2] = @truncate(smp & 0xFF);
            ptr[off + 3] = @truncate((smp >> 8) & 0xFF);
        }
    }
}

pub fn fillSilence() void {
    if (!dma_ready) return;
    for (0..NUM_PCM_BUFFERS) |i| zeroMemory(pcm_virt[i], PCM_BUFFER_SIZE);
}

// =============================================================================
// Poll & Status
// =============================================================================

pub fn poll() void {
    if (playback_state != .playing) return;

    // Circular LVI Update
    const lpib = sdRead32(SD_LPIB);
    const cur_buf: u32 = (lpib / @as(u32, PCM_BUFFER_SIZE)) % @as(u32, NUM_BDL_ENTRIES);
    const new_lvi: u16 = if (cur_buf == 0) @intCast(NUM_BDL_ENTRIES - 1) else @intCast(cur_buf - 1);
    if (sdRead16(SD_LVI) != new_lvi) sdWrite16(SD_LVI, new_lvi);

    // Clear SD Status Bits
    sdWrite8(SD_STS, SD_STS_ALL);
}

pub fn handleInterrupt() void {
    const intsts = mmioRead32(HDA_INTSTS);
    mmioWrite32(HDA_INTSTS, intsts);
    sdWrite8(SD_STS, SD_STS_ALL);
}

pub fn setVolume(_: u8) void {}
pub fn setSampleRate(_: u16) void {}

pub fn isInitialized() bool {
    return initialized;
}
pub fn isDetected() bool {
    return detected;
}
pub fn isDmaReady() bool {
    return dma_ready;
}
pub fn isPlaying() bool {
    return playback_state == .playing;
}
pub fn getPlaybackState() PlaybackState {
    return playback_state;
}
pub fn getStats() DriverStats {
    return stats;
}
pub fn getMmioBase() u64 {
    return mmio_base;
}
pub fn getIrq() u8 {
    return irq_line;
}
pub fn getCodecVendor() u32 {
    return codec_vendor;
}
pub fn getDacNid() u8 {
    return dac_nid;
}
pub fn getPinNid() u8 {
    return pin_nid;
}
pub fn getLpib() u32 {
    return sdRead32(SD_LPIB);
}
pub fn getCurrentBuffer() u32 {
    return 0;
}
pub fn getOutputStatus() u8 {
    return sdRead8(SD_STS);
}
pub fn getLastLpib() u32 {
    return 0;
}
pub fn needsPoll() bool {
    return initialized and playback_state == .playing;
}
pub fn getPollStats() struct { polls: u64, restarts: u64 } {
    return .{ .polls = 0, .restarts = 0 };
}
pub fn resetPollStats() void {}
pub fn deinit() void {}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[@as(usize, (val >> 12) & 0xF)]);
    serial.writeChar(hex[@as(usize, (val >> 8) & 0xF)]);
    serial.writeChar(hex[@as(usize, (val >> 4) & 0xF)]);
    serial.writeChar(hex[@as(usize, val & 0xF)]);
}
fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    var i: u5 = 28;
    while (true) : (i -= 4) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
    }
}
fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) : (i -= 4) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
    }
}
fn printDec(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var len: usize = 0;
    var v = val;
    while (v > 0) : (len += 1) {
        buf[len] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (len > 0) {
        len -= 1;
        serial.writeChar(buf[len]);
    }
}
fn zeroMemory(addr: u64, size: usize) void {
    var i: usize = 0;
    while (i < size) : (i += 1) {
        const ptr: *volatile u8 = @ptrFromInt(addr + i);
        ptr.* = 0;
    }
}
