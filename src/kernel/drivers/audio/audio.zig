//! Zamrud OS - Audio Subsystem API
//! Unified audio interface abstracting AC97/HDA backends
//! B2.10: Sound Driver — Timer-driven continuous playback
//!
//! Architecture:
//!   APIC Timer (100Hz) → timerPoll() → ac97.poll() [<1µs, IRQ-safe]
//!   Shell idle loop → poll() → ac97.poll() [backup path]
//!   IRQ handler → handleInterrupt() → ac97.handleInterrupt()
//!
//! Three poll paths ensure zero-gap circular DMA playback:
//!   1. Timer interrupt (primary) — 10ms interval, never misses
//!   2. Shell idle loop (secondary) — variable interval
//!   3. Hardware IRQ (tertiary) — if AC97 IRQ fires

const ac97 = @import("ac97.zig");
const serial = @import("../serial/serial.zig");

// =============================================================================
// Types
// =============================================================================

pub const AudioBackend = enum {
    none,
    ac97,
    hda, // Future
};

pub const AudioStatus = struct {
    backend: AudioBackend,
    initialized: bool,
    codec_ready: bool,
    dma_ready: bool,
    playing: bool,
    sample_rate: u16,
    channels: u8,
    bits_per_sample: u8,
    volume_percent: u8,
    muted: bool,
    variable_rate: bool,
    nam_base: u16,
    nabm_base: u16,
    irq: u8,
    codec_vendor: u32,
    buffers_played: u64,
    bytes_played: u64,
    underruns: u64,
    interrupts: u64,
    timer_polls: u64,
};

// =============================================================================
// State
// =============================================================================

var active_backend: AudioBackend = .none;
var audio_initialized: bool = false;

// B2.10: Timer poll tracking
var timer_poll_count: u64 = 0;
var shell_poll_count: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() bool {
    serial.writeString("[AUDIO] Probing audio devices...\n");

    // Try AC97 first
    if (ac97.probe()) {
        serial.writeString("[AUDIO] AC97 detected, initializing...\n");
        if (ac97.init()) {
            active_backend = .ac97;
            audio_initialized = true;
            serial.writeString("[AUDIO] AC97 backend active\n");
            return true;
        }
    }

    // TODO: Try HDA in future

    serial.writeString("[AUDIO] No audio device found\n");
    return false;
}

// =============================================================================
// Playback
// =============================================================================

pub fn playTone(freq_hz: u16, duration_buffers: u8) bool {
    switch (active_backend) {
        .ac97 => {
            ac97.generateTone(freq_hz, duration_buffers);
            return ac97.play();
        },
        else => return false,
    }
}

pub fn stopPlayback() void {
    switch (active_backend) {
        .ac97 => ac97.stop(),
        else => {},
    }
}

pub fn pausePlayback() void {
    switch (active_backend) {
        .ac97 => ac97.pause(),
        else => {},
    }
}

pub fn resumePlayback() void {
    switch (active_backend) {
        .ac97 => ac97.resume_playback(),
        else => {},
    }
}

pub fn isPlaying() bool {
    switch (active_backend) {
        .ac97 => return ac97.isPlaying(),
        else => return false,
    }
}

// =============================================================================
// Volume
// =============================================================================

pub fn setVolume(percent: u8) void {
    switch (active_backend) {
        .ac97 => ac97.setVolumePercent(percent),
        else => {},
    }
}

pub fn getVolumePercent() u8 {
    switch (active_backend) {
        .ac97 => {
            const vol = ac97.getPcmVolume();
            if ((vol & 0x8000) != 0) return 0; // Muted
            const right = vol & 0x1F;
            return @intCast(100 - (@as(u16, @intCast(right)) * 100 / 31));
        },
        else => return 0,
    }
}

pub fn toggleMute() void {
    switch (active_backend) {
        .ac97 => ac97.toggleMute(),
        else => {},
    }
}

pub fn isMuted() bool {
    switch (active_backend) {
        .ac97 => return ac97.isMuted(),
        else => return true,
    }
}

// =============================================================================
// Sample Rate
// =============================================================================

pub fn setSampleRate(rate: u16) void {
    switch (active_backend) {
        .ac97 => ac97.setSampleRate(rate),
        else => {},
    }
}

pub fn getSampleRate() u16 {
    switch (active_backend) {
        .ac97 => return ac97.getSampleRate(),
        else => return 0,
    }
}

// =============================================================================
// Polling — Triple-path for zero-gap continuous playback
// =============================================================================

/// Shell idle loop poll (secondary path)
/// Called from shell.readInput() and shell.shellLoop()
pub fn poll() void {
    switch (active_backend) {
        .ac97 => {
            ac97.poll();
            shell_poll_count += 1;
        },
        else => {},
    }
}

/// Check if audio is playing and needs polling
pub fn needsPoll() bool {
    switch (active_backend) {
        .ac97 => return ac97.needsPoll(),
        else => return false,
    }
}

/// B2.10: Timer-driven poll — called from APIC timer interrupt (100Hz)
///
/// This is the PRIMARY poll path for continuous playback.
/// Runs in IRQ context, but ac97.poll() only does:
///   - I/O port reads (inb/inw/inl) — <100ns each
///   - I/O port writes (outb/outw/outl) — <100ns each
///   - Total: ~500ns worst case
///
/// At 100Hz (10ms interval), this ensures DMA LVI is always
/// updated BEFORE CIV catches up, preventing halt gaps.
///
/// AC97 DMA buffer duration at 48kHz stereo 16-bit:
///   32 buffers × 4096 bytes = 131072 bytes
///   131072 / (48000 × 4) = ~682ms total
///   1 buffer = ~21ms
///   Timer at 10ms → always 2+ polls per buffer → zero gaps
pub fn timerPoll() void {
    switch (active_backend) {
        .ac97 => {
            if (ac97.needsPoll()) {
                ac97.poll();
                timer_poll_count += 1;
            }
        },
        else => {},
    }
}

/// Get timer poll statistics
pub fn getTimerPollCount() u64 {
    return timer_poll_count;
}

/// Get shell poll statistics
pub fn getShellPollCount() u64 {
    return shell_poll_count;
}

/// Reset poll statistics
pub fn resetPollStats() void {
    timer_poll_count = 0;
    shell_poll_count = 0;
    ac97.resetPollStats();
}

// =============================================================================
// Status
// =============================================================================

pub fn getStatus() AudioStatus {
    switch (active_backend) {
        .ac97 => {
            const fmt = ac97.getFormat();
            const st = ac97.getStats();
            return .{
                .backend = .ac97,
                .initialized = ac97.isInitialized(),
                .codec_ready = ac97.isCodecReady(),
                .dma_ready = ac97.isDmaReady(),
                .playing = ac97.isPlaying(),
                .sample_rate = fmt.sample_rate,
                .channels = fmt.channels,
                .bits_per_sample = fmt.bits_per_sample,
                .volume_percent = getVolumePercent(),
                .muted = ac97.isMuted(),
                .variable_rate = ac97.isVariableRate(),
                .nam_base = ac97.getNamBase(),
                .nabm_base = ac97.getNabmBase(),
                .irq = ac97.getIrq(),
                .codec_vendor = ac97.getCodecVendorId(),
                .buffers_played = st.buffers_played,
                .bytes_played = st.bytes_played,
                .underruns = st.underruns,
                .interrupts = st.interrupts,
                .timer_polls = timer_poll_count,
            };
        },
        else => return .{
            .backend = .none,
            .initialized = false,
            .codec_ready = false,
            .dma_ready = false,
            .playing = false,
            .sample_rate = 0,
            .channels = 0,
            .bits_per_sample = 0,
            .volume_percent = 0,
            .muted = true,
            .variable_rate = false,
            .nam_base = 0,
            .nabm_base = 0,
            .irq = 0,
            .codec_vendor = 0,
            .buffers_played = 0,
            .bytes_played = 0,
            .underruns = 0,
            .interrupts = 0,
            .timer_polls = 0,
        },
    }
}

pub fn isInitialized() bool {
    return audio_initialized;
}

pub fn getBackend() AudioBackend {
    return active_backend;
}

pub fn getBackendName() []const u8 {
    return switch (active_backend) {
        .none => "None",
        .ac97 => "AC97",
        .hda => "HDA",
    };
}

pub fn handleInterrupt() void {
    switch (active_backend) {
        .ac97 => ac97.handleInterrupt(),
        else => {},
    }
}

pub fn deinit() void {
    switch (active_backend) {
        .ac97 => ac97.deinit(),
        else => {},
    }
    active_backend = .none;
    audio_initialized = false;
    timer_poll_count = 0;
    shell_poll_count = 0;
}
