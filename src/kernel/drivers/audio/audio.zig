//! Zamrud OS - Audio Subsystem API
//! Unified audio interface abstracting AC97/HDA backends
//! B2.10:  AC97 Sound Driver
//! B2.10b: Intel HDA Driver
//!
//! Backend priority: HDA > AC97

const ac97 = @import("ac97.zig");
const hda = @import("hda.zig");
const serial = @import("../serial/serial.zig");

// =============================================================================
// Types
// =============================================================================

pub const AudioBackend = enum { none, ac97, hda };

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
    // AC97
    nam_base: u16,
    nabm_base: u16,
    // HDA
    mmio_base: u64,
    dac_nid: u8,
    pin_nid: u8,
    // Common
    irq: u8,
    codec_vendor: u32,
    buffers_played: u64,
    bytes_played: u64,
    underruns: u64,
    interrupts: u64,
    timer_polls: u64,
    descriptor_errors: u64,
    stream_restarts: u64,
    rirb_timeouts: u64,
};

// =============================================================================
// State
// =============================================================================

var active_backend: AudioBackend = .none;
var audio_initialized: bool = false;
var timer_poll_count: u64 = 0;
var shell_poll_count: u64 = 0;

// =============================================================================
// Init
// =============================================================================

pub fn init() bool {
    serial.writeString("[AUDIO] Probing audio devices...\n");

    // HDA dulu (real hardware + QEMU intel-hda)
    if (hda.probe()) {
        serial.writeString("[AUDIO] HDA detected, initializing...\n");
        if (hda.init()) {
            active_backend = .hda;
            audio_initialized = true;
            serial.writeString("[AUDIO] Backend: Intel HDA\n");
            return true;
        }
        serial.writeString("[AUDIO] HDA init failed, fallback AC97\n");
    }

    // Fallback: AC97
    if (ac97.probe()) {
        serial.writeString("[AUDIO] AC97 detected, initializing...\n");
        if (ac97.init()) {
            active_backend = .ac97;
            audio_initialized = true;
            serial.writeString("[AUDIO] Backend: AC97\n");
            return true;
        }
    }

    serial.writeString("[AUDIO] No audio device found\n");
    return false;
}

// =============================================================================
// Playback
// =============================================================================

pub fn playTone(freq_hz: u16, duration_buffers: u8) bool {
    return switch (active_backend) {
        .hda => blk: {
            hda.generateTone(freq_hz, duration_buffers);
            break :blk hda.play();
        },
        .ac97 => blk: {
            ac97.generateTone(freq_hz, duration_buffers);
            break :blk ac97.play();
        },
        .none => false,
    };
}

pub fn stopPlayback() void {
    switch (active_backend) {
        .hda => hda.stop(),
        .ac97 => ac97.stop(),
        .none => {},
    }
}

pub fn pausePlayback() void {
    switch (active_backend) {
        .hda => hda.pause(),
        .ac97 => ac97.pause(),
        .none => {},
    }
}

pub fn resumePlayback() void {
    switch (active_backend) {
        .hda => hda.resume_playback(),
        .ac97 => ac97.resume_playback(),
        .none => {},
    }
}

pub fn isPlaying() bool {
    return switch (active_backend) {
        .hda => hda.isPlaying(),
        .ac97 => ac97.isPlaying(),
        .none => false,
    };
}

// =============================================================================
// Volume
// =============================================================================

pub fn setVolume(percent: u8) void {
    switch (active_backend) {
        .hda => hda.setVolume(percent),
        .ac97 => ac97.setVolumePercent(percent),
        .none => {},
    }
}

pub fn getVolumePercent() u8 {
    return switch (active_backend) {
        .hda => 75, // HDA tidak ada easy register readback
        .ac97 => blk: {
            const vol = ac97.getPcmVolume();
            if ((vol & 0x8000) != 0) break :blk 0;
            const right: u16 = vol & 0x1F;
            break :blk @intCast(100 - (right * 100 / 31));
        },
        .none => 0,
    };
}

pub fn toggleMute() void {
    switch (active_backend) {
        .hda => hda.setVolume(0),
        .ac97 => ac97.toggleMute(),
        .none => {},
    }
}

pub fn isMuted() bool {
    return switch (active_backend) {
        .hda => false,
        .ac97 => ac97.isMuted(),
        .none => true,
    };
}

// =============================================================================
// Sample Rate
// =============================================================================

pub fn setSampleRate(rate: u16) void {
    switch (active_backend) {
        .hda => hda.setSampleRate(rate),
        .ac97 => ac97.setSampleRate(rate),
        .none => {},
    }
}

pub fn getSampleRate() u16 {
    return switch (active_backend) {
        .hda => 48000,
        .ac97 => ac97.getSampleRate(),
        .none => 0,
    };
}

// =============================================================================
// Polling
// =============================================================================

/// Shell idle loop (secondary)
pub fn poll() void {
    switch (active_backend) {
        .hda => {
            if (hda.needsPoll()) {
                hda.poll();
                shell_poll_count += 1;
            }
        },
        .ac97 => {
            if (ac97.needsPoll()) {
                ac97.poll();
                shell_poll_count += 1;
            }
        },
        .none => {},
    }
}

pub fn needsPoll() bool {
    return switch (active_backend) {
        .hda => hda.needsPoll(),
        .ac97 => ac97.needsPoll(),
        .none => false,
    };
}

/// APIC Timer poll (primary, called from smp.handleApicTimer every 2 ticks)
pub fn timerPoll() void {
    switch (active_backend) {
        .hda => {
            if (hda.needsPoll()) {
                hda.poll();
                timer_poll_count += 1;
            }
        },
        .ac97 => {
            if (ac97.needsPoll()) {
                ac97.poll();
                timer_poll_count += 1;
            }
        },
        .none => {},
    }
}

pub fn getTimerPollCount() u64 {
    return timer_poll_count;
}
pub fn getShellPollCount() u64 {
    return shell_poll_count;
}

pub fn resetPollStats() void {
    timer_poll_count = 0;
    shell_poll_count = 0;
    switch (active_backend) {
        .hda => hda.resetPollStats(),
        .ac97 => ac97.resetPollStats(),
        .none => {},
    }
}

// =============================================================================
// Interrupt Handler
// =============================================================================

pub fn handleInterrupt() void {
    switch (active_backend) {
        .hda => hda.handleInterrupt(),
        .ac97 => ac97.handleInterrupt(),
        .none => {},
    }
}

// =============================================================================
// Status
// =============================================================================

pub fn getStatus() AudioStatus {
    return switch (active_backend) {
        .hda => blk: {
            const st = hda.getStats();
            break :blk AudioStatus{
                .backend = .hda,
                .initialized = hda.isInitialized(),
                .codec_ready = hda.isInitialized(),
                .dma_ready = hda.isDmaReady(),
                .playing = hda.isPlaying(),
                .sample_rate = 48000,
                .channels = 2,
                .bits_per_sample = 16,
                .volume_percent = getVolumePercent(),
                .muted = false,
                .variable_rate = false,
                .nam_base = 0,
                .nabm_base = 0,
                .mmio_base = hda.getMmioBase(),
                .dac_nid = hda.getDacNid(),
                .pin_nid = hda.getPinNid(),
                .irq = hda.getIrq(),
                .codec_vendor = hda.getCodecVendor(),
                .buffers_played = st.buffers_played,
                .bytes_played = st.bytes_played,
                .underruns = st.underruns,
                .interrupts = st.interrupts,
                .timer_polls = timer_poll_count,
                .descriptor_errors = st.descriptor_errors,
                .stream_restarts = st.stream_restarts,
                .rirb_timeouts = st.rirb_timeouts,
            };
        },

        .ac97 => blk: {
            const fmt = ac97.getFormat();
            const st = ac97.getStats();
            break :blk AudioStatus{
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
                .mmio_base = 0,
                .dac_nid = 0,
                .pin_nid = 0,
                .irq = ac97.getIrq(),
                .codec_vendor = ac97.getCodecVendorId(),
                .buffers_played = st.buffers_played,
                .bytes_played = st.bytes_played,
                .underruns = st.underruns,
                .interrupts = st.interrupts,
                .timer_polls = timer_poll_count,
                .descriptor_errors = 0,
                .stream_restarts = 0,
                .rirb_timeouts = 0,
            };
        },

        .none => AudioStatus{
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
            .mmio_base = 0,
            .dac_nid = 0,
            .pin_nid = 0,
            .irq = 0,
            .codec_vendor = 0,
            .buffers_played = 0,
            .bytes_played = 0,
            .underruns = 0,
            .interrupts = 0,
            .timer_polls = 0,
            .descriptor_errors = 0,
            .stream_restarts = 0,
            .rirb_timeouts = 0,
        },
    };
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
        .hda => "Intel HDA",
    };
}

pub fn deinit() void {
    switch (active_backend) {
        .hda => hda.deinit(),
        .ac97 => ac97.deinit(),
        .none => {},
    }
    active_backend = .none;
    audio_initialized = false;
    timer_poll_count = 0;
    shell_poll_count = 0;
}
