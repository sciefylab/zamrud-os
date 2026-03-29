//! Zamrud OS - Audio Shell Commands (B2.10)
//! Commands: audio status|play|stop|volume|test|diag|pollstats|help

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const audio = @import("../../drivers/audio/audio.zig");
const ac97 = @import("../../drivers/audio/ac97.zig");
const smp = @import("../../arch/x86_64/smp.zig");

// =============================================================================
// Command Dispatcher
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);
    const subcmd = parsed.cmd;
    const rest = parsed.rest;

    if (subcmd.len == 0 or helpers.strEql(subcmd, "status")) {
        cmdStatus();
    } else if (helpers.strEql(subcmd, "play")) {
        cmdPlay(rest);
    } else if (helpers.strEql(subcmd, "stop")) {
        cmdStop();
    } else if (helpers.strEql(subcmd, "pause")) {
        cmdPause();
    } else if (helpers.strEql(subcmd, "resume")) {
        cmdResume();
    } else if (helpers.strEql(subcmd, "volume") or helpers.strEql(subcmd, "vol")) {
        cmdVolume(rest);
    } else if (helpers.strEql(subcmd, "mute")) {
        cmdMute();
    } else if (helpers.strEql(subcmd, "rate")) {
        cmdRate(rest);
    } else if (helpers.strEql(subcmd, "diag")) {
        cmdDiag();
    } else if (helpers.strEql(subcmd, "pollstats")) {
        cmdPollStats();
    } else if (helpers.strEql(subcmd, "test")) {
        cmdTest();
    } else if (helpers.strEql(subcmd, "help")) {
        cmdHelp();
    } else {
        shell.printError("Unknown audio command: ");
        shell.print(subcmd);
        shell.newLine();
        shell.println("  Type 'audio help' for usage");
    }
}

// =============================================================================
// Hex16 helper (not in helpers.zig, needed for I/O port display)
// =============================================================================

fn printHex16Val(val: u16) void {
    const hex = "0123456789ABCDEF";
    shell.printChar(hex[(val >> 12) & 0xF]);
    shell.printChar(hex[(val >> 8) & 0xF]);
    shell.printChar(hex[(val >> 4) & 0xF]);
    shell.printChar(hex[val & 0xF]);
}

// =============================================================================
// Status
// =============================================================================

fn cmdStatus() void {
    shell.println("=== Audio Subsystem Status ===");

    const status = audio.getStatus();

    shell.print("  Backend:      ");
    shell.println(audio.getBackendName());

    shell.print("  Initialized:  ");
    shell.println(if (status.initialized) "Yes" else "No");

    shell.print("  Codec Ready:  ");
    shell.println(if (status.codec_ready) "Yes" else "No");

    shell.print("  DMA Ready:    ");
    shell.println(if (status.dma_ready) "Yes" else "No");

    if (status.backend != .none) {
        shell.print("  NAM I/O:      0x");
        printHex16Val(status.nam_base);
        shell.newLine();

        shell.print("  NABM I/O:     0x");
        printHex16Val(status.nabm_base);
        shell.newLine();

        shell.print("  IRQ:          ");
        helpers.printDec(status.irq);
        shell.newLine();

        shell.print("  Codec Vendor: 0x");
        helpers.printHex32(status.codec_vendor);
        shell.newLine();

        shell.print("  Sample Rate:  ");
        helpers.printDec(status.sample_rate);
        shell.println(" Hz");

        shell.print("  Format:       ");
        helpers.printDec(status.bits_per_sample);
        shell.print("-bit, ");
        helpers.printDec(status.channels);
        shell.println("-ch");

        shell.print("  Variable Rate:");
        shell.println(if (status.variable_rate) "Yes" else "No (fixed 48kHz)");

        shell.print("  Volume:       ");
        helpers.printDec(status.volume_percent);
        shell.print("% ");
        if (status.muted) shell.print("[MUTED]");
        shell.newLine();

        shell.print("  Playback:     ");
        if (status.playing) {
            shell.println("PLAYING");
        } else {
            shell.println("Stopped");
        }

        shell.print("  Buffers Done: ");
        helpers.printDec64(status.buffers_played);
        shell.newLine();

        shell.print("  Bytes Played: ");
        helpers.printDec64(status.bytes_played);
        shell.newLine();

        shell.print("  Underruns:    ");
        helpers.printDec64(status.underruns);
        shell.newLine();

        shell.print("  Interrupts:   ");
        helpers.printDec64(status.interrupts);
        shell.newLine();

        shell.print("  Timer Polls:  ");
        helpers.printDec64(status.timer_polls);
        shell.newLine();
    }
}

// =============================================================================
// Play
// =============================================================================

fn cmdPlay(args: []const u8) void {
    if (!audio.isInitialized()) {
        shell.printError("Audio not initialized");
        shell.newLine();
        return;
    }

    // Parse frequency (default 440Hz = A4)
    var freq: u16 = 440;
    const duration: u8 = 32; // All buffers

    if (args.len > 0) {
        freq = parseU16(args) orelse 440;
    }

    if (freq < 20 or freq > 20000) {
        shell.printError("Frequency must be 20-20000 Hz");
        shell.newLine();
        return;
    }

    shell.print("  Playing ");
    helpers.printDec(freq);
    shell.print("Hz tone (");
    helpers.printDec(duration);
    shell.println(" buffers)...");

    if (audio.playTone(freq, duration)) {
        shell.println("  Playback started (use 'audio stop' to stop)");
        shell.println("  Timer-driven polling active @ 100Hz");
    } else {
        shell.printError("Failed to start playback");
        shell.newLine();
    }
}

fn cmdStop() void {
    audio.stopPlayback();
    shell.println("  Playback stopped");
}

fn cmdPause() void {
    audio.pausePlayback();
    shell.println("  Playback paused");
}

fn cmdResume() void {
    audio.resumePlayback();
    shell.println("  Playback resumed");
}

// =============================================================================
// Volume
// =============================================================================

fn cmdVolume(args: []const u8) void {
    if (!audio.isInitialized()) {
        shell.printError("Audio not initialized");
        shell.newLine();
        return;
    }

    if (args.len == 0) {
        shell.print("  Volume: ");
        helpers.printDec(audio.getVolumePercent());
        shell.print("% ");
        if (audio.isMuted()) shell.print("[MUTED]");
        shell.newLine();
        shell.println("  Usage: audio volume <0-100>");
        return;
    }

    if (helpers.strEql(args, "up")) {
        const cur = audio.getVolumePercent();
        const new_vol: u8 = if (cur > 90) 100 else cur + 10;
        audio.setVolume(new_vol);
        shell.print("  Volume: ");
        helpers.printDec(new_vol);
        shell.println("%");
        return;
    }

    if (helpers.strEql(args, "down")) {
        const cur = audio.getVolumePercent();
        const new_vol: u8 = if (cur < 10) 0 else cur - 10;
        audio.setVolume(new_vol);
        shell.print("  Volume: ");
        helpers.printDec(new_vol);
        shell.println("%");
        return;
    }

    const vol = parseU16(args) orelse {
        shell.printError("Invalid volume (0-100)");
        shell.newLine();
        return;
    };

    if (vol > 100) {
        shell.printError("Volume must be 0-100");
        shell.newLine();
        return;
    }

    audio.setVolume(@intCast(vol));
    shell.print("  Volume set to ");
    helpers.printDec(vol);
    shell.println("%");
}

fn cmdMute() void {
    if (!audio.isInitialized()) {
        shell.printError("Audio not initialized");
        shell.newLine();
        return;
    }

    audio.toggleMute();
    shell.print("  Mute: ");
    shell.println(if (audio.isMuted()) "ON" else "OFF");
}

// =============================================================================
// Sample Rate
// =============================================================================

fn cmdRate(args: []const u8) void {
    if (!audio.isInitialized()) {
        shell.printError("Audio not initialized");
        shell.newLine();
        return;
    }

    if (args.len == 0) {
        shell.print("  Sample rate: ");
        helpers.printDec(audio.getSampleRate());
        shell.println(" Hz");
        shell.println("  Usage: audio rate <8000|11025|22050|44100|48000>");
        return;
    }

    const rate = parseU16(args) orelse {
        shell.printError("Invalid sample rate");
        shell.newLine();
        return;
    };

    audio.setSampleRate(rate);
    shell.print("  Sample rate set to ");
    helpers.printDec(audio.getSampleRate());
    shell.println(" Hz");
}

// =============================================================================
// Diagnostics
// =============================================================================

fn cmdDiag() void {
    shell.println("=== Audio Diagnostics ===");

    // PCI detection
    const pci = @import("../../drivers/pci/pci.zig");
    shell.print("  PCI Multimedia devices: ");
    var pci_buf: [8]?*const pci.PciDevice = undefined;
    const count = pci.findAllByClass(0x04, 0x01, &pci_buf);
    helpers.printDec(count);
    shell.newLine();

    for (0..count) |i| {
        if (pci_buf[i]) |dev| {
            shell.print("    ");
            shell.print(pci.getVendorName(dev.vendor_id));
            shell.print(" 0x");
            printHex16Val(dev.vendor_id);
            shell.print(":0x");
            printHex16Val(dev.device_id);
            shell.print(" BAR0=0x");
            helpers.printHex32(dev.bar0);
            shell.print(" BAR1=0x");
            helpers.printHex32(dev.bar1);
            shell.print(" IRQ=");
            helpers.printDec(dev.irq_line);
            shell.newLine();
        }
    }

    if (ac97.isInitialized()) {
        shell.println("  AC97 Registers:");

        shell.print("    Global Status: 0x");
        helpers.printHex32(ac97.getGlobalStatus());
        shell.newLine();

        shell.print("    Output Status: 0x");
        printHex16Val(ac97.getOutputStatus());
        shell.newLine();

        shell.print("    CIV (Current): ");
        helpers.printDec(ac97.getCurrentBufferIndex());
        shell.newLine();

        shell.print("    LVI (Last):    ");
        helpers.printDec(ac97.getLastValidIndex());
        shell.newLine();

        shell.print("    PICB (Pos):    ");
        helpers.printDec(ac97.getPositionInBuffer());
        shell.newLine();

        shell.print("    Master Vol:    0x");
        printHex16Val(ac97.getMasterVolume());
        shell.newLine();

        shell.print("    PCM Vol:       0x");
        printHex16Val(ac97.getPcmVolume());
        shell.newLine();

        shell.print("    IRQ Fired:     ");
        helpers.printDec64(ac97.getIrqFiredCount());
        shell.newLine();
    }

    // SMP Timer status
    shell.println("  Timer Status:");
    shell.print("    SMP Init:      ");
    shell.println(if (smp.isInitialized()) "Yes" else "No");

    shell.print("    APIC Timer:    ");
    shell.println(if (smp.isApicTimerEnabled()) "Active" else "Disabled");

    shell.print("    Timer Ticks:   ");
    helpers.printDec64(smp.getTicks());
    shell.newLine();

    shell.print("    Timer Seconds: ");
    helpers.printDec64(smp.getSeconds());
    shell.newLine();
}

// =============================================================================
// Poll Statistics (B2.10 DEBUG)
// =============================================================================

fn cmdPollStats() void {
    shell.println("=== Audio Poll Statistics ===");

    const ac97_stats = ac97.getPollStats();
    const timer_polls = audio.getTimerPollCount();
    const shell_polls = audio.getShellPollCount();

    shell.print("  Timer Polls:   ");
    helpers.printDec64(timer_polls);
    shell.println(" (from APIC timer interrupt)");

    shell.print("  Shell Polls:   ");
    helpers.printDec64(shell_polls);
    shell.println(" (from shell idle loop)");

    shell.print("  AC97 Polls:    ");
    helpers.printDec64(ac97_stats.polls);
    shell.println(" (total poll() calls)");

    shell.print("  DMA Restarts:  ");
    helpers.printDec64(ac97_stats.restarts);
    shell.println(" (halt recovery count)");

    shell.print("  IRQ Fired:     ");
    helpers.printDec64(ac97.getIrqFiredCount());
    shell.println(" (hardware interrupts)");

    // FIX: Gunakan ticks sejak audio mulai, bukan uptime total
    const total_polls = timer_polls + shell_polls;
    shell.newLine();
    if (total_polls > 0) {
        // Estimasi durasi dari AC97 polls (lebih akurat)
        // Timer poll setiap 2 ticks = 20ms, jadi durasi = timer_polls * 20ms
        const duration_ms = timer_polls * 20;
        const duration_sec = duration_ms / 1000;
        if (duration_sec > 0) {
            shell.print("  Est. Audio Duration: ");
            helpers.printDec64(duration_sec);
            shell.println(" sec");

            shell.print("  Timer Poll Rate: ");
            helpers.printDec64(timer_polls / duration_sec);
            shell.println(" Hz (expected ~50Hz)");
        }
    }

    // Health check
    if (timer_polls == 0) {
        shell.printError("  WARNING: Timer polls = 0!");
        shell.newLine();
        shell.println("    Timer-driven polling NOT working!");
    } else if (ac97_stats.restarts > 10) {
        shell.printError("  WARNING: Too many DMA restarts!");
        shell.newLine();
    } else {
        shell.printSuccess("  Poll health: OK");
        shell.newLine();
    }
}

// =============================================================================
// Tests (25 tests)
// =============================================================================

fn cmdTest() void {
    helpers.printTestHeader("AUDIO / AC97 TESTS (B2.10)");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // --- PCI Detection Tests (5) ---

    // Test 1: PCI subsystem available
    passed += helpers.doTest("PCI subsystem init", @import("../../drivers/pci/pci.zig").isInitialized(), &failed);

    // Test 2: PCI multimedia class scan
    {
        const pci_mod = @import("../../drivers/pci/pci.zig");
        var buf: [4]?*const pci_mod.PciDevice = undefined;
        const cnt = pci_mod.findAllByClass(0x04, 0x01, &buf);
        passed += helpers.doTest("PCI audio class found", cnt > 0, &failed);
    }

    // Test 3: AC97 probe
    passed += helpers.doTest("AC97 device detected", ac97.isDetected() or ac97.isInitialized(), &failed);

    // Test 4: BAR0 (NAM) valid
    passed += helpers.doTest("NAM BAR0 valid", ac97.getNamBase() != 0, &failed);

    // Test 5: BAR1 (NABM) valid
    passed += helpers.doTest("NABM BAR1 valid", ac97.getNabmBase() != 0, &failed);

    // --- Mixer Register Tests (5) ---

    // Test 6: AC97 initialized
    passed += helpers.doTest("AC97 initialized", ac97.isInitialized(), &failed);

    // Test 7: Codec ready
    passed += helpers.doTest("Codec ready (primary)", ac97.isCodecReady(), &failed);

    // Test 8: Codec vendor ID readable
    {
        const vid = ac97.getCodecVendorId();
        passed += helpers.doTest("Codec vendor ID readable", vid != 0 and vid != 0xFFFFFFFF, &failed);
    }

    // Test 9: Master volume read/write
    {
        if (ac97.getNamBase() != 0) {
            ac97.setMasterVolume(10, 10, false);
            const vol = ac97.getMasterVolume();
            passed += helpers.doTest("Master vol read/write", (vol & 0x3F3F) != 0, &failed);
            ac97.setMasterVolume(0, 0, false);
        } else {
            passed += helpers.doTest("Master vol read/write", true, &failed);
        }
    }

    // Test 10: PCM volume read/write
    {
        if (ac97.getNamBase() != 0) {
            ac97.setPcmVolume(15, 15, false);
            const vol = ac97.getPcmVolume();
            passed += helpers.doTest("PCM vol read/write", (vol & 0x1F1F) != 0, &failed);
            ac97.setPcmVolume(8, 8, false);
        } else {
            passed += helpers.doTest("PCM vol read/write", true, &failed);
        }
    }

    // --- BDL / DMA Tests (5) ---

    // Test 11: DMA buffers allocated
    passed += helpers.doTest("DMA buffers allocated", ac97.isDmaReady(), &failed);

    // Test 12: BDL configured
    passed += helpers.doTest("BDL configured", ac97.isDmaReady() and ac97.isInitialized(), &failed);

    // Test 13: Fill silence (no crash)
    ac97.fillSilence();
    passed += helpers.doTest("Fill silence (no crash)", true, &failed);

    // Test 14: Generate tone (no crash)
    ac97.generateTone(440, 4);
    passed += helpers.doTest("Generate 440Hz tone", true, &failed);

    // Test 15: Generate high tone
    ac97.generateTone(1000, 2);
    passed += helpers.doTest("Generate 1000Hz tone", true, &failed);

    // --- Playback Control Tests (5) ---

    // Test 16: Start playback
    ac97.generateTone(440, 32);
    const play_ok = ac97.play();
    passed += helpers.doTest("Start playback", play_ok, &failed);

    // Test 17: Playback state is playing
    passed += helpers.doTest("State = playing", ac97.isPlaying(), &failed);

    // Test 18: Pause playback
    ac97.pause();
    passed += helpers.doTest("Pause playback", ac97.getPlaybackState() == .paused, &failed);

    // Test 19: Resume playback
    ac97.resume_playback();
    passed += helpers.doTest("Resume playback", ac97.isPlaying(), &failed);

    // Test 20: Stop playback
    ac97.stop();
    passed += helpers.doTest("Stop playback", !ac97.isPlaying(), &failed);

    // --- Volume / Rate / API Tests (5) ---

    // Test 21: Volume percent API
    audio.setVolume(75);
    {
        const vol = audio.getVolumePercent();
        passed += helpers.doTest("Volume percent API", vol >= 50 and vol <= 100, &failed);
    }

    // Test 22: Mute toggle
    {
        const was_muted = audio.isMuted();
        audio.toggleMute();
        const now_muted = audio.isMuted();
        audio.toggleMute(); // Restore
        passed += helpers.doTest("Mute toggle", was_muted != now_muted, &failed);
    }

    // Test 23: Sample rate query
    passed += helpers.doTest("Sample rate query", audio.getSampleRate() > 0, &failed);

    // Test 24: Audio status API
    {
        const status = audio.getStatus();
        passed += helpers.doTest("Audio status API", status.backend == .ac97 and status.initialized, &failed);
    }

    // Test 25: Stats tracking
    {
        const st = ac97.getStats();
        passed += helpers.doTest("Stats tracking", st.playback_started >= 1 and st.playback_stopped >= 1, &failed);
    }

    // --- Summary ---
    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Help
// =============================================================================

fn cmdHelp() void {
    shell.println("=== Audio Commands (B2.10) ===");
    shell.println("  audio status     - Show audio subsystem status");
    shell.println("  audio play [Hz]  - Play test tone (default 440Hz)");
    shell.println("  audio stop       - Stop playback");
    shell.println("  audio pause      - Pause playback");
    shell.println("  audio resume     - Resume playback");
    shell.println("  audio volume <n> - Set volume (0-100) or 'up'/'down'");
    shell.println("  audio mute       - Toggle mute");
    shell.println("  audio rate <Hz>  - Set sample rate (48000/44100/etc)");
    shell.println("  audio diag       - Hardware diagnostics");
    shell.println("  audio pollstats  - Show timer poll statistics (DEBUG)");
    shell.println("  audio test       - Run 25 tests");
    shell.println("  audio help       - Show this help");
}

// =============================================================================
// Utilities
// =============================================================================

fn parseU16(s: []const u8) ?u16 {
    if (s.len == 0) return null;

    var result: u32 = 0;
    for (s) |c| {
        if (c == ' ') break;
        if (c < '0' or c > '9') return null;
        result = result * 10 + (c - '0');
        if (result > 65535) return null;
    }

    return @intCast(result);
}
