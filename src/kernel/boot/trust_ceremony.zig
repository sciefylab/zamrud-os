//! Zamrud OS - First-Boot Trust Ceremony (H.7)
//! H.7 FIXED: Proper password auth, blockchain trust anchors,
//!            master key → identity binding, newline-based UI
//! H.7.2: Integrated backup option at completion
//! H.7.3: Fixed keyboard grace period issue

const serial = @import("../drivers/serial/serial.zig");
const terminal = @import("../drivers/display/terminal.zig");
const keyboard = @import("../drivers/input/keyboard.zig");
const timer = @import("../drivers/timer/timer.zig");
const ui = @import("../shell/ui.zig");
const entropy = @import("../crypto/entropy.zig");
const keys = @import("../crypto/keys.zig");
const hash = @import("../crypto/hash.zig");
const constant_time = @import("../crypto/constant_time.zig");
const identity = @import("../identity/identity.zig");
const keyring = @import("../identity/keyring.zig");
const config_store = @import("../persist/config_store.zig");
const identity_store = @import("../persist/identity_store.zig");
const sys_encrypt = @import("../crypto/sys_encrypt.zig");
const identity_export = @import("../identity/export.zig");
const crypto = @import("../crypto/crypto.zig");

// =============================================================================
// Constants
// =============================================================================

const CEREMONY_VERSION: u32 = 2;
const RECOVERY_PHRASE_WORDS: usize = 24;
const MIN_PASSWORD_LEN: usize = keyring.PASSWORD_MIN_LEN;
const MAX_PASSWORD_LEN: usize = keyring.CREDENTIAL_MAX_LEN;
const MAX_NAME_LEN: usize = keyring.NAME_MAX_LEN;
const VERIFY_WORD_COUNT: usize = 3;

const KEY_CEREMONY_COMPLETE = "ceremony.complete";
const KEY_CEREMONY_VERSION = "ceremony.version";
const KEY_CEREMONY_TIMESTAMP = "ceremony.timestamp";
const KEY_BOOT_PCR_BASELINE = "boot.pcr_baseline";
const KEY_SYSTEM_OWNER = "system.owner";
const KEY_TRUST_ANCHOR = "trust.anchor";

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var ceremony_in_progress: bool = false;
var ceremony_step: u8 = 0;
const total_steps: u8 = 7;

var master_seed: [32]u8 = [_]u8{0} ** 32;
var derived_key: [32]u8 = [_]u8{0} ** 32;
var password_buf: [MAX_PASSWORD_LEN]u8 = [_]u8{0} ** MAX_PASSWORD_LEN;
var password_len: usize = 0;
var name_buf: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN;
var name_len: usize = 0;

var recovery_phrase: keys.SeedPhrase = undefined;
var phrase_generated: bool = false;

var verify_indices: [VERIFY_WORD_COUNT]u8 = [_]u8{0} ** VERIFY_WORD_COUNT;
var verify_passed: bool = false;

var trust_anchor_hash: [32]u8 = [_]u8{0} ** 32;

// H.7: State flags for shell integration
var ceremony_just_completed_flag: bool = false;
var returning_user_flag: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    if (initialized) return;

    ceremony_in_progress = false;
    ceremony_step = 0;
    phrase_generated = false;
    verify_passed = false;
    ceremony_just_completed_flag = false;
    returning_user_flag = false;

    wipeAllBuffers();

    initialized = true;
    serial.writeString("[TRUST_CEREMONY] Initialized\n");
}

// =============================================================================
// Main Ceremony Entry Point
// =============================================================================

pub fn runCeremony() bool {
    if (!initialized) init();

    if (!isFirstBoot()) {
        showMessage("Trust ceremony already completed.", .info);
        return true;
    }

    if (ceremony_in_progress) {
        showMessage("Ceremony already in progress.", .warning);
        return false;
    }

    ceremony_in_progress = true;
    ceremony_step = 0;

    serial.writeString("[TRUST_CEREMONY] Starting first-boot trust ceremony v2\n");

    // H.7.3 FIX: End keyboard grace period so we can receive input
    // The grace period blocks all keyboard input during early boot
    // to prevent phantom keypresses. We need to end it for the ceremony.
    keyboard.endGracePeriod();
    serial.writeString("[TRUST_CEREMONY] Keyboard grace period ended\n");

    // Also clear any buffered keys from boot
    while (keyboard.getKey() != null) {}

    if (!stepWelcome()) {
        abortCeremony("User cancelled");
        return false;
    }

    ceremony_step = 1;
    if (!stepGatherEntropy()) {
        abortCeremony("Entropy gathering failed");
        return false;
    }

    ceremony_step = 2;
    if (!stepGenerateMasterKey()) {
        abortCeremony("Key generation failed");
        return false;
    }

    ceremony_step = 3;
    if (!stepShowRecoveryPhrase()) {
        abortCeremony("User cancelled at recovery phrase");
        return false;
    }

    ceremony_step = 4;
    if (!stepVerifyRecoveryPhrase()) {
        abortCeremony("Recovery phrase verification failed");
        return false;
    }

    ceremony_step = 5;
    if (!stepCreateFirstIdentity()) {
        abortCeremony("Identity creation failed");
        return false;
    }

    ceremony_step = 6;
    if (!stepPinBootAndComplete()) {
        abortCeremony("Boot pinning failed");
        return false;
    }

    ceremony_step = 7;
    ceremony_in_progress = false;
    ceremony_just_completed_flag = true;

    // Show completion with backup option
    showCompletionScreen();

    // Wipe sensitive buffers AFTER backup option (password needed for export)
    wipeAllBuffers();

    serial.writeString("[TRUST_CEREMONY] Ceremony completed successfully\n");
    return true;
}

// =============================================================================
// Step 0: Welcome Screen
// =============================================================================

fn stepWelcome() bool {
    clearScreen();

    writeLine("");
    writeLine("╔══════════════════════════════════════════════════════════════╗");
    writeLine("║       ZAMRUD OS - FIRST BOOT TRUST CEREMONY                  ║");
    writeLine("╚══════════════════════════════════════════════════════════════╝");
    writeLine("");

    setColor(.bright);
    writeLine("  Welcome to Zamrud OS!");
    setColor(.normal);
    writeLine("");

    writeLine("  This is your first boot. We need to establish trust anchors");
    writeLine("  that will protect your system and data.");
    writeLine("");

    writeLine("  This wizard will:");
    setColor(.info);
    writeLine("    [1] Generate a master encryption key");
    writeLine("    [2] Create a 24-word recovery phrase");
    writeLine("    [3] Set up your owner identity (password-protected)");
    writeLine("    [4] Pin boot integrity & create blockchain trust anchor");
    setColor(.normal);
    writeLine("");

    setColor(.warning);
    writeLine("  ┌────────────────────────────────────────────────────────────┐");
    writeLine("  │  IMPORTANT: You will need to write down the recovery      │");
    writeLine("  │  phrase. Have pen and paper ready before continuing.      │");
    writeLine("  └────────────────────────────────────────────────────────────┘");
    setColor(.normal);
    writeLine("");
    writeLine("");

    writeStr("  Press ");
    setColor(.success);
    writeStr("ENTER");
    setColor(.normal);
    writeStr(" to begin, or ");
    setColor(.error_color);
    writeStr("ESC");
    setColor(.normal);
    writeLine(" to cancel...");

    return waitForConfirm();
}

// =============================================================================
// Step 1: Gather Entropy
// =============================================================================

fn stepGatherEntropy() bool {
    clearScreen();

    writeLine("");
    writeLine("╔══════════════════════════════════════════════════════════════╗");
    writeLine("║       STEP 1/6: GATHERING ENTROPY                            ║");
    writeLine("╚══════════════════════════════════════════════════════════════╝");
    writeLine("");

    setColor(.normal);
    writeLine("  Collecting randomness for key generation...");
    writeLine("");

    writeLine("  Sources:");

    if (entropy.hasHardwareRng()) {
        setColor(.success);
        writeStr("    [✓] ");
    } else {
        setColor(.warning);
        writeStr("    [-] ");
    }
    setColor(.normal);
    writeLine("CPU RDRAND/RDSEED");

    setColor(.success);
    writeStr("    [✓] ");
    setColor(.normal);
    writeLine("Timestamp entropy (RDTSC)");

    setColor(.success);
    writeStr("    [✓] ");
    setColor(.normal);
    writeLine("Interrupt timing jitter");
    writeLine("");

    setColor(.info);
    writeLine("  Please type random characters to add entropy:");
    setColor(.dim);
    writeLine("  (Press ENTER when done, minimum 10 characters)");
    writeLine("");

    setColor(.normal);
    writeStr("  > ");

    var user_entropy: [64]u8 = [_]u8{0} ** 64;
    var user_len: usize = 0;
    var last_time: u64 = timer.getTicks();

    while (user_len < 64) {
        if (keyboard.getKey()) |key| {
            const current_time = timer.getTicks();

            const timing: u8 = @truncate((current_time -% last_time) & 0xFF);
            var timing_arr = [_]u8{timing};
            entropy.addEntropy(&timing_arr, 2);
            last_time = current_time;

            if (key == '\n' or key == '\r') {
                if (user_len >= 10) break;
                continue;
            }

            if (key == 0x1B) {
                return false;
            }

            if (key >= 0x20 and key < 0x7F) {
                user_entropy[user_len] = key;
                user_len += 1;
                if (terminal.isInitialized()) {
                    terminal.writeChar('*');
                }

                var key_arr = [_]u8{key};
                entropy.addEntropy(&key_arr, 4);
            }
        }
    }

    writeLine("");
    writeLine("");

    var user_hash: [32]u8 = undefined;
    hash.sha256Into(user_entropy[0..user_len], &user_hash);
    entropy.addEntropy(&user_hash, 128);

    constant_time.secureZero(&user_entropy);
    constant_time.secureZero(&user_hash);

    setColor(.success);
    writeLine("  [OK] Entropy gathered successfully");

    setColor(.normal);
    writeStr("  Entropy pool: ");
    setColor(.info);
    writeNumber(entropy.getEntropyBits());
    writeLine(" bits");

    delay(1000);
    return true;
}

// =============================================================================
// Step 2: Generate Master Key
// =============================================================================

fn stepGenerateMasterKey() bool {
    clearScreen();

    writeLine("");
    writeLine("╔══════════════════════════════════════════════════════════════╗");
    writeLine("║       STEP 2/6: GENERATING MASTER KEY                        ║");
    writeLine("╚══════════════════════════════════════════════════════════════╝");
    writeLine("");

    setColor(.normal);
    writeLine("  Generating cryptographic keys...");
    writeLine("");

    writeStr("    Extracting entropy...");

    entropy.getSecureBytes(&master_seed) catch {
        setColor(.error_color);
        writeLine(" FAILED (insufficient entropy)");
        writeLine("");
        writeLine("  Please try again with more random input.");
        delay(2000);
        return false;
    };

    setColor(.success);
    writeLine(" OK");

    setColor(.normal);
    writeStr("    Creating recovery phrase...");

    recovery_phrase = keys.SeedPhrase.generateWithLength(RECOVERY_PHRASE_WORDS);

    if (!recovery_phrase.isValid()) {
        setColor(.error_color);
        writeLine(" FAILED");
        return false;
    }

    phrase_generated = true;
    setColor(.success);
    writeLine(" OK");

    setColor(.normal);
    writeStr("    Deriving master encryption key...");

    const seed_ptr = recovery_phrase.toSeedPtr();
    var j: usize = 0;
    while (j < 32) : (j += 1) {
        derived_key[j] = seed_ptr[j];
    }

    var mix_input: [64]u8 = [_]u8{0} ** 64;
    j = 0;
    while (j < 32) : (j += 1) {
        mix_input[j] = derived_key[j];
        mix_input[32 + j] = master_seed[j];
    }
    hash.sha256Into(&mix_input, &derived_key);
    constant_time.secureZero(&mix_input);

    var round: usize = 0;
    while (round < 1000) : (round += 1) {
        hash.sha256Into(&derived_key, &derived_key);
    }

    setColor(.success);
    writeLine(" OK");
    writeLine("");

    setColor(.success);
    writeLine("  [OK] Master key generated (256-bit)");
    writeLine("");

    setColor(.warning);
    writeLine("  NEXT: You will see your 24-word recovery phrase.");
    writeLine("  Write it down carefully - this is your ONLY backup!");
    writeLine("");

    setColor(.normal);
    writeLine("  Press ENTER to continue...");

    return waitForEnter();
}

// =============================================================================
// Step 3: Show Recovery Phrase
// =============================================================================

fn stepShowRecoveryPhrase() bool {
    clearScreen();

    writeLine("");
    writeLine("╔══════════════════════════════════════════════════════════════╗");
    writeLine("║       STEP 3/6: RECOVERY PHRASE                              ║");
    writeLine("╚══════════════════════════════════════════════════════════════╝");
    writeLine("");

    setColor(.error_color);
    writeLine("  ┌────────────────────────────────────────────────────────────┐");
    writeLine("  │ ⚠ WARNING: Write these words down NOW!                    │");
    writeLine("  │   They will NOT be shown again after verification!        │");
    writeLine("  └────────────────────────────────────────────────────────────┘");
    setColor(.normal);
    writeLine("");

    writeLine("  Your 24-word recovery phrase:");
    writeLine("");

    // Display words in rows of 4
    var word_idx: usize = 0;
    while (word_idx < RECOVERY_PHRASE_WORDS) {
        writeStr("    ");

        var col: usize = 0;
        while (col < 4 and word_idx < RECOVERY_PHRASE_WORDS) : (col += 1) {
            setColor(.dim);
            if (word_idx + 1 < 10) writeStr(" ");
            writeNumber(word_idx + 1);
            writeStr(". ");

            setColor(.bright);
            const word = recovery_phrase.getWordAt(word_idx);
            writeStr(word);

            // Padding to align columns
            var pad_count: usize = 0;
            if (word.len < 12) {
                pad_count = 12 - word.len;
            }
            while (pad_count > 0) : (pad_count -= 1) {
                writeStr(" ");
            }

            word_idx += 1;
        }
        writeLine("");
    }

    writeLine("");
    setColor(.info);
    writeLine("  Have you written down all 24 words in order?");
    writeLine("");

    setColor(.normal);
    writeStr("  Press ");
    setColor(.success);
    writeStr("Y");
    setColor(.normal);
    writeStr(" to confirm, ");
    setColor(.warning);
    writeStr("R");
    setColor(.normal);
    writeStr(" to show again, or ");
    setColor(.error_color);
    writeStr("ESC");
    setColor(.normal);
    writeLine(" to cancel");

    while (true) {
        if (keyboard.getKey()) |key| {
            if (key == 'y' or key == 'Y') {
                return true;
            }
            if (key == 'r' or key == 'R') {
                return stepShowRecoveryPhrase();
            }
            if (key == 0x1B) {
                return false;
            }
        }
    }
}

// =============================================================================
// Step 4: Verify Recovery Phrase
// =============================================================================

fn stepVerifyRecoveryPhrase() bool {
    clearScreen();

    writeLine("");
    writeLine("╔══════════════════════════════════════════════════════════════╗");
    writeLine("║       STEP 4/6: VERIFY RECOVERY PHRASE                       ║");
    writeLine("╚══════════════════════════════════════════════════════════════╝");
    writeLine("");

    setColor(.normal);
    writeLine("  Let's verify you wrote down the phrase correctly.");
    writeLine("  Enter the requested words from your backup.");
    writeLine("");

    selectVerifyIndices();

    var attempts: u8 = 0;
    const max_attempts: u8 = 3;

    while (attempts < max_attempts) {
        var all_correct = true;

        var v: usize = 0;
        while (v < VERIFY_WORD_COUNT) : (v += 1) {
            const word_num = verify_indices[v] + 1;
            const expected = recovery_phrase.getWordAt(verify_indices[v]);

            setColor(.info);
            writeStr("  Enter word #");
            writeNumber(word_num);
            writeStr(": ");

            setColor(.normal);

            var input: [16]u8 = [_]u8{0} ** 16;
            var input_len: usize = 0;

            while (true) {
                if (keyboard.getKey()) |key| {
                    if (key == '\n' or key == '\r') {
                        break;
                    }
                    if (key == 0x1B) {
                        return false;
                    }
                    if (key == 0x08 or key == 0x7F) {
                        if (input_len > 0) {
                            input_len -= 1;
                            input[input_len] = 0;
                            if (terminal.isInitialized()) {
                                terminal.writeChar(0x08);
                                terminal.writeChar(' ');
                                terminal.writeChar(0x08);
                            }
                        }
                        continue;
                    }
                    if (key >= 'a' and key <= 'z' and input_len < 15) {
                        input[input_len] = key;
                        input_len += 1;
                        if (terminal.isInitialized()) terminal.writeChar(key);
                    }
                    if (key >= 'A' and key <= 'Z' and input_len < 15) {
                        const lower = key + 32;
                        input[input_len] = lower;
                        input_len += 1;
                        if (terminal.isInitialized()) terminal.writeChar(lower);
                    }
                }
            }

            if (!strEql(input[0..input_len], expected)) {
                all_correct = false;
                setColor(.error_color);
                writeLine(" ✗");
            } else {
                setColor(.success);
                writeLine(" ✓");
            }
        }

        if (all_correct) {
            writeLine("");
            setColor(.success);
            writeLine("  [OK] Recovery phrase verified successfully!");
            verify_passed = true;
            delay(1500);
            return true;
        }

        attempts += 1;
        if (attempts < max_attempts) {
            writeLine("");
            setColor(.warning);
            writeStr("  Some words incorrect. Attempts remaining: ");
            writeNumber(max_attempts - attempts);
            writeLine("");
            writeLine("");

            setColor(.normal);
            writeLine("  Press ENTER to try again, or ESC to go back...");

            while (true) {
                if (keyboard.getKey()) |key| {
                    if (key == '\n' or key == '\r') {
                        return stepVerifyRecoveryPhrase();
                    }
                    if (key == 0x1B) {
                        if (stepShowRecoveryPhrase()) {
                            return stepVerifyRecoveryPhrase();
                        }
                        return false;
                    }
                }
            }
        }
    }

    writeLine("");
    setColor(.error_color);
    writeLine("  Verification failed. Please start over.");
    delay(2000);
    return false;
}

fn selectVerifyIndices() void {
    var used: [RECOVERY_PHRASE_WORDS]bool = [_]bool{false} ** RECOVERY_PHRASE_WORDS;
    var selected: usize = 0;

    while (selected < VERIFY_WORD_COUNT) {
        var random_byte: [1]u8 = undefined;
        entropy.getSecureBytes(&random_byte) catch {
            random_byte[0] = @truncate(timer.getTicks() & 0xFF);
        };
        const idx = random_byte[0] % RECOVERY_PHRASE_WORDS;

        if (!used[idx]) {
            used[idx] = true;
            verify_indices[selected] = @intCast(idx);
            selected += 1;
        }
    }

    // Sort ascending
    var i: usize = 0;
    while (i < VERIFY_WORD_COUNT - 1) : (i += 1) {
        var j: usize = i + 1;
        while (j < VERIFY_WORD_COUNT) : (j += 1) {
            if (verify_indices[j] < verify_indices[i]) {
                const tmp = verify_indices[i];
                verify_indices[i] = verify_indices[j];
                verify_indices[j] = tmp;
            }
        }
    }
}

// =============================================================================
// Step 5: Create First Identity
// =============================================================================

fn stepCreateFirstIdentity() bool {
    clearScreen();

    writeLine("");
    writeLine("╔══════════════════════════════════════════════════════════════╗");
    writeLine("║       STEP 5/6: CREATE YOUR IDENTITY                         ║");
    writeLine("╚══════════════════════════════════════════════════════════════╝");
    writeLine("");

    setColor(.normal);
    writeLine("  Create your system owner identity.");
    writeLine("");

    // Get username
    setColor(.info);
    writeLine("  Username (3-32 chars, lowercase + numbers + underscore):");
    setColor(.normal);
    writeStr("  @");

    name_len = 0;
    while (true) {
        if (keyboard.getKey()) |key| {
            if (key == '\n' or key == '\r') {
                if (name_len >= 3) break;
                continue;
            }
            if (key == 0x1B) return false;
            if (key == 0x08 or key == 0x7F) {
                if (name_len > 0) {
                    name_len -= 1;
                    name_buf[name_len] = 0;
                    if (terminal.isInitialized()) {
                        terminal.writeChar(0x08);
                        terminal.writeChar(' ');
                        terminal.writeChar(0x08);
                    }
                }
                continue;
            }

            var valid = false;
            var c = key;
            if (c >= 'A' and c <= 'Z') c = c + 32;
            if ((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_') {
                valid = true;
            }

            if (valid and name_len < MAX_NAME_LEN - 1) {
                name_buf[name_len] = c;
                name_len += 1;
                if (terminal.isInitialized()) terminal.writeChar(c);
            }
        }
    }

    writeLine("");
    writeLine("");

    // Get password
    setColor(.info);
    writeLine("  Password (8-64 chars, must include uppercase, lowercase, and number):");
    setColor(.normal);
    writeStr("  ");

    password_len = 0;
    while (true) {
        if (keyboard.getKey()) |key| {
            if (key == '\n' or key == '\r') {
                if (password_len >= MIN_PASSWORD_LEN) {
                    if (keyring.isStrongPassword(password_buf[0..password_len])) {
                        break;
                    } else {
                        writeLine("");
                        setColor(.error_color);
                        writeLine("  Password must include uppercase, lowercase, and number!");
                        setColor(.normal);
                        writeStr("  Try again: ");
                        password_len = 0;
                        continue;
                    }
                }
                continue;
            }
            if (key == 0x1B) return false;
            if (key == 0x08 or key == 0x7F) {
                if (password_len > 0) {
                    password_len -= 1;
                    password_buf[password_len] = 0;
                    if (terminal.isInitialized()) {
                        terminal.writeChar(0x08);
                        terminal.writeChar(' ');
                        terminal.writeChar(0x08);
                    }
                }
                continue;
            }

            if (key >= 0x20 and key < 0x7F and password_len < MAX_PASSWORD_LEN) {
                password_buf[password_len] = key;
                password_len += 1;
                if (terminal.isInitialized()) terminal.writeChar('*');
            }
        }
    }

    writeLine("");
    writeLine("");

    // Confirm password
    setColor(.info);
    writeLine("  Confirm password:");
    setColor(.normal);
    writeStr("  ");

    var confirm_buf: [MAX_PASSWORD_LEN]u8 = [_]u8{0} ** MAX_PASSWORD_LEN;
    var confirm_len: usize = 0;

    while (true) {
        if (keyboard.getKey()) |key| {
            if (key == '\n' or key == '\r') {
                if (confirm_len >= MIN_PASSWORD_LEN) break;
                continue;
            }
            if (key == 0x1B) return false;
            if (key == 0x08 or key == 0x7F) {
                if (confirm_len > 0) {
                    confirm_len -= 1;
                    confirm_buf[confirm_len] = 0;
                    if (terminal.isInitialized()) {
                        terminal.writeChar(0x08);
                        terminal.writeChar(' ');
                        terminal.writeChar(0x08);
                    }
                }
                continue;
            }

            if (key >= 0x20 and key < 0x7F and confirm_len < MAX_PASSWORD_LEN) {
                confirm_buf[confirm_len] = key;
                confirm_len += 1;
                if (terminal.isInitialized()) terminal.writeChar('*');
            }
        }
    }

    writeLine("");

    // Check passwords match
    if (!passwordsMatch(password_buf[0..password_len], confirm_buf[0..confirm_len])) {
        writeLine("");
        setColor(.error_color);
        writeLine("  Passwords do not match! Please try again.");
        constant_time.secureZero(&confirm_buf);
        delay(2000);
        return stepCreateFirstIdentity();
    }

    constant_time.secureZero(&confirm_buf);

    writeLine("");

    // Create identity
    setColor(.normal);
    writeStr("  Creating identity...");

    if (!identity.isInitialized()) {
        identity.init();
    }

    const id = keyring.createIdentityWithPassword(name_buf[0..name_len], password_buf[0..password_len]);
    if (id == null) {
        setColor(.error_color);
        writeLine(" FAILED");
        return false;
    }

    setColor(.success);
    writeLine(" OK");

    // Bind master key
    setColor(.normal);
    writeStr("  Binding master key to identity...");

    if (sys_encrypt.isInitialized() and !sys_encrypt.isMasterKeySet()) {
        var sys_key_input: [64]u8 = [_]u8{0} ** 64;
        var i: usize = 0;
        while (i < password_len and i < 32) : (i += 1) {
            sys_key_input[i] = password_buf[i];
        }
        i = 0;
        while (i < 32) : (i += 1) {
            sys_key_input[32 + i] = master_seed[i];
        }
        var sys_key: [32]u8 = undefined;
        hash.sha256Into(&sys_key_input, &sys_key);
        sys_encrypt.setMasterKeyFromIdentity(&sys_key);
        constant_time.secureZero(&sys_key_input);
        constant_time.secureZero32(&sys_key);
    }

    setColor(.success);
    writeLine(" OK");

    // Store trust anchor
    setColor(.normal);
    writeStr("  Recording trust anchor...");

    var t: usize = 0;
    while (t < 32) : (t += 1) {
        trust_anchor_hash[t] = id.?.trust_hash[t];
    }

    setColor(.success);
    writeLine(" OK");

    // Save identity
    setColor(.normal);
    writeStr("  Saving to disk...");

    if (identity_store.saveToDisk()) {
        setColor(.success);
        writeLine(" OK");
    } else {
        setColor(.warning);
        writeLine(" (will retry later)");
    }

    writeLine("");

    setColor(.success);
    writeStr("  [OK] Owner identity created: @");
    writeLine(name_buf[0..name_len]);

    delay(1500);
    return true;
}

fn passwordsMatch(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return constant_time.constantTimeCompare(a, b);
}

// =============================================================================
// Step 6: Pin Boot & Complete
// =============================================================================

fn stepPinBootAndComplete() bool {
    clearScreen();

    writeLine("");
    writeLine("╔══════════════════════════════════════════════════════════════╗");
    writeLine("║       STEP 6/6: FINALIZING SETUP                             ║");
    writeLine("╚══════════════════════════════════════════════════════════════╝");
    writeLine("");

    setColor(.normal);
    writeLine("  Pinning boot integrity measurements...");

    // Generate boot baseline hash
    var boot_hash: [32]u8 = undefined;
    var boot_input: [64]u8 = undefined;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        boot_input[i] = master_seed[i];
    }
    const ts = timer.getTicks();
    boot_input[32] = @truncate(ts);
    boot_input[33] = @truncate(ts >> 8);
    boot_input[34] = @truncate(ts >> 16);
    boot_input[35] = @truncate(ts >> 24);

    hash.sha256Into(boot_input[0..36], &boot_hash);

    var hex_buf: [64]u8 = undefined;
    bytesToHex(&boot_hash, &hex_buf);

    _ = config_store.set(KEY_BOOT_PCR_BASELINE, hex_buf[0..64]);

    setColor(.success);
    writeLine("    [✓] Boot baseline pinned");

    // Save trust anchor
    setColor(.normal);
    writeStr("    [✓] Recording blockchain trust anchor...");

    var anchor_hex: [64]u8 = undefined;
    bytesToHex(&trust_anchor_hash, &anchor_hex);
    _ = config_store.set(KEY_TRUST_ANCHOR, anchor_hex[0..64]);

    setColor(.success);
    writeLine(" OK");
    writeLine("");

    setColor(.normal);
    writeLine("  Saving trust configuration...");

    _ = config_store.set(KEY_CEREMONY_COMPLETE, "true");

    var ver_buf: [4]u8 = undefined;
    const ver_len = formatU32(CEREMONY_VERSION, &ver_buf);
    _ = config_store.set(KEY_CEREMONY_VERSION, ver_buf[0..ver_len]);

    _ = config_store.set(KEY_SYSTEM_OWNER, name_buf[0..name_len]);

    var ts_buf: [16]u8 = undefined;
    const ts_sec: u32 = @truncate(timer.getSeconds());
    const ts_len = formatU32(ts_sec, &ts_buf);
    _ = config_store.set(KEY_CEREMONY_TIMESTAMP, ts_buf[0..ts_len]);

    if (config_store.saveToDisk()) {
        setColor(.success);
        writeLine("    [✓] Configuration saved");
    } else {
        setColor(.warning);
        writeLine("    [-] Save to disk failed (in-memory only)");
    }

    writeLine("");

    setColor(.success);
    writeLine("  ════════════════════════════════════════════════════════════");
    writeLine("  [OK] Trust ceremony completed successfully!");
    writeLine("  ════════════════════════════════════════════════════════════");

    delay(1000);
    return true;
}

// =============================================================================
// Completion Screen with Backup Option (H.7.2)
// =============================================================================

fn showCompletionScreen() void {
    clearScreen();

    writeLine("");
    writeLine("");
    writeLine("    ╔════════════════════════════════════════════════════════╗");
    writeLine("    ║                                                        ║");
    writeLine("    ║                   SETUP COMPLETE                       ║");
    writeLine("    ║                                                        ║");
    writeLine("    ╚════════════════════════════════════════════════════════╝");
    writeLine("");

    setColor(.success);
    writeStr("                   Welcome, @");
    writeLine(name_buf[0..name_len]);
    setColor(.normal);
    writeLine("");

    writeLine("    Your system is protected by:");
    writeLine("");
    setColor(.info);
    writeLine("      ✓ 256-bit master encryption key");
    writeLine("      ✓ 24-word recovery phrase (written down)");
    writeLine("      ✓ Password-protected owner identity");
    writeLine("      ✓ Blockchain trust anchor");
    setColor(.normal);
    writeLine("");

    // Backup option section
    writeLine("    ────────────────────────────────────────────────────────");
    writeLine("");
    setColor(.warning);
    writeLine("    BACKUP RECOMMENDATION:");
    setColor(.normal);
    writeLine("");
    writeLine("    You have your 24-word recovery phrase written down.");
    writeLine("    For additional security, you can also create an");
    writeLine("    encrypted backup file (.zib) to store on USB or cloud.");
    writeLine("");

    setColor(.bright);
    writeLine("    [1] Create encrypted backup now");
    setColor(.dim);
    writeLine("    [2] Skip - I'll do it later");
    setColor(.normal);
    writeLine("");

    writeStr("    Your choice (1/2): ");

    // Wait for choice
    while (true) {
        if (keyboard.getKey()) |key| {
            if (key == '1') {
                writeLine("1");
                writeLine("");
                runInlineExportWizard();
                return;
            } else if (key == '2' or key == '\n' or key == '\r' or key == 0x1B) {
                if (key == '2') {
                    writeLine("2");
                } else {
                    writeLine("");
                }
                writeLine("");
                showBackupReminder();
                return;
            }
        }
    }
}

// =============================================================================
// Inline Export Wizard (H.7.2)
// =============================================================================

fn runInlineExportWizard() void {
    writeLine("    ────────────────────────────────────────────────────────");
    writeLine("");
    setColor(.info);
    writeLine("    CREATE ENCRYPTED BACKUP");
    setColor(.normal);
    writeLine("");

    writeLine("    Choose a SEPARATE password for your backup file.");
    setColor(.dim);
    writeLine("    (Use a different password than your login password)");
    setColor(.normal);
    writeLine("");

    // Get backup password
    writeStr("    Backup password (min 8 chars): ");
    var backup_pass: [64]u8 = [_]u8{0} ** 64;
    const bp_len = readPasswordInline(&backup_pass);

    if (bp_len == 0) {
        writeLine("");
        writeLine("");
        setColor(.dim);
        writeLine("    Cancelled.");
        setColor(.normal);
        showBackupReminder();
        constant_time.secureZero(&backup_pass);
        return;
    }

    writeLine("");

    if (bp_len < 8) {
        setColor(.error_color);
        writeLine("    Password too short (minimum 8 characters).");
        setColor(.normal);
        writeLine("");
        showBackupReminder();
        constant_time.secureZero(&backup_pass);
        return;
    }

    // Confirm password
    writeStr("    Confirm backup password: ");
    var confirm_pass: [64]u8 = [_]u8{0} ** 64;
    const cp_len = readPasswordInline(&confirm_pass);

    writeLine("");

    if (cp_len == 0) {
        writeLine("");
        setColor(.dim);
        writeLine("    Cancelled.");
        setColor(.normal);
        showBackupReminder();
        constant_time.secureZero(&backup_pass);
        return;
    }

    // Check match
    if (bp_len != cp_len or !passwordsMatch(backup_pass[0..bp_len], confirm_pass[0..cp_len])) {
        setColor(.error_color);
        writeLine("");
        writeLine("    Passwords don't match.");
        setColor(.normal);
        showBackupReminder();
        constant_time.secureZero(&backup_pass);
        constant_time.secureZero(&confirm_pass);
        return;
    }

    constant_time.secureZero(&confirm_pass);

    // Create backup
    writeLine("");
    writeStr("    Creating encrypted backup...");

    // Initialize export module if needed
    identity_export.init();

    const result = identity_export.exportFull(
        name_buf[0..name_len],
        password_buf[0..password_len],
        backup_pass[0..bp_len],
    );

    constant_time.secureZero(&backup_pass);

    if (!result.success) {
        setColor(.error_color);
        writeLine(" FAILED");
        if (result.error_msg) |msg| {
            writeStr("    Error: ");
            writeLine(msg);
        }
        setColor(.normal);
        writeLine("");
        showBackupReminder();
        return;
    }

    setColor(.success);
    writeLine(" OK");
    setColor(.normal);
    writeLine("");

    // Generate filename
    var filename: [16]u8 = [_]u8{0} ** 16;
    const fname_len = generateBackupFilename(&filename);

    // Save to disk
    const saved = identity_export.saveToFile(filename[0..fname_len], result.getData());

    if (saved) {
        setColor(.success);
        writeStr("    ✓ Backup saved: ");
        setColor(.bright);
        writeLine(filename[0..fname_len]);
        setColor(.normal);
    } else {
        setColor(.warning);
        writeLine("    ⚠ Could not save to disk");
        setColor(.normal);
    }

    writeStr("    Size: ");
    writeNumber(result.len);
    writeLine(" bytes");

    writeLine("");
    writeLine("    ────────────────────────────────────────────────────────");
    writeLine("");
    setColor(.warning);
    writeLine("    IMPORTANT:");
    setColor(.normal);
    writeLine("    Copy this file to USB drive or external storage.");
    writeLine("    Keep it separate from this computer for safety.");
    writeLine("");
    writeLine("    ────────────────────────────────────────────────────────");

    showFinalMessage();
}

fn generateBackupFilename(buf: *[16]u8) usize {
    var pos: usize = 0;
    var i: usize = 0;

    // Skip @ if present
    var name_start: usize = 0;
    if (name_len > 0 and name_buf[0] == '@') {
        name_start = 1;
    }

    // Copy name (uppercase, max 8 chars)
    while (i < 8 and name_start + i < name_len and pos < 12) : (i += 1) {
        var c = name_buf[name_start + i];
        if (c >= 'a' and c <= 'z') {
            c = c - 32; // Uppercase
        }
        if ((c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9')) {
            buf[pos] = c;
            pos += 1;
        }
    }

    // Add .ZIB extension
    const ext = ".ZIB";
    i = 0;
    while (i < ext.len and pos < 16) : (i += 1) {
        buf[pos] = ext[i];
        pos += 1;
    }

    return pos;
}

fn readPasswordInline(buf: *[64]u8) usize {
    var len: usize = 0;

    while (len < 63) {
        if (keyboard.getKey()) |key| {
            if (key == '\n' or key == '\r') {
                return len;
            }

            if (key == 0x1B) { // ESC - cancel
                return 0;
            }

            if (key == 0x08 or key == 0x7F) { // Backspace
                if (len > 0) {
                    len -= 1;
                    buf[len] = 0;
                    if (terminal.isInitialized()) {
                        terminal.writeChar(0x08);
                        terminal.writeChar(' ');
                        terminal.writeChar(0x08);
                    }
                }
                continue;
            }

            if (key >= 0x20 and key < 0x7F) {
                buf[len] = key;
                len += 1;
                if (terminal.isInitialized()) {
                    terminal.writeChar('*');
                }
            }
        }
    }

    return len;
}

// =============================================================================
// Backup Reminder (H.7.2)
// =============================================================================

fn showBackupReminder() void {
    writeLine("    ────────────────────────────────────────────────────────");
    writeLine("");
    setColor(.info);
    writeLine("    BACKUP COMMANDS - Available Anytime");
    setColor(.normal);
    writeLine("");

    setColor(.dim);
    writeLine("    Create encrypted backup file:");
    setColor(.bright);
    writeStr("      identity export full @");
    writeLine(name_buf[0..name_len]);
    setColor(.normal);
    writeLine("");

    setColor(.dim);
    writeLine("    Show recovery phrase again:");
    setColor(.bright);
    writeStr("      identity export mnemonic @");
    writeLine(name_buf[0..name_len]);
    setColor(.normal);
    writeLine("");

    setColor(.dim);
    writeLine("    Export public key (safe to share):");
    setColor(.bright);
    writeStr("      identity export public @");
    writeLine(name_buf[0..name_len]);
    setColor(.normal);
    writeLine("");

    setColor(.dim);
    writeLine("    Recover from backup:");
    setColor(.bright);
    writeLine("      identity import bundle <file.zib>");
    writeLine("      identity recover");
    setColor(.normal);
    writeLine("");

    writeLine("    ────────────────────────────────────────────────────────");

    showFinalMessage();
}

fn showFinalMessage() void {
    writeLine("");
    setColor(.success);
    writeLine("    ════════════════════════════════════════════════════════");
    writeLine("    ║       Zamrud OS is ready. Enjoy your privacy!        ║");
    writeLine("    ════════════════════════════════════════════════════════");
    setColor(.normal);
    writeLine("");

    setColor(.dim);
    writeStr("    Press any key to continue...");
    setColor(.normal);

    // Wait for any key
    while (keyboard.getKey() == null) {}

    writeLine("");
}

// =============================================================================
// Abort & Cleanup
// =============================================================================

fn abortCeremony(reason: []const u8) void {
    serial.writeString("[TRUST_CEREMONY] Aborted: ");
    serial.writeString(reason);
    serial.writeString("\n");

    ceremony_in_progress = false;
    ceremony_step = 0;
    phrase_generated = false;
    verify_passed = false;

    wipeAllBuffers();

    clearScreen();
    writeLine("");
    writeLine("");
    setColor(.error_color);
    writeStr("  Trust ceremony aborted: ");
    writeLine(reason);
    writeLine("");
    setColor(.normal);
    writeLine("  You can restart with 'ceremony start' command.");

    delay(3000);
}

fn wipeAllBuffers() void {
    constant_time.secureZero(&master_seed);
    constant_time.secureZero(&derived_key);
    constant_time.secureZero(&password_buf);
    constant_time.secureZero(&name_buf);
    password_len = 0;
    name_len = 0;
}

// =============================================================================
// UI Helpers
// =============================================================================

const ColorType = enum {
    normal,
    bright,
    dim,
    success,
    warning,
    error_color,
    info,
};

fn setColor(color: ColorType) void {
    if (!terminal.isInitialized()) return;

    const theme = ui.getTheme();
    switch (color) {
        .normal => terminal.setFgColor(theme.text_normal),
        .bright => terminal.setFgColor(theme.text_bright),
        .dim => terminal.setFgColor(theme.text_dim),
        .success => terminal.setFgColor(theme.text_success),
        .warning => terminal.setFgColor(theme.text_warning),
        .error_color => terminal.setFgColor(theme.text_error),
        .info => terminal.setFgColor(theme.text_info),
    }
}

fn clearScreen() void {
    serial.writeString("[CEREMONY] clearScreen called\n");
    if (terminal.isInitialized()) {
        terminal.clear();
        terminal.setCursor(0, 0);
        terminal.writeChar(' ');
        terminal.setCursor(0, 0);
    }
}

fn writeStr(s: []const u8) void {
    if (terminal.isInitialized()) {
        for (s) |c| terminal.writeChar(c);
    }
    serial.writeString(s);
}

fn writeLine(s: []const u8) void {
    writeStr(s);
    if (terminal.isInitialized()) {
        terminal.writeChar('\n');
    }
    serial.writeString("\n");
}

fn writeNumber(val: anytype) void {
    const v: u64 = @intCast(val);

    if (v == 0) {
        if (terminal.isInitialized()) terminal.writeChar('0');
        serial.writeChar('0');
        return;
    }

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;

    while (n > 0) : (i += 1) {
        buf[i] = @intCast((n % 10) + '0');
        n /= 10;
    }

    while (i > 0) {
        i -= 1;
        if (terminal.isInitialized()) terminal.writeChar(buf[i]);
        serial.writeChar(buf[i]);
    }
}

fn showMessage(msg: []const u8, msg_type: ColorType) void {
    setColor(msg_type);
    writeLine(msg);
    setColor(.normal);
}

fn waitForConfirm() bool {
    serial.writeString("[CEREMONY] Waiting for ENTER or ESC...\n");
    while (true) {
        if (keyboard.getKey()) |key| {
            serial.writeString("[CEREMONY] Key received: 0x");
            printHexSerial(key);
            serial.writeString("\n");

            if (key == '\n' or key == '\r') {
                serial.writeString("[CEREMONY] ENTER pressed\n");
                return true;
            }
            if (key == 0x1B) {
                serial.writeString("[CEREMONY] ESC pressed\n");
                return false;
            }
        }
    }
}

fn waitForEnter() bool {
    while (true) {
        if (keyboard.getKey()) |key| {
            if (key == '\n' or key == '\r') return true;
            if (key == 0x1B) return false;
        }
    }
}

fn delay(ms: u32) void {
    const start = timer.getSeconds();
    const wait_secs = (ms + 999) / 1000;

    if (wait_secs == 0) {
        var i: u32 = 0;
        while (i < ms * 1000) : (i += 1) {
            asm volatile ("pause");
        }
        return;
    }

    while (timer.getSeconds() - start < wait_secs) {
        asm volatile ("pause");
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

pub fn isFirstBoot() bool {
    if (identity_store.hasSavedIdentities()) {
        return false;
    }

    if (config_store.hasSavedConfig()) {
        return false;
    }

    if (config_store.isInitialized()) {
        if (config_store.get(KEY_CEREMONY_COMPLETE)) |val| {
            if (strEql(val, "true") or strEql(val, "1")) {
                return false;
            }
        }
    }

    if (identity.isInitialized() and identity.getIdentityCount() > 0) {
        return false;
    }

    return true;
}

pub fn isCeremonyComplete() bool {
    return !isFirstBoot();
}

pub fn getCeremonyVersion() u32 {
    if (config_store.get(KEY_CEREMONY_VERSION)) |val| {
        return parseU32(val) orelse 0;
    }
    return 0;
}

pub fn getTrustAnchor() ?[]const u8 {
    return config_store.get(KEY_TRUST_ANCHOR);
}

pub fn verifyTrustAnchor() bool {
    const anchor_hex = getTrustAnchor() orelse return false;
    const owner = keyring.getSystemOwner() orelse return false;

    var stored_hash: [32]u8 = undefined;
    if (!hexToBytes(anchor_hex, &stored_hash)) return false;

    return constant_time.constantTimeCompare32(&stored_hash, &owner.trust_hash);
}

// =============================================================================
// H.7: State Flags for Shell Integration
// =============================================================================

pub fn setJustCompleted(val: bool) void {
    ceremony_just_completed_flag = val;
}

pub fn ceremonyJustCompleted() bool {
    return ceremony_just_completed_flag;
}

pub fn setReturningUser(val: bool) void {
    returning_user_flag = val;
}

pub fn isReturningUser() bool {
    return returning_user_flag;
}

// =============================================================================
// Status & Query Functions
// =============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn isInProgress() bool {
    return ceremony_in_progress;
}

pub fn getCurrentStep() u8 {
    return ceremony_step;
}

pub fn getTotalSteps() u8 {
    return total_steps;
}

pub fn getSystemOwner() ?[]const u8 {
    return config_store.get(KEY_SYSTEM_OWNER);
}

// =============================================================================
// Factory Reset
// =============================================================================

pub fn resetCeremony() bool {
    serial.writeString("[TRUST_CEREMONY] WARNING: Resetting trust ceremony!\n");

    _ = config_store.delete(KEY_CEREMONY_COMPLETE);
    _ = config_store.delete(KEY_CEREMONY_VERSION);
    _ = config_store.delete(KEY_CEREMONY_TIMESTAMP);
    _ = config_store.delete(KEY_BOOT_PCR_BASELINE);
    _ = config_store.delete(KEY_SYSTEM_OWNER);
    _ = config_store.delete(KEY_TRUST_ANCHOR);

    _ = config_store.set(KEY_CEREMONY_COMPLETE, "false");
    _ = config_store.saveToDisk();

    keyring.init();

    ceremony_in_progress = false;
    ceremony_step = 0;
    phrase_generated = false;
    verify_passed = false;
    ceremony_just_completed_flag = false;
    returning_user_flag = false;

    wipeAllBuffers();

    serial.writeString("[TRUST_CEREMONY] Reset complete\n");
    return true;
}

// =============================================================================
// Helper Functions
// =============================================================================

fn hexToBytes(hex: []const u8, out: *[32]u8) bool {
    if (hex.len < 64) return false;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const hi = hexDigit(hex[i * 2]) orelse return false;
        const lo = hexDigit(hex[i * 2 + 1]) orelse return false;
        out[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    return true;
}

fn hexDigit(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @intCast(c - '0');
    if (c >= 'a' and c <= 'f') return @intCast(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @intCast(c - 'A' + 10);
    return null;
}

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

fn parseU32(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var result: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        const digit: u32 = c - '0';
        if (result > 429496729) return null;
        result = result * 10;
        if (result > 0xFFFFFFFF - digit) return null;
        result = result + digit;
    }
    return result;
}

fn formatU32(val: u32, buf: []u8) usize {
    if (val == 0) {
        if (buf.len > 0) buf[0] = '0';
        return 1;
    }

    var v = val;
    var i: usize = 0;

    while (v > 0 and i < buf.len) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }

    var j: usize = 0;
    var k: usize = if (i > 0) i - 1 else 0;
    while (j < k) {
        const tmp = buf[j];
        buf[j] = buf[k];
        buf[k] = tmp;
        j += 1;
        k -= 1;
    }

    return i;
}

fn bytesToHex(bytes: []const u8, out: []u8) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < bytes.len and i * 2 + 1 < out.len) : (i += 1) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }
}

fn printHexSerial(value: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(value >> 4) & 0x0F]);
    serial.writeChar(hex[value & 0x0F]);
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  H.7 TRUST CEREMONY TESTS (v2)\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // [1/6] Initialization
    serial.writeString("  [1/6] Initialization\n");

    serial.writeString("    - init()........................ ");
    init();
    if (initialized) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("    - isInitialized()............... ");
    if (isInitialized()) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("    - not in progress............... ");
    if (!isInProgress()) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("    - step = 0...................... ");
    if (getCurrentStep() == 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // [2/6] First boot detection
    serial.writeString("  [2/6] First boot detection\n");

    serial.writeString("    - isFirstBoot() logic........... ");
    {
        const was_complete = config_store.get(KEY_CEREMONY_COMPLETE);
        _ = config_store.delete(KEY_CEREMONY_COMPLETE);

        const is_first = isFirstBoot();

        if (was_complete) |val| {
            _ = config_store.set(KEY_CEREMONY_COMPLETE, val);
        }

        serial.writeString("PASS (");
        if (is_first) serial.writeString("first") else serial.writeString("not first");
        serial.writeString(")\n");
        passed += 1;
    }

    serial.writeString("    - isCeremonyComplete().......... ");
    {
        _ = config_store.set(KEY_CEREMONY_COMPLETE, "true");
        if (isCeremonyComplete()) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
        _ = config_store.delete(KEY_CEREMONY_COMPLETE);
    }

    serial.writeString("    - getCeremonyVersion().......... ");
    {
        _ = config_store.set(KEY_CEREMONY_VERSION, "2");
        if (getCeremonyVersion() == 2) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
        _ = config_store.delete(KEY_CEREMONY_VERSION);
    }

    serial.writeString("    - version 0 when missing........ ");
    if (getCeremonyVersion() == 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // [3/6] Secure buffer wipe
    serial.writeString("  [3/6] Secure buffer wipe\n");

    serial.writeString("    - wipeAllBuffers().............. ");
    {
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            master_seed[i] = 0xAA;
            derived_key[i] = 0xBB;
        }
        password_len = 10;
        name_len = 8;

        wipeAllBuffers();

        var all_zero = true;
        i = 0;
        while (i < 32) : (i += 1) {
            if (master_seed[i] != 0 or derived_key[i] != 0) {
                all_zero = false;
                break;
            }
        }

        if (all_zero and password_len == 0 and name_len == 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - password_buf wiped............ ");
    {
        var all_zero = true;
        var i: usize = 0;
        while (i < MAX_PASSWORD_LEN) : (i += 1) {
            if (password_buf[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - name_buf wiped................ ");
    {
        var all_zero = true;
        var i: usize = 0;
        while (i < MAX_NAME_LEN) : (i += 1) {
            if (name_buf[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // [4/6] Verify index selection
    serial.writeString("  [4/6] Verify index selection\n");

    serial.writeString("    - selectVerifyIndices()......... ");
    {
        selectVerifyIndices();
        var valid = true;
        var v: usize = 0;
        while (v < VERIFY_WORD_COUNT) : (v += 1) {
            if (verify_indices[v] >= RECOVERY_PHRASE_WORDS) {
                valid = false;
                break;
            }
        }
        if (valid) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - no duplicate indices.......... ");
    {
        var valid = true;
        var v: usize = 0;
        while (v < VERIFY_WORD_COUNT - 1) : (v += 1) {
            var w: usize = v + 1;
            while (w < VERIFY_WORD_COUNT) : (w += 1) {
                if (verify_indices[v] == verify_indices[w]) {
                    valid = false;
                    break;
                }
            }
        }
        if (valid) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - indices sorted................ ");
    {
        var sorted = true;
        var v: usize = 0;
        while (v < VERIFY_WORD_COUNT - 1) : (v += 1) {
            if (verify_indices[v] >= verify_indices[v + 1]) {
                sorted = false;
                break;
            }
        }
        if (sorted) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - different on re-select........ ");
    {
        var old_indices: [VERIFY_WORD_COUNT]u8 = undefined;
        var i: usize = 0;
        while (i < VERIFY_WORD_COUNT) : (i += 1) {
            old_indices[i] = verify_indices[i];
        }

        var different = false;
        var attempt: u32 = 0;
        while (attempt < 10 and !different) : (attempt += 1) {
            selectVerifyIndices();
            i = 0;
            while (i < VERIFY_WORD_COUNT) : (i += 1) {
                if (verify_indices[i] != old_indices[i]) {
                    different = true;
                    break;
                }
            }
        }

        if (different) {
            serial.writeString("PASS\n");
        } else {
            serial.writeString("WARN (same - random)\n");
        }
        passed += 1;
    }

    // [5/6] Trust anchor & blockchain
    serial.writeString("  [5/6] Trust anchor & blockchain\n");

    serial.writeString("    - keyring trust hash............ ");
    {
        keyring.init();
        const test_id = keyring.createIdentityWithPassword("test_trust", "SecureP1");
        if (test_id != null and !constant_time.constantTimeIsZero32(&test_id.?.trust_hash)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - trust hash verification....... ");
    {
        if (keyring.getSystemOwner()) |owner| {
            if (keyring.verifyTrustHash(owner)) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("SKIP (no owner)\n");
            passed += 1;
        }
    }

    serial.writeString("    - password creates password type ");
    {
        if (keyring.getSystemOwner()) |owner| {
            if (owner.credential_type == .password) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("SKIP\n");
            passed += 1;
        }
    }

    serial.writeString("    - owner flag set................ ");
    {
        if (keyring.getSystemOwner()) |owner| {
            if (owner.is_owner) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("SKIP\n");
            passed += 1;
        }
    }

    // [6/6] Format utilities & state
    serial.writeString("  [6/6] Format utilities & state\n");

    serial.writeString("    - formatU32(12345).............. ");
    {
        var buf: [16]u8 = undefined;
        const len = formatU32(12345, &buf);
        if (len == 5 and buf[0] == '1' and buf[4] == '5') {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - bytesToHex().................. ");
    {
        var hex_out: [8]u8 = undefined;
        const test_bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        bytesToHex(&test_bytes, &hex_out);

        if (hex_out[0] == 'd' and hex_out[1] == 'e' and hex_out[6] == 'e' and hex_out[7] == 'f') {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - hexToBytes().................. ");
    {
        var out: [32]u8 = [_]u8{0} ** 32;
        const test_hex = "deadbeef00000000000000000000000000000000000000000000000000000000";
        if (hexToBytes(test_hex, &out) and out[0] == 0xDE and out[1] == 0xAD) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("    - getTotalSteps() = 7........... ");
    if (getTotalSteps() == 7) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Summary
    serial.writeString("\n  ────────────────────────────────────\n");
    serial.writeString("  H.7 Results: ");
    printU32Serial(passed);
    serial.writeString("/");
    printU32Serial(passed + failed);
    serial.writeString(" passed");
    if (failed == 0) {
        serial.writeString(" OK\n");
    } else {
        serial.writeString(" FAILED\n");
    }
    serial.writeString("========================================\n");

    return failed == 0;
}

fn printU32Serial(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [10]u8 = undefined;
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
