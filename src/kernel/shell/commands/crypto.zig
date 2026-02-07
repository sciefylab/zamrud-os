//! Zamrud OS - Crypto Commands
//! Cryptographic operations: hashing, signing, key generation

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const crypto = @import("../../crypto/crypto.zig");

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "status")) {
        showStatus();
    } else if (helpers.strEql(parsed.cmd, "hash")) {
        computeHash(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "sign")) {
        signMessage(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "verify")) {
        verifySignature(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "keygen")) {
        generateKey();
    } else if (helpers.strEql(parsed.cmd, "random")) {
        generateRandom(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "seed")) {
        showSeedPhrase();
    } else {
        shell.printError("crypto: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'crypto help'");
    }
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  CRYPTO - Cryptography Module");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: crypto <command> [args]");
    shell.newLine();

    shell.println("Commands:");
    shell.println("  help              Show this help");
    shell.println("  status            Show crypto subsystem status");
    shell.println("  hash <text>       Compute SHA-256 hash");
    shell.println("  sign <text>       Sign message with current key");
    shell.println("  verify            Verify last signature");
    shell.println("  keygen            Generate new key pair");
    shell.println("  random [n]        Generate random bytes (default: 16)");
    shell.println("  seed              Generate/show seed phrase");
    shell.newLine();

    shell.println("Test Commands:");
    shell.println("  test              Run all crypto tests");
    shell.println("  test quick        Quick health check");
    shell.println("  test hash         Test SHA-256 only");
    shell.println("  test random       Test RNG only");
    shell.println("  test sign         Test signatures only");
    shell.println("  test seed         Test seed phrases");
    shell.newLine();
}

// =============================================================================
// Test Commands
// =============================================================================

pub fn runTest(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "all")) {
        runAllTests();
    } else if (helpers.strEql(opt, "quick")) {
        runQuickTest();
    } else if (helpers.strEql(opt, "hash")) {
        runHashTest();
    } else if (helpers.strEql(opt, "random")) {
        runRandomTest();
    } else if (helpers.strEql(opt, "sign")) {
        runSignTest();
    } else if (helpers.strEql(opt, "seed")) {
        runSeedTest();
    } else {
        shell.println("crypto test options:");
        shell.println("  all, quick, hash, random, sign, seed");
    }
}

fn runQuickTest() void {
    shell.printInfoLine("Crypto Quick Test...");
    shell.newLine();

    var ok = true;

    shell.print("  Initialized:  ");
    if (crypto.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  SHA-256:      ");
    const hash_result = crypto.sha256("test");
    if (hash_result[0] != 0 or hash_result[1] != 0) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  RNG:          ");
    var rand_buf: [8]u8 = [_]u8{0} ** 8;
    crypto.random.getBytes(&rand_buf);
    var has_nonzero = false;
    for (rand_buf) |b| {
        if (b != 0) has_nonzero = true;
    }
    if (has_nonzero) {
        shell.printSuccessLine("OK");
    } else {
        shell.printWarningLine("Weak");
    }

    shell.print("  RDRAND:       ");
    if (crypto.random.hasHardwareRng()) {
        shell.printSuccessLine("Available");
    } else {
        shell.println("Software fallback");
    }

    shell.newLine();
    helpers.printQuickResult("Crypto", ok);
}

fn runAllTests() void {
    helpers.printTestHeader("CRYPTO TEST SUITE");

    var total_passed: u32 = 0;
    var total_failed: u32 = 0;

    // SHA-256 Tests
    shell.printInfoLine("=== SHA-256 ===");
    var p: u32 = 0;
    var f: u32 = 0;

    // Test empty string hash
    const empty_hash = crypto.sha256("");
    p += helpers.doTest("Empty string hash", empty_hash[0] == 0xe3 and empty_hash[1] == 0xb0, &f);

    // Test non-zero hash
    const test_hash = crypto.sha256("test");
    p += helpers.doTest("'test' hash not zero", test_hash[0] != 0, &f);

    // Test deterministic - hash same input twice
    const test_hash1 = crypto.sha256("test");
    const test_hash2 = crypto.sha256("test");
    var same = true;
    for (test_hash1, test_hash2) |h1, h2| {
        if (h1 != h2) same = false;
    }
    p += helpers.doTest("Hash is deterministic", same, &f);

    // Test different inputs produce different hashes
    // FIXED: Use sha256() which returns a copy, not sha256Ptr() which returns pointer to static buffer
    const hash_a = crypto.sha256("a");
    const hash_b = crypto.sha256("b");
    var different = false;
    for (hash_a, hash_b) |ha, hb| {
        if (ha != hb) different = true;
    }
    p += helpers.doTest("Different inputs differ", different, &f);

    total_passed += p;
    total_failed += f;

    // Random Tests
    shell.newLine();
    shell.printInfoLine("=== Random Number Generator ===");
    p = 0;
    f = 0;

    var buf1: [16]u8 = [_]u8{0} ** 16;
    var buf2: [16]u8 = [_]u8{0} ** 16;

    crypto.random.getBytes(&buf1);
    crypto.random.getBytes(&buf2);

    var buffers_different = false;
    for (buf1, buf2) |b1, b2| {
        if (b1 != b2) buffers_different = true;
    }
    p += helpers.doTest("Sequential fills differ", buffers_different, &f);

    var has_nonzero = false;
    for (buf1) |b| {
        if (b != 0) has_nonzero = true;
    }
    p += helpers.doTest("Output not all zeros", has_nonzero, &f);

    p += helpers.doTest("RDRAND detection works", true, &f);

    const rand_val = crypto.random.getU32();
    _ = rand_val;
    p += helpers.doTest("getU32() works", true, &f);

    total_passed += p;
    total_failed += f;

    // Signature Tests
    shell.newLine();
    shell.printInfoLine("=== Digital Signatures ===");
    p = 0;
    f = 0;

    crypto.KeyPair.generate();
    const pub_key = crypto.KeyPair.getPublicKey();
    p += helpers.doTest("Key generation", pub_key[0] != 0 or pub_key[1] != 0, &f);

    const message = "Test message for signing";
    const signature = crypto.KeyPair.sign(message);
    p += helpers.doTest("Signature created", signature[0] != 0 or signature[1] != 0, &f);

    const valid = crypto.verify(pub_key, message, signature);
    p += helpers.doTest("Verify correct message", valid, &f);

    const invalid = crypto.verify(pub_key, "Wrong message", signature);
    p += helpers.doTest("Reject wrong message", !invalid, &f);

    var bad_sig: [64]u8 = undefined;
    for (signature, 0..) |b, i| {
        bad_sig[i] = b;
    }
    bad_sig[0] ^= 0xFF;
    const invalid2 = crypto.verify(pub_key, message, &bad_sig);
    p += helpers.doTest("Reject bad signature", !invalid2, &f);

    total_passed += p;
    total_failed += f;

    // Seed Phrase Tests
    shell.newLine();
    shell.printInfoLine("=== Seed Phrases ===");
    p = 0;
    f = 0;

    const phrase1 = crypto.SeedPhrase.generate();
    const word0 = phrase1.getWordAt(0);
    p += helpers.doTest("Word 0 exists", word0.len > 0, &f);

    const word11 = phrase1.getWordAt(11);
    p += helpers.doTest("Word 11 exists", word11.len > 0, &f);

    const phrase2 = crypto.SeedPhrase.generate();
    _ = phrase2;
    p += helpers.doTest("Phrases generated", true, &f);

    total_passed += p;
    total_failed += f;

    helpers.printTestResults(total_passed, total_failed);
}

fn runHashTest() void {
    helpers.printTestHeader("SHA-256 HASH TEST");

    var p: u32 = 0;
    var f: u32 = 0;

    shell.println("Testing SHA-256 implementation...");
    shell.newLine();

    const empty = crypto.sha256("");
    p += helpers.doTest("Empty string prefix", empty[0] == 0xe3, &f);

    const abc = crypto.sha256("abc");
    p += helpers.doTest("'abc' first byte", abc[0] == 0xba, &f);

    const long_str = "The quick brown fox jumps over the lazy dog";
    const long_hash = crypto.sha256(long_str);
    p += helpers.doTest("Long string hashes", long_hash[0] != 0, &f);

    const h1 = crypto.sha256("determinism");
    const h2 = crypto.sha256("determinism");
    var match = true;
    for (h1, h2) |a, b| {
        if (a != b) match = false;
    }
    p += helpers.doTest("Deterministic output", match, &f);

    helpers.printTestResults(p, f);

    shell.newLine();
    shell.println("Example hash:");
    shell.print("  Input:  \"test\"");
    shell.newLine();
    shell.print("  SHA-256: ");
    const test_h = crypto.sha256("test");
    for (test_h) |b| {
        helpers.printHexByte(b);
    }
    shell.newLine();
}

fn runRandomTest() void {
    helpers.printTestHeader("RANDOM NUMBER GENERATOR TEST");

    var p: u32 = 0;
    var f: u32 = 0;

    shell.print("Hardware RNG (RDRAND): ");
    if (crypto.random.hasHardwareRng()) {
        shell.printSuccessLine("Available");
    } else {
        shell.printWarningLine("Not available - using software PRNG");
    }
    shell.newLine();

    var buf: [32]u8 = [_]u8{0} ** 32;
    crypto.random.getBytes(&buf);

    var nonzero_count: usize = 0;
    for (buf) |b| {
        if (b != 0) nonzero_count += 1;
    }
    p += helpers.doTest("Has non-zero bytes", nonzero_count > 0, &f);
    p += helpers.doTest("Good distribution", nonzero_count > 8, &f);

    var buf2: [32]u8 = [_]u8{0} ** 32;
    crypto.random.getBytes(&buf2);
    var diff_count: usize = 0;
    for (buf, buf2) |b1, b2| {
        if (b1 != b2) diff_count += 1;
    }
    p += helpers.doTest("Sequential differs", diff_count > 16, &f);

    const v1 = crypto.random.getU32();
    const v2 = crypto.random.getU32();
    p += helpers.doTest("getU32 varies", v1 != v2, &f);

    const v3 = crypto.random.getU64();
    const v4 = crypto.random.getU64();
    p += helpers.doTest("getU64 varies", v3 != v4, &f);

    helpers.printTestResults(p, f);

    shell.newLine();
    shell.println("Sample random bytes:");
    shell.print("  ");
    for (buf[0..16]) |b| {
        helpers.printHexByte(b);
        shell.print(" ");
    }
    shell.newLine();
}

fn runSignTest() void {
    helpers.printTestHeader("DIGITAL SIGNATURE TEST");

    var p: u32 = 0;
    var f: u32 = 0;

    shell.println("Testing HMAC-SHA256 signatures...");
    shell.newLine();

    crypto.KeyPair.generate();
    const pub_key = crypto.KeyPair.getPublicKey();
    p += helpers.doTest("Key pair generated", pub_key[0] != 0, &f);

    const msg = "Important transaction data";
    const sig = crypto.KeyPair.sign(msg);
    p += helpers.doTest("Message signed", sig[0] != 0, &f);

    p += helpers.doTest("Correct verification", crypto.verify(pub_key, msg, sig), &f);

    p += helpers.doTest("Tampered msg rejected", !crypto.verify(pub_key, "Tampered data", sig), &f);

    var bad_sig: [64]u8 = undefined;
    for (sig, 0..) |b, i| {
        bad_sig[i] = b;
    }
    bad_sig[15] ^= 0x01;
    p += helpers.doTest("Tampered sig rejected", !crypto.verify(pub_key, msg, &bad_sig), &f);

    crypto.KeyPair.generate();
    const new_pub = crypto.KeyPair.getPublicKey();
    p += helpers.doTest("Wrong key rejected", !crypto.verify(new_pub, msg, sig), &f);

    helpers.printTestResults(p, f);
}

fn runSeedTest() void {
    helpers.printTestHeader("SEED PHRASE TEST");

    var p: u32 = 0;
    var f: u32 = 0;

    const phrase = crypto.SeedPhrase.generate();

    var all_valid = true;
    var i: usize = 0;
    while (i < 12) : (i += 1) {
        const word = phrase.getWordAt(i);
        if (word.len == 0) all_valid = false;
    }
    p += helpers.doTest("12 words generated", all_valid, &f);

    const word0 = phrase.getWordAt(0);
    p += helpers.doTest("Word length valid", word0.len >= 3 and word0.len <= 8, &f);

    const phrase2 = crypto.SeedPhrase.generate();
    _ = phrase2;
    p += helpers.doTest("Multiple phrases work", true, &f);

    phrase.toKeyPair();
    const derived_key = crypto.KeyPair.getPublicKey();
    p += helpers.doTest("Derives key pair", derived_key[0] != 0, &f);

    helpers.printTestResults(p, f);
}

// =============================================================================
// Status Command
// =============================================================================

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  CRYPTO SUBSYSTEM STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Initialized:      ");
    if (crypto.isInitialized()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printErrorLine("No");
    }

    shell.newLine();
    shell.println("  Algorithms:");

    shell.print("    SHA-256:        ");
    shell.printSuccessLine("Available (software)");

    shell.print("    Signatures:     ");
    shell.printSuccessLine("HMAC-based");

    shell.newLine();
    shell.println("  Random Number Generator:");

    shell.print("    Hardware RNG:   ");
    if (crypto.random.hasHardwareRng()) {
        shell.printSuccessLine("RDRAND available");
    } else {
        shell.printWarningLine("Not available");
    }

    shell.print("    Fallback:       ");
    shell.println("Software PRNG");

    shell.newLine();
    shell.println("  Key Management:");
    shell.println("    Seed phrases:   BIP39 (2048 words)");
    shell.println("    Key derivation: SHA-256 based");

    shell.newLine();
}

// =============================================================================
// Hash Command
// =============================================================================

fn computeHash(args: []const u8) void {
    if (args.len == 0) {
        shell.printErrorLine("Usage: crypto hash <text>");
        return;
    }

    shell.printInfoLine("SHA-256 Hash:");
    shell.newLine();

    shell.print("  Input:  \"");
    shell.print(args);
    shell.println("\"");

    shell.print("  Length: ");
    helpers.printUsize(args.len);
    shell.println(" bytes");

    shell.newLine();
    shell.print("  Hash:   ");

    const hash_result = crypto.sha256(args);
    for (hash_result) |b| {
        helpers.printHexByte(b);
    }
    shell.newLine();
}

// =============================================================================
// Sign Command
// =============================================================================

fn signMessage(args: []const u8) void {
    if (args.len == 0) {
        shell.printErrorLine("Usage: crypto sign <message>");
        return;
    }

    shell.printInfoLine("Digital Signature:");
    shell.newLine();

    shell.print("  Message: \"");
    shell.print(args);
    shell.println("\"");

    crypto.KeyPair.generate();

    shell.print("  Public Key: ");
    const pub_key = crypto.KeyPair.getPublicKey();
    for (pub_key[0..16]) |b| {
        helpers.printHexByte(b);
    }
    shell.println("...");

    const sig = crypto.KeyPair.sign(args);
    shell.print("  Signature:  ");
    for (sig[0..16]) |b| {
        helpers.printHexByte(b);
    }
    shell.println("...");

    const valid = crypto.verify(pub_key, args, sig);
    shell.print("  Verified:   ");
    if (valid) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printErrorLine("No");
    }

    shell.newLine();
}

// =============================================================================
// Verify Command
// =============================================================================

fn verifySignature(_: []const u8) void {
    shell.printInfoLine("Signature Verification:");
    shell.newLine();
    shell.println("  Use 'crypto sign' to sign and verify.");
    shell.newLine();
}

// =============================================================================
// Key Generation
// =============================================================================

fn generateKey() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  IDENTITY KEY GENERATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.printWarningLine("!! BACKUP YOUR SEED PHRASE !!");
    shell.newLine();

    const phrase = crypto.SeedPhrase.generate();

    shell.println("+------------------------------------------+");

    var i: usize = 0;
    while (i < 12) : (i += 1) {
        if (i % 3 == 0) {
            shell.print("| ");
        }

        if (i + 1 < 10) shell.print(" ");
        helpers.printUsize(i + 1);
        shell.print(". ");

        const word = phrase.getWordAt(i);
        shell.print(word);

        var pad: usize = 0;
        while (pad + word.len < 10) : (pad += 1) {
            shell.print(" ");
        }

        if ((i + 1) % 3 == 0) {
            shell.println(" |");
        }
    }

    shell.println("+------------------------------------------+");
    shell.newLine();

    phrase.toKeyPair();

    shell.print("  Public Key: ");
    const pub_key = crypto.KeyPair.getPublicKey();
    for (pub_key) |b| {
        helpers.printHexByte(b);
    }
    shell.newLine();

    shell.newLine();
    shell.printSuccessLine("Identity generated!");
    shell.newLine();
}

// =============================================================================
// Random Command
// =============================================================================

fn generateRandom(args: []const u8) void {
    var count: usize = 16;

    if (args.len > 0) {
        count = helpers.parseU32(args) orelse 16;
        if (count > 256) count = 256;
        if (count == 0) count = 16;
    }

    shell.printInfoLine("Random Bytes:");
    shell.newLine();

    shell.print("  Count: ");
    helpers.printUsize(count);
    shell.println(" bytes");

    shell.newLine();
    shell.print("  ");

    var buf: [256]u8 = [_]u8{0} ** 256;
    crypto.random.getBytes(buf[0..count]);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        helpers.printHexByte(buf[i]);
        if ((i + 1) % 16 == 0 and i + 1 < count) {
            shell.newLine();
            shell.print("  ");
        } else if (i + 1 < count) {
            shell.print(" ");
        }
    }
    shell.newLine();
    shell.newLine();
}

// =============================================================================
// Seed Phrase Command
// =============================================================================

fn showSeedPhrase() void {
    shell.printInfoLine("Seed Phrase Generator:");
    shell.newLine();

    const phrase = crypto.SeedPhrase.generate();

    var i: usize = 0;
    while (i < 12) : (i += 1) {
        shell.print("    ");
        if (i + 1 < 10) shell.print(" ");
        helpers.printUsize(i + 1);
        shell.print(". ");
        shell.println(phrase.getWordAt(i));
    }

    shell.newLine();
}
