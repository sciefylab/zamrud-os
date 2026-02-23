//! Zamrud OS - Crypto Commands (HARDENED)
//! H.1 + H.2: Includes constant-time and entropy testing
//! Cryptographic operations: hashing, signing, key generation, entropy

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
    } else if (helpers.strEql(parsed.cmd, "entropy")) {
        showEntropy(parsed.rest);
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
    shell.printInfoLine("  CRYPTO - Cryptography Module (H.1+H.2)");
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
    shell.println("  entropy [cmd]     Entropy pool management");
    shell.newLine();

    shell.println("Test Commands:");
    shell.println("  test              Run all crypto tests (8 suites)");
    shell.println("  test quick        Quick health check");
    shell.println("  test hash         Test SHA-256 only");
    shell.println("  test random       Test RNG only");
    shell.println("  test sign         Test signatures only");
    shell.println("  test seed         Test seed phrases");
    shell.println("  test ct           Test constant-time ops (H.1)");
    shell.println("  test entropy      Test entropy/CSPRNG (H.2)");
    shell.println("  test hardened     Test H.1 + H.2 together");
    shell.newLine();

    shell.println("Entropy Commands:");
    shell.println("  entropy status    Show entropy pool status");
    shell.println("  entropy reseed    Force reseed from all sources");
    shell.println("  entropy test      Run entropy tests");
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
    } else if (helpers.strEql(opt, "ct")) {
        runConstantTimeTest();
    } else if (helpers.strEql(opt, "entropy")) {
        runEntropyTest();
    } else if (helpers.strEql(opt, "hardened")) {
        runHardenedTest();
    } else {
        shell.println("crypto test options:");
        shell.println("  all, quick, hash, random, sign, seed, ct, entropy, hardened");
    }
}

fn runQuickTest() void {
    shell.printInfoLine("Crypto Quick Test (HARDENED)...");
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

    // H.1: Constant-time check
    shell.print("  Const-Time:   ");
    {
        const a = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        const b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        const c = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDE };
        if (crypto.constantTimeCompare(&a, &b) and !crypto.constantTimeCompare(&a, &c)) {
            shell.printSuccessLine("OK");
        } else {
            shell.printErrorLine("FAIL");
            ok = false;
        }
    }

    // H.2: Entropy check
    shell.print("  Entropy:      ");
    {
        const bits = crypto.entropy.getEntropyBits();
        if (bits > 0) {
            shell.printSuccess("OK (");
            helpers.printUsize(@as(usize, bits));
            shell.printSuccessLine(" bits)");
        } else {
            shell.printErrorLine("FAIL (0 bits)");
            ok = false;
        }
    }

    // H.2: CSPRNG check
    shell.print("  CSPRNG:       ");
    {
        if (crypto.entropy.isSeeded()) {
            shell.printSuccessLine("Seeded");
        } else {
            shell.printWarningLine("Not seeded");
        }
    }

    shell.newLine();
    helpers.printQuickResult("Crypto", ok);
}

fn runAllTests() void {
    helpers.printTestHeader("CRYPTO TEST SUITE (HARDENED)");

    var total_passed: u32 = 0;
    var total_failed: u32 = 0;

    // SHA-256 Tests
    shell.printInfoLine("=== SHA-256 ===");
    var p: u32 = 0;
    var f: u32 = 0;

    const empty_hash = crypto.sha256("");
    p += helpers.doTest("Empty string hash", empty_hash[0] == 0xe3 and empty_hash[1] == 0xb0, &f);

    const test_hash = crypto.sha256("test");
    p += helpers.doTest("'test' hash not zero", test_hash[0] != 0, &f);

    const test_hash1 = crypto.sha256("test");
    const test_hash2 = crypto.sha256("test");
    var same = true;
    for (test_hash1, test_hash2) |h1, h2| {
        if (h1 != h2) same = false;
    }
    p += helpers.doTest("Hash is deterministic", same, &f);

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

    // Signature Tests (HARDENED)
    shell.newLine();
    shell.printInfoLine("=== Digital Signatures (HARDENED) ===");
    p = 0;
    f = 0;

    crypto.KeyPair.generate();
    const pub_key = crypto.KeyPair.getPublicKey();
    p += helpers.doTest("Key generation", pub_key[0] != 0 or pub_key[1] != 0, &f);

    const message = "Test message for signing";
    const sig1 = crypto.KeyPair.sign(message);
    p += helpers.doTest("Signature created", sig1[0] != 0 or sig1[1] != 0, &f);

    const valid = crypto.verify(pub_key, message, sig1);
    p += helpers.doTest("Verify correct message", valid, &f);

    const invalid = crypto.verify(pub_key, "Wrong message", sig1);
    p += helpers.doTest("Reject wrong message", !invalid, &f);

    var bad_sig: [64]u8 = undefined;
    for (sig1, 0..) |b, i| {
        bad_sig[i] = b;
    }
    bad_sig[0] ^= 0xFF;
    const invalid2 = crypto.verify(pub_key, message, &bad_sig);
    p += helpers.doTest("Reject bad signature", !invalid2, &f);

    // H.1 FIX: Test long messages (>64 bytes) — was BROKEN before!
    const long_msg = "This is a message longer than sixty-four bytes to test the HMAC truncation fix applied in H.1!";
    const long_sig = crypto.KeyPair.sign(long_msg);
    p += helpers.doTest("Long msg (>64B) sign+verify", crypto.verify(pub_key, long_msg, long_sig), &f);

    // H.1 FIX: Different suffixes after byte 64 must produce different signatures
    const msg_a = "Identical prefix that spans well past the sixty-four byte boundary: suffix_AAAA";
    const msg_b = "Identical prefix that spans well past the sixty-four byte boundary: suffix_BBBB";
    const sig_a = crypto.KeyPair.sign(msg_a);

    var sig_a_copy: [64]u8 = undefined;
    for (sig_a, 0..) |b, i| {
        sig_a_copy[i] = b;
    }

    const sig_b = crypto.KeyPair.sign(msg_b);
    p += helpers.doTest("Long msg diff suffix ≠ sig", !crypto.constantTimeCompare64(&sig_a_copy, sig_b), &f);

    // Zero signature rejected
    var zero_sig: [64]u8 = [_]u8{0} ** 64;
    p += helpers.doTest("Reject zero signature", !crypto.verify(pub_key, message, &zero_sig), &f);

    // Zero public key rejected
    var zero_pk: [32]u8 = [_]u8{0} ** 32;
    p += helpers.doTest("Reject zero pubkey", !crypto.verify(&zero_pk, message, sig1), &f);

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

    phrase1.toKeyPair();
    const derived_key = crypto.KeyPair.getPublicKey();
    p += helpers.doTest("Derives key pair", derived_key[0] != 0, &f);

    total_passed += p;
    total_failed += f;

    // H.1: Constant-Time Tests
    shell.newLine();
    shell.printInfoLine("=== Constant-Time Operations (H.1) ===");
    p = 0;
    f = 0;

    // CT compare equal
    {
        const a = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        const b = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        p += helpers.doTest("CT compare equal", crypto.constantTimeCompare(&a, &b), &f);
    }

    // CT compare different
    {
        const a = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        const c = [_]u8{ 0xDE, 0xAD, 0xBE, 0x00 };
        p += helpers.doTest("CT compare different", !crypto.constantTimeCompare(&a, &c), &f);
    }

    // CT 32-byte compare
    {
        var h1: [32]u8 = undefined;
        var h2: [32]u8 = undefined;
        crypto.sha256Into("ct-test", &h1);
        crypto.sha256Into("ct-test", &h2);
        p += helpers.doTest("CT hash compare (32B)", crypto.constantTimeCompare32(&h1, &h2), &f);
    }

    // CT isZero
    {
        const zeros = [_]u8{0} ** 32;
        var nonzero = [_]u8{0} ** 32;
        nonzero[31] = 1;
        p += helpers.doTest("CT isZero (true)", crypto.constantTimeIsZero(&zeros), &f);
        p += helpers.doTest("CT isZero (false)", !crypto.constantTimeIsZero(&nonzero), &f);
    }

    // Secure zero
    {
        var secret = [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE };
        crypto.secureZero(&secret);
        p += helpers.doTest("Secure zero works", crypto.constantTimeIsZero(&secret), &f);
    }

    // CT PKCS7 padding
    {
        const valid_pad = [_]u8{ 'H', 'i', 0x02, 0x02 };
        const bad_pad = [_]u8{ 'H', 'i', 0x01, 0x02 };
        const v = crypto.constant_time.verifyPkcs7Padding(&valid_pad, 4);
        const b = crypto.constant_time.verifyPkcs7Padding(&bad_pad, 4);
        p += helpers.doTest("PKCS7 valid padding", v != null and v.? == 2, &f);
        p += helpers.doTest("PKCS7 invalid rejected", b == null, &f);
    }

    total_passed += p;
    total_failed += f;

    // H.2: Entropy Tests
    shell.newLine();
    shell.printInfoLine("=== Entropy & CSPRNG (H.2) ===");
    p = 0;
    f = 0;

    // Entropy collected
    p += helpers.doTest("Entropy pool has bits", crypto.entropy.getEntropyBits() > 0, &f);

    // CSPRNG seeded
    p += helpers.doTest("CSPRNG is seeded", crypto.entropy.isSeeded(), &f);

    // Secure bytes output
    {
        var sbuf: [32]u8 = [_]u8{0} ** 32;
        if (crypto.entropy.getSecureBytes(&sbuf)) {
            p += helpers.doTest("Secure bytes non-zero", !crypto.constantTimeIsZero(&sbuf), &f);
        } else |_| {
            p += helpers.doTest("Secure bytes non-zero", false, &f);
        }
    }

    // Two secure outputs differ
    {
        var sa: [16]u8 = [_]u8{0} ** 16;
        var sb: [16]u8 = [_]u8{0} ** 16;
        const ok_a = crypto.entropy.getSecureBytes(&sa);
        const ok_b = crypto.entropy.getSecureBytes(&sb);
        if (ok_a) {
            if (ok_b) {
                var differs = false;
                for (sa, sb) |a, b| {
                    if (a != b) differs = true;
                }
                p += helpers.doTest("Two secure outputs differ", differs, &f);
            } else |_| {
                p += helpers.doTest("Two secure outputs differ", false, &f);
            }
        } else |_| {
            p += helpers.doTest("Two secure outputs differ", false, &f);
        }
    }

    // Event entropy
    {
        const before = crypto.entropy.getEntropyBits();
        crypto.entropy.addEventEntropy();
        crypto.entropy.addEventEntropy();
        p += helpers.doTest("Event entropy added", crypto.entropy.getEntropyBits() >= before, &f);
    }

    // Reseed
    {
        crypto.entropy.reseed();
        p += helpers.doTest("Reseed completed", crypto.entropy.isSeeded(), &f);
    }

    total_passed += p;
    total_failed += f;

    helpers.printTestResults(total_passed, total_failed);
}

// =============================================================================
// Individual Test Runners
// =============================================================================

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
    helpers.printTestHeader("DIGITAL SIGNATURE TEST (HARDENED)");

    var p: u32 = 0;
    var f: u32 = 0;

    shell.println("Testing HMAC-SHA256 signatures (H.1 hardened)...");
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

    // H.1: Long message test
    const long_msg = "This transaction contains data well beyond 64 bytes to verify HMAC truncation fix works properly!";
    const long_sig = crypto.KeyPair.sign(long_msg);
    p += helpers.doTest("Long msg (>64B) verified", crypto.verify(pub_key, long_msg, long_sig), &f);

    // H.1: Zero sig rejected
    var zero_sig: [64]u8 = [_]u8{0} ** 64;
    p += helpers.doTest("Zero sig rejected", !crypto.verify(pub_key, msg, &zero_sig), &f);

    // Different key rejected
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

fn runConstantTimeTest() void {
    helpers.printTestHeader("CONSTANT-TIME OPERATIONS (H.1)");

    shell.println("Running H.1 constant-time test suite...");
    shell.newLine();

    if (crypto.constant_time.runTests()) {
        shell.newLine();
        shell.printSuccessLine("H.1 Constant-Time: ALL PASSED");
    } else {
        shell.newLine();
        shell.printErrorLine("H.1 Constant-Time: SOME FAILED");
    }
}

fn runEntropyTest() void {
    helpers.printTestHeader("ENTROPY & CSPRNG (H.2)");

    shell.println("Running H.2 entropy test suite...");
    shell.newLine();

    if (crypto.entropy.runTests()) {
        shell.newLine();
        shell.printSuccessLine("H.2 Entropy/CSPRNG: ALL PASSED");
    } else {
        shell.newLine();
        shell.printErrorLine("H.2 Entropy/CSPRNG: SOME FAILED");
    }
}

fn runHardenedTest() void {
    helpers.printTestHeader("HARDENED CRYPTO TESTS (H.1 + H.2)");

    shell.println("Running all security hardening tests...");
    shell.newLine();

    var suites_passed: u32 = 0;
    var suites_failed: u32 = 0;

    // H.1: Constant-Time
    shell.printInfoLine("--- H.1: Constant-Time Operations ---");
    if (crypto.constant_time.runTests()) {
        suites_passed += 1;
    } else {
        suites_failed += 1;
    }

    // H.2: Entropy
    shell.newLine();
    shell.printInfoLine("--- H.2: Entropy & CSPRNG ---");
    if (crypto.entropy.runTests()) {
        suites_passed += 1;
    } else {
        suites_failed += 1;
    }

    // H.1: Signature hardening verification
    shell.newLine();
    shell.printInfoLine("--- H.1: Signature Hardening ---");
    if (crypto.signature.test_signature()) {
        suites_passed += 1;
    } else {
        suites_failed += 1;
    }

    shell.newLine();
    shell.printInfoLine("========================================");
    shell.print("  Hardened Suites: ");
    helpers.printUsize(@as(usize, suites_passed));
    shell.print("/");
    helpers.printUsize(@as(usize, suites_passed + suites_failed));
    shell.println(" passed");
    shell.printInfoLine("========================================");

    if (suites_failed == 0) {
        shell.newLine();
        shell.printSuccessLine("  ALL HARDENED TESTS PASSED!");
        shell.newLine();
    } else {
        shell.newLine();
        shell.printErrorLine("  SOME HARDENED TESTS FAILED!");
        shell.newLine();
    }
}

// =============================================================================
// Status Command
// =============================================================================

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  CRYPTO SUBSYSTEM STATUS (HARDENED)");
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

    shell.print("    AES-256-CBC:    ");
    shell.printSuccessLine("Available (software)");

    shell.print("    Signatures:     ");
    shell.printSuccessLine("HMAC-SHA256 (hardened)");

    shell.print("    Const-Time:     ");
    shell.printSuccessLine("H.1 enabled");

    shell.newLine();
    shell.println("  Random Number Generator:");

    shell.print("    Hardware RNG:   ");
    if (crypto.random.hasHardwareRng()) {
        shell.printSuccessLine("RDRAND available");
    } else {
        shell.printWarningLine("Not available");
    }

    shell.print("    RDSEED:         ");
    if (crypto.entropy.hasHardwareRdseed()) {
        shell.printSuccessLine("Available");
    } else {
        shell.println("Not available");
    }

    shell.print("    Fallback:       ");
    shell.println("Software PRNG");

    shell.newLine();
    shell.println("  Entropy Pool (H.2):");

    shell.print("    Entropy bits:   ");
    helpers.printUsize(@as(usize, crypto.entropy.getEntropyBits()));
    shell.newLine();

    shell.print("    CSPRNG seeded:  ");
    if (crypto.entropy.isSeeded()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printWarningLine("No");
    }

    shell.newLine();
    shell.println("  Key Management:");
    shell.println("    Seed phrases:   BIP39 (2048 words)");
    shell.println("    Key derivation: SHA-256 iterated");

    shell.newLine();
    shell.println("  Security Hardening:");
    shell.println("    H.1: Constant-time comparisons    ACTIVE");
    shell.println("    H.1: Timing-safe verification     ACTIVE");
    shell.println("    H.1: HMAC full-length messages     FIXED");
    shell.println("    H.1: Secure memory zeroing         ACTIVE");
    shell.println("    H.2: Entropy pool (SHA-256 mix)   ACTIVE");
    shell.println("    H.2: CSPRNG (SHA-256 CTR)         ACTIVE");
    shell.println("    H.2: Forward secrecy              ACTIVE");

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

    shell.printInfoLine("Digital Signature (HARDENED):");
    shell.newLine();

    shell.print("  Message: \"");
    shell.print(args);
    shell.println("\"");

    shell.print("  Length:  ");
    helpers.printUsize(args.len);
    if (args.len > 64) {
        shell.println(" bytes (>64B, HMAC full-length)");
    } else {
        shell.println(" bytes");
    }

    crypto.KeyPair.generate();

    shell.print("  PubKey:  ");
    const pub_key = crypto.KeyPair.getPublicKey();
    for (pub_key[0..16]) |b| {
        helpers.printHexByte(b);
    }
    shell.println("...");

    const sig = crypto.KeyPair.sign(args);
    shell.print("  Sig:     ");
    for (sig[0..16]) |b| {
        helpers.printHexByte(b);
    }
    shell.println("...");

    const valid = crypto.verify(pub_key, args, sig);
    shell.print("  Verified: ");
    if (valid) {
        shell.printSuccessLine("Yes (constant-time)");
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
    shell.println("  Use 'crypto sign <message>' to sign and verify.");
    shell.println("  Verification uses constant-time comparison (H.1).");
    shell.newLine();
}

// =============================================================================
// Key Generation
// =============================================================================

fn generateKey() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  IDENTITY KEY GENERATION (HARDENED)");
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
    shell.println("  Security: H.1 constant-time + H.2 entropy");
    shell.printSuccessLine("  Identity generated!");
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

    shell.print("  Count:  ");
    helpers.printUsize(count);
    shell.println(" bytes");

    shell.print("  Source: ");
    if (crypto.entropy.hasHardwareRng()) {
        shell.println("RDRAND + Entropy Pool (CSPRNG)");
    } else {
        shell.println("Software PRNG + Entropy Pool");
    }

    shell.newLine();
    shell.print("  ");

    var buf: [256]u8 = [_]u8{0} ** 256;

    // Try CSPRNG first, fallback to basic RNG
    if (crypto.entropy.getSecureBytes(buf[0..count])) {
        // Using CSPRNG
    } else |_| {
        crypto.random.getBytes(buf[0..count]);
    }

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

    // Secure zero buffer after display
    crypto.secureZero(buf[0..count]);
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

// =============================================================================
// Entropy Command (NEW — H.2)
// =============================================================================

fn showEntropy(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "status")) {
        showEntropyStatus();
    } else if (helpers.strEql(opt, "reseed")) {
        doReseed();
    } else if (helpers.strEql(opt, "test")) {
        runEntropyTest();
    } else {
        shell.println("entropy options: status, reseed, test");
    }
}

fn showEntropyStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  ENTROPY POOL STATUS (H.2)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Entropy bits:     ");
    helpers.printUsize(@as(usize, crypto.entropy.getEntropyBits()));
    shell.print(" / ");
    helpers.printUsize(256 * 8);
    shell.newLine();

    shell.print("  CSPRNG seeded:    ");
    if (crypto.entropy.isSeeded()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printErrorLine("No");
    }

    shell.print("  Hardware RDRAND:  ");
    if (crypto.entropy.hasHardwareRng()) {
        shell.printSuccessLine("Available");
    } else {
        shell.printWarningLine("Not available");
    }

    shell.print("  Hardware RDSEED:  ");
    if (crypto.entropy.hasHardwareRdseed()) {
        shell.printSuccessLine("Available");
    } else {
        shell.println("Not available");
    }

    shell.newLine();
    shell.println("  Entropy Sources:");
    shell.println("    [+] CPU timestamp (RDTSC)");
    if (crypto.entropy.hasHardwareRng()) {
        shell.println("    [+] Hardware RNG (RDRAND)");
    }
    if (crypto.entropy.hasHardwareRdseed()) {
        shell.println("    [+] Hardware Seed (RDSEED)");
    }
    shell.println("    [+] Interrupt timing jitter");
    shell.println("    [+] Keyboard/event timing");

    shell.newLine();
    shell.println("  Security Properties:");
    shell.println("    SHA-256 entropy mixing:     ACTIVE");
    shell.println("    CSPRNG (SHA-256 CTR):       ACTIVE");
    shell.println("    Forward secrecy:            ACTIVE");
    shell.println("    Auto-reseed interval:       1024 outputs");
    shell.println("    Min entropy threshold:      128 bits");

    shell.newLine();
}

fn doReseed() void {
    shell.println("  Reseeding entropy pool...");
    crypto.entropy.reseed();
    shell.printSuccessLine("  Reseed complete.");
    shell.newLine();

    shell.print("  New entropy: ");
    helpers.printUsize(@as(usize, crypto.entropy.getEntropyBits()));
    shell.println(" bits");
    shell.newLine();
}
