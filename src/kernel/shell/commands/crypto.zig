//! Zamrud OS - Crypto Commands
//! H.1/H.2 hardened primitives, H.10 SLOR KEM, H.11 stream protection,
//! and ML-DSA-65 production signature status.

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const crypto = @import("../../crypto/crypto.zig");
const slor = @import("../../crypto/slor.zig");
const gov_sign = @import("../../crypto/gov_sign.zig");
const keys = @import("../../crypto/keys.zig");

var seed_output: [keys.SEED_SIZE]u8 = [_]u8{0} ** keys.SEED_SIZE;

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
        generateSeed();
    } else if (helpers.strEql(parsed.cmd, "random")) {
        generateRandom(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "seed")) {
        showSeedPhrase();
    } else if (helpers.strEql(parsed.cmd, "entropy")) {
        showEntropy(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "otp")) {
        demoOtp(parsed.rest);
    } else {
        shell.printError("crypto: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'crypto help'");
    }
}

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  CRYPTO - Unified Cryptography");
    shell.printInfoLine("========================================");
    shell.newLine();
    shell.println("Usage: crypto <command> [args]");
    shell.println("  status          Show subsystem status");
    shell.println("  hash <text>     Compute SHA-256");
    shell.println("  sign <text>     Show production signing guidance");
    shell.println("  verify          Show production verification guidance");
    shell.println("  keygen          Generate mnemonic and seed fingerprint");
    shell.println("  random [n]      Generate random bytes");
    shell.println("  seed            Generate a seed phrase");
    shell.println("  entropy [cmd]   Entropy status/reseed/test");
    shell.println("  otp <text>      Stream-XOR compatibility demonstration");
    shell.println("  test [option]   Run crypto tests");
    shell.newLine();
    shell.println("Test options: all, quick, hash, random, sign, seed,");
    shell.println("              ct, entropy, hardened, slor");
}

pub fn runTest(args: []const u8) void {
    const option = helpers.trim(args);

    if (option.len == 0 or helpers.strEql(option, "all")) {
        runAllTests();
    } else if (helpers.strEql(option, "quick")) {
        runQuickTest();
    } else if (helpers.strEql(option, "hash")) {
        runHashTest();
    } else if (helpers.strEql(option, "random")) {
        runRandomTest();
    } else if (helpers.strEql(option, "sign")) {
        runSignTest();
    } else if (helpers.strEql(option, "seed")) {
        runSeedTest();
    } else if (helpers.strEql(option, "ct")) {
        runConstantTimeTest();
    } else if (helpers.strEql(option, "entropy")) {
        runEntropyTest();
    } else if (helpers.strEql(option, "hardened")) {
        runHardenedTest();
    } else if (helpers.strEql(option, "slor")) {
        _ = slor.test_slor();
    } else {
        shell.println("crypto test: all, quick, hash, random, sign, seed,");
        shell.println("             ct, entropy, hardened, slor");
    }
}

fn runAllTests() void {
    helpers.printTestHeader("CRYPTO TEST SUITE (UNIFIED)");
    var passed: u32 = 0;
    var failed: u32 = 0;

    passed += helpers.doTest(
        "SHA-256 known prefix",
        crypto.sha256("")[0] == 0xe3,
        &failed,
    );

    var random_bytes: [16]u8 = [_]u8{0} ** 16;
    crypto.random.getBytes(&random_bytes);
    passed += helpers.doTest(
        "RNG output non-zero",
        !crypto.constantTimeIsZero(&random_bytes),
        &failed,
    );
    crypto.secureZero(&random_bytes);

    passed += helpers.doTest("Seed phrase management", keys.test_keys(), &failed);
    passed += helpers.doTest(
        "Constant-time operations",
        crypto.constant_time.runTests(),
        &failed,
    );
    passed += helpers.doTest(
        "Entropy/CSPRNG",
        crypto.entropy.runTests(),
        &failed,
    );
    passed += helpers.doTest("SLOR KEM", slor.test_slor(), &failed);
    passed += helpers.doTest(
        "ML-DSA-65 production backend",
        gov_sign.isProductionBackendAvailable(),
        &failed,
    );
    passed += helpers.doTest("Stream protection", crypto.otp.test_otp(), &failed);

    helpers.printTestResults(passed, failed);
}

fn runQuickTest() void {
    var ok = true;
    shell.printInfoLine("Crypto Quick Test...");

    if (!crypto.isInitialized()) ok = false;
    if (crypto.sha256("test")[0] == 0) ok = false;
    if (!gov_sign.isProductionBackendAvailable()) ok = false;

    shell.print("  ML-DSA-65: ");
    if (gov_sign.isProductionBackendAvailable()) {
        shell.printSuccessLine("Operational");
    } else {
        shell.printErrorLine("Unavailable (fail-closed)");
    }

    helpers.printQuickResult("Crypto", ok);
}

fn runHashTest() void {
    var failed: u32 = 0;
    var passed: u32 = 0;
    const empty = crypto.sha256("");
    const abc = crypto.sha256("abc");
    passed += helpers.doTest("Empty SHA-256 prefix", empty[0] == 0xe3, &failed);
    passed += helpers.doTest("abc SHA-256 prefix", abc[0] == 0xba, &failed);
    helpers.printTestResults(passed, failed);
}

fn runRandomTest() void {
    var first: [32]u8 = [_]u8{0} ** 32;
    var second: [32]u8 = [_]u8{0} ** 32;
    defer crypto.secureZero(&first);
    defer crypto.secureZero(&second);

    crypto.random.getBytes(&first);
    crypto.random.getBytes(&second);

    var failed: u32 = 0;
    var passed: u32 = 0;
    passed += helpers.doTest(
        "Output non-zero",
        !crypto.constantTimeIsZero(&first),
        &failed,
    );
    passed += helpers.doTest(
        "Sequential outputs differ",
        !crypto.constantTimeCompare32(&first, &second),
        &failed,
    );
    helpers.printTestResults(passed, failed);
}

fn runSignTest() void {
    helpers.printTestHeader("ML-DSA-65 SIGNATURE STATUS");
    var failed: u32 = 0;
    var passed: u32 = 0;
    passed += helpers.doTest(
        "Production backend operational",
        gov_sign.isProductionBackendAvailable(),
        &failed,
    );
    helpers.printTestResults(passed, failed);
    shell.println("Use 'identity test dsa' for the complete KAT/negative suite.");
}

fn runSeedTest() void {
    var failed: u32 = 0;
    var passed: u32 = 0;
    passed += helpers.doTest("Seed phrase management", keys.test_keys(), &failed);
    helpers.printTestResults(passed, failed);
}

fn runConstantTimeTest() void {
    _ = crypto.constant_time.runTests();
}

fn runEntropyTest() void {
    _ = crypto.entropy.runTests();
}

fn runHardenedTest() void {
    helpers.printTestHeader("HARDENED CRYPTO TESTS");
    var failed: u32 = 0;
    var passed: u32 = 0;
    passed += helpers.doTest(
        "Constant-time operations",
        crypto.constant_time.runTests(),
        &failed,
    );
    passed += helpers.doTest(
        "Entropy/CSPRNG",
        crypto.entropy.runTests(),
        &failed,
    );
    passed += helpers.doTest(
        "ML-DSA-65 health gate",
        gov_sign.isProductionBackendAvailable(),
        &failed,
    );
    helpers.printTestResults(passed, failed);
}

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  CRYPTO SUBSYSTEM STATUS");
    shell.printInfoLine("========================================");
    shell.println("  SHA-256:        Available");
    shell.println("  AES-256-CBC:    Available (legacy storage mode)");
    shell.println("  SLOR KEM:       Integrated");
    shell.print("  ML-DSA-65:     ");
    if (gov_sign.isProductionBackendAvailable()) {
        shell.printSuccessLine("Operational");
    } else {
        shell.printErrorLine("Unavailable (fail-closed)");
    }
    shell.println("  Stream cipher:  Compatibility mode; AEAD upgrade pending");
    shell.println("  Signature API:  gov_sign.zig only");
}

fn computeHash(args: []const u8) void {
    if (args.len == 0) {
        shell.printErrorLine("Usage: crypto hash <text>");
        return;
    }

    const result = crypto.sha256(args);
    shell.print("SHA-256: ");
    for (result) |byte| helpers.printHexByte(byte);
    shell.newLine();
}

fn signMessage(args: []const u8) void {
    _ = args;
    shell.printWarningLine("Direct shell key generation/signing is disabled.");
    shell.println("Production signing uses the unlocked identity via gov_sign.zig.");
    shell.println("Run 'identity test dsa' to verify the ML-DSA-65 backend.");
}

fn verifySignature(_: []const u8) void {
    shell.println("Verification is performed by typed consumers through gov_sign.zig.");
    shell.println("Legacy 32-byte/64-byte HMAC signatures are not production-trusted.");
}

fn generateSeed() void {
    const phrase = keys.SeedPhrase.generate();
    printPhrase(&phrase);
    phrase.deriveSeed(&seed_output);

    shell.print("  Seed fingerprint: ");
    const fingerprint = crypto.sha256(&seed_output);
    for (fingerprint[0..8]) |byte| helpers.printHexByte(byte);
    shell.println("...");

    crypto.secureZero32(&seed_output);
    shell.println("  Use 'identity create' for managed identity/key generation.");
}

fn showSeedPhrase() void {
    const phrase = keys.SeedPhrase.generate();
    printPhrase(&phrase);
}

fn printPhrase(phrase: *const keys.SeedPhrase) void {
    shell.printWarningLine("Back up this seed phrase securely:");
    var i: usize = 0;
    while (i < phrase.word_count) : (i += 1) {
        shell.print("  ");
        helpers.printUsize(i + 1);
        shell.print(". ");
        shell.println(phrase.getWordAt(i));
    }
}

fn generateRandom(args: []const u8) void {
    var count: usize = 16;
    if (args.len > 0) count = helpers.parseU32(args) orelse 16;
    if (count == 0) count = 16;
    if (count > 256) count = 256;

    var buffer: [256]u8 = [_]u8{0} ** 256;
    defer crypto.secureZero(&buffer);

    if (crypto.entropy.getSecureBytes(buffer[0..count])) {
        // CSPRNG output ready.
    } else |_| {
        crypto.random.getBytes(buffer[0..count]);
    }

    for (buffer[0..count]) |byte| helpers.printHexByte(byte);
    shell.newLine();
}

fn showEntropy(args: []const u8) void {
    const option = helpers.trim(args);
    if (option.len == 0 or helpers.strEql(option, "status")) {
        shell.print("Entropy bits: ");
        helpers.printUsize(@as(usize, crypto.entropy.getEntropyBits()));
        shell.newLine();
    } else if (helpers.strEql(option, "reseed")) {
        crypto.entropy.reseed();
        shell.printSuccessLine("Entropy pool reseeded");
    } else if (helpers.strEql(option, "test")) {
        runEntropyTest();
    } else {
        shell.println("entropy options: status, reseed, test");
    }
}

fn demoOtp(args: []const u8) void {
    if (args.len == 0) {
        shell.printErrorLine("Usage: crypto otp <text>");
        return;
    }

    const shared_secret = "ZamrudCompatibilitySecret";
    var buffer: [256]u8 = [_]u8{0} ** 256;
    defer crypto.secureZero(&buffer);

    const length = @min(args.len, buffer.len);
    @memcpy(buffer[0..length], args[0..length]);

    var encrypt_stream = crypto.OtpStream.init(shared_secret);
    encrypt_stream.process(buffer[0..length]);
    encrypt_stream.destroy();

    shell.print("Encrypted: ");
    for (buffer[0..length]) |byte| helpers.printHexByte(byte);
    shell.newLine();

    var decrypt_stream = crypto.OtpStream.init(shared_secret);
    decrypt_stream.process(buffer[0..length]);
    decrypt_stream.destroy();

    shell.print("Decrypted: ");
    shell.println(buffer[0..length]);
    shell.println("Note: this is a deterministic stream demo, not a strict OTP proof.");
}
