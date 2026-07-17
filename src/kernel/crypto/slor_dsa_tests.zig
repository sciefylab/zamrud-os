//! Zamrud OS - SLOR-DSA / ML-DSA-65 complete test aggregator.
//!
//! Purpose:
//! - Force compilation of every native ML-DSA-65 module.
//! - Run primitive, functional, adversarial, and optional external KAT tests.
//! - Keep the production backend fail-closed when the external KAT gate has
//!   not been provisioned or does not pass.
//!
//! Production modules must use gov_sign.zig. This file is test-only.

const serial = @import("../drivers/serial/serial.zig");

const keccak = @import("keccak.zig");
const params = @import("slor_dsa_params.zig");
const reduce = @import("slor_dsa_reduce.zig");
const ntt = @import("slor_dsa_ntt.zig");
const poly = @import("slor_dsa_poly.zig");
const rounding = @import("slor_dsa_rounding.zig");
const sampling = @import("slor_dsa_sampling.zig");
const packing = @import("slor_dsa_pack.zig");
const keygen = @import("slor_dsa_keygen.zig");
const signing = @import("slor_dsa_sign.zig");
const verification = @import("slor_dsa_verify.zig");
const kat = @import("slor_dsa_kat.zig");
const negative_tests = @import("slor_dsa_negative_tests.zig");

const PublicKeyBytes = packing.PublicKeyBytes;
const SecretKeyBytes = packing.SecretKeyBytes;
const SignatureBytes = packing.SignatureBytes;

// Large objects remain in static test storage instead of the kernel stack.
var test_seed_1: keygen.KeyGenerationSeed =
    [_]u8{0} ** params.SEED_BYTES;
var test_seed_2: keygen.KeyGenerationSeed =
    [_]u8{0} ** params.SEED_BYTES;

var public_key_1: PublicKeyBytes =
    [_]u8{0} ** params.PUBLIC_KEY_BYTES;
var secret_key_1: SecretKeyBytes =
    [_]u8{0} ** params.SECRET_KEY_BYTES;
var public_key_2: PublicKeyBytes =
    [_]u8{0} ** params.PUBLIC_KEY_BYTES;
var secret_key_2: SecretKeyBytes =
    [_]u8{0} ** params.SECRET_KEY_BYTES;

var signature_1: SignatureBytes =
    [_]u8{0} ** params.SIGNATURE_BYTES;
var signature_2: SignatureBytes =
    [_]u8{0} ** params.SIGNATURE_BYTES;
var mutated_signature: SignatureBytes =
    [_]u8{0} ** params.SIGNATURE_BYTES;
var zero_signature: SignatureBytes =
    [_]u8{0} ** params.SIGNATURE_BYTES;

const test_message = "Zamrud OS ML-DSA-65 functional test message";
const modified_message = "Zamrud OS ML-DSA-65 functional test messagf";
const test_context = "ZAMRUD-GOV.2-TEST";
const wrong_context = "ZAMRUD-GOV.2-WRONG";

pub fn runAll() bool {
    serial.writeString("\n");
    serial.writeString("========================================\n");
    serial.writeString("  SLOR-DSA / ML-DSA-65 TESTS\n");
    serial.writeString("========================================\n");

    clearTestWorkspace();
    initializeSeeds();

    var passed: u32 = 0;
    var failed: u32 = 0;
    var kat_ready = false;

    runOne("Keccak / SHAKE", keccak.selfTest(), &passed, &failed);
    runOne("ML-DSA-65 parameters", params.selfTest(), &passed, &failed);
    runOne("Modular reduction", reduce.selfTest(), &passed, &failed);

    const ntt_results = ntt.getSelfTestResults();
    const ntt_ok = ntt_results.allPassed();
    runOne("NTT / inverse NTT", ntt_ok, &passed, &failed);
    if (!ntt_ok) printNttDiagnostics(ntt_results);

    runOne("Polynomial arithmetic", poly.selfTest(), &passed, &failed);
    runOne("Rounding and hints", rounding.selfTest(), &passed, &failed);
    runOne("Sampling", sampling.selfTest(), &passed, &failed);
    runOne("Canonical packing", packing.selfTest(), &passed, &failed);
    runOne("Key generation", keygen.selfTest(), &passed, &failed);

    const keys_ready = generateFunctionalTestKeys();
    runOne("Functional test keypairs", keys_ready, &passed, &failed);

    if (keys_ready) {
        runFunctionalTests(&passed, &failed);
    } else {
        skipFunctionalTests(&failed);
    }

    runOne(
        "Canonical negative suite",
        negative_tests.selfTest(),
        &passed,
        &failed,
    );

    if (kat.vectorsProvisioned()) {
        kat_ready = kat.selfTest();
        runOne("External ACVP KAT", kat_ready, &passed, &failed);
    } else {
        printStatus("External ACVP KAT", "NOT PROVISIONED");
    }

    serial.writeString("----------------------------------------\n");
    serial.writeString("Results: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed\n");
    serial.writeString("========================================\n");

    clearTestWorkspace();

    if (failed != 0) {
        serial.writeString(
            "[SLOR_DSA_TEST] Tests FAILED; backend must remain fail-closed\n",
        );
        return false;
    }

    serial.writeString(
        "[SLOR_DSA_TEST] Functional and negative tests PASSED\n",
    );

    if (kat_ready) {
        serial.writeString("[SLOR_DSA_TEST] External ACVP KAT PASSED\n");
        serial.writeString(
            "[SLOR_DSA_TEST] Backend eligible for facade health gate\n",
        );
    } else {
        serial.writeString(
            "[SLOR_DSA_TEST] External ACVP KAT NOT PROVISIONED\n",
        );
        serial.writeString(
            "[SLOR_DSA_TEST] Backend remains functional_ready / fail-closed\n",
        );
    }

    // This return value means all currently executable tests passed. It does
    // not mean the production backend is operational. slor_dsa.zig must check
    // kat.vectorsProvisioned() and kat.selfTest() separately.
    return true;
}

fn runFunctionalTests(passed: *u32, failed: *u32) void {
    const deterministic_sign_ok = signing.signDeterministic(
        &signature_1,
        test_message,
        test_context,
        &secret_key_1,
    );
    runOne("Deterministic signing", deterministic_sign_ok, passed, failed);

    const second_sign_ok = signing.signDeterministic(
        &signature_2,
        test_message,
        test_context,
        &secret_key_1,
    );

    runOne(
        "Deterministic repeatability",
        deterministic_sign_ok and second_sign_ok and
            constantTimeEqual(&signature_1, &signature_2),
        passed,
        failed,
    );

    const valid_signature = deterministic_sign_ok and verification.verify(
        &signature_1,
        test_message,
        test_context,
        &public_key_1,
    );
    runOne("Sign / verify", valid_signature, passed, failed);

    runOne(
        "Modified message rejected",
        deterministic_sign_ok and !verification.verify(
            &signature_1,
            modified_message,
            test_context,
            &public_key_1,
        ),
        passed,
        failed,
    );

    runOne(
        "Wrong context rejected",
        deterministic_sign_ok and !verification.verify(
            &signature_1,
            test_message,
            wrong_context,
            &public_key_1,
        ),
        passed,
        failed,
    );

    runOne(
        "Wrong public key rejected",
        deterministic_sign_ok and !verification.verify(
            &signature_1,
            test_message,
            test_context,
            &public_key_2,
        ),
        passed,
        failed,
    );

    mutated_signature = signature_1;
    mutated_signature[0] ^= 0x01;
    runOne(
        "Mutated challenge rejected",
        deterministic_sign_ok and !verification.verify(
            &mutated_signature,
            test_message,
            test_context,
            &public_key_1,
        ),
        passed,
        failed,
    );

    mutated_signature = signature_1;
    mutated_signature[params.CTILDE_BYTES] ^= 0x01;
    runOne(
        "Mutated z rejected",
        deterministic_sign_ok and !verification.verify(
            &mutated_signature,
            test_message,
            test_context,
            &public_key_1,
        ),
        passed,
        failed,
    );

    mutated_signature = signature_1;
    const hint_start = params.CTILDE_BYTES +
        params.L * params.POLY_Z_PACKED_BYTES;
    mutated_signature[hint_start + params.OMEGA] =
        @intCast(params.OMEGA + 1);
    runOne(
        "Malformed hints rejected",
        deterministic_sign_ok and !verification.verify(
            &mutated_signature,
            test_message,
            test_context,
            &public_key_1,
        ),
        passed,
        failed,
    );

    @memset(zero_signature[0..], 0);
    runOne(
        "All-zero signature rejected",
        !verification.verify(
            &zero_signature,
            test_message,
            test_context,
            &public_key_1,
        ),
        passed,
        failed,
    );

    const oversized_context = [_]u8{0x41} ** 256;
    runOne(
        "Oversized context rejected",
        !signing.signDeterministic(
            &signature_2,
            test_message,
            &oversized_context,
            &secret_key_1,
        ) and !verification.verify(
            &signature_1,
            test_message,
            &oversized_context,
            &public_key_1,
        ),
        passed,
        failed,
    );

    const randomized_sign_ok = signing.signRandomized(
        &signature_2,
        test_message,
        test_context,
        &secret_key_1,
    );
    runOne(
        "Randomized sign / verify",
        randomized_sign_ok and verification.verify(
            &signature_2,
            test_message,
            test_context,
            &public_key_1,
        ),
        passed,
        failed,
    );
}

fn generateFunctionalTestKeys() bool {
    if (!keygen.generateFromSeed(
        &public_key_1,
        &secret_key_1,
        &test_seed_1,
    )) return false;

    if (!keygen.generateFromSeed(
        &public_key_2,
        &secret_key_2,
        &test_seed_2,
    )) return false;

    return !constantTimeEqual(&public_key_1, &public_key_2);
}

fn initializeSeeds() void {
    var index: usize = 0;
    while (index < params.SEED_BYTES) : (index += 1) {
        test_seed_1[index] = @truncate(index * 7 + 1);
        test_seed_2[index] = @truncate(index * 11 + 3);
    }
}

fn skipFunctionalTests(failed: *u32) void {
    const skipped: u32 = 12;
    serial.writeString(
        "  Functional tests skipped: key generation failed\n",
    );
    failed.* += skipped;
}

fn printNttDiagnostics(results: ntt.SelfTestResults) void {
    serial.writeString("\n");
    serial.writeString("  NTT diagnostics:\n");
    printDiagnostic("Reduction dependency", results.reduction);
    printDiagnostic("Known zeta constants", results.known_zetas);
    printDiagnostic("Zero polynomial", results.zero_polynomial);
    printDiagnostic("Forward / inverse", results.forward_inverse);
    printDiagnostic("Pointwise zero", results.pointwise_zero);
    printDiagnostic(
        "Polynomial multiplication",
        results.polynomial_multiplication,
    );
    serial.writeString("\n");
}

fn printDiagnostic(name: []const u8, result: bool) void {
    serial.writeString("    ");
    serial.writeString(name);
    serial.writeString(": ");
    serial.writeString(if (result) "PASS\n" else "FAIL\n");
}

fn printStatus(name: []const u8, status: []const u8) void {
    serial.writeString("  ");
    serial.writeString(name);

    const target_width: usize = 31;
    var padding: usize = if (name.len < target_width)
        target_width - name.len
    else
        1;

    while (padding > 0) : (padding -= 1) {
        serial.writeChar('.');
    }

    serial.writeChar(' ');
    serial.writeString(status);
    serial.writeChar('\n');
}

fn runOne(
    name: []const u8,
    result: bool,
    passed: *u32,
    failed: *u32,
) void {
    serial.writeString("  ");
    serial.writeString(name);

    const target_width: usize = 31;
    var padding: usize = if (name.len < target_width)
        target_width - name.len
    else
        1;

    while (padding > 0) : (padding -= 1) {
        serial.writeChar('.');
    }

    if (result) {
        serial.writeString(" PASS\n");
        passed.* += 1;
    } else {
        serial.writeString(" FAIL\n");
        failed.* += 1;
    }
}

fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var difference: u8 = 0;
    var index: usize = 0;
    while (index < left.len) : (index += 1) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

fn clearTestWorkspace() void {
    @memset(test_seed_1[0..], 0);
    @memset(test_seed_2[0..], 0);
    @memset(public_key_1[0..], 0);
    @memset(secret_key_1[0..], 0);
    @memset(public_key_2[0..], 0);
    @memset(secret_key_2[0..], 0);
    @memset(signature_1[0..], 0);
    @memset(signature_2[0..], 0);
    @memset(mutated_signature[0..], 0);
    @memset(zero_signature[0..], 0);
}

fn printU32(value: u32) void {
    if (value == 0) {
        serial.writeChar('0');
        return;
    }

    var buffer: [10]u8 = undefined;
    var count: usize = 0;
    var remaining = value;

    while (remaining > 0) : (count += 1) {
        buffer[count] = @intCast((remaining % 10) + '0');
        remaining /= 10;
    }

    while (count > 0) {
        count -= 1;
        serial.writeChar(buffer[count]);
    }
}
