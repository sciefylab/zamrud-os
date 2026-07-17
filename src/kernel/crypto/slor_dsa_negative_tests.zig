//! Zamrud OS - ML-DSA-65 adversarial and canonical-decoding tests.
//!
//! Test-only module. It imports native keygen/sign/verify directly so Zig
//! compiles every path. Production consumers must use gov_sign.zig.

const params = @import("slor_dsa_params.zig");
const keygen = @import("slor_dsa_keygen.zig");
const signing = @import("slor_dsa_sign.zig");
const verification = @import("slor_dsa_verify.zig");
const packing = @import("slor_dsa_pack.zig");

pub const Results = struct {
    setup: bool,
    valid_control: bool,
    modified_message: bool,
    wrong_context: bool,
    wrong_key: bool,
    challenge_mutation: bool,
    z_mutation: bool,
    duplicate_hint: bool,
    descending_hint: bool,
    decreasing_endpoint: bool,
    endpoint_overflow: bool,
    nonzero_unused_hint: bool,
    all_zero_signature: bool,
    all_zero_public_key: bool,
    public_key_mutation: bool,
    oversized_context: bool,

    pub fn allPassed(self: Results) bool {
        return self.setup and self.valid_control and
            self.modified_message and self.wrong_context and self.wrong_key and
            self.challenge_mutation and self.z_mutation and
            self.duplicate_hint and self.descending_hint and
            self.decreasing_endpoint and self.endpoint_overflow and
            self.nonzero_unused_hint and self.all_zero_signature and
            self.all_zero_public_key and self.public_key_mutation and
            self.oversized_context;
    }
};

const message = "Zamrud ML-DSA negative test";
const altered_message = "Zamrud ML-DSA negative tesu";
const context = "ZAMRUD-GOV.2-NEGATIVE";
const other_context = "ZAMRUD-GOV.2-OTHER";
const HINT_START: usize = params.CTILDE_BYTES +
    params.L * params.POLY_Z_PACKED_BYTES;
const ENDPOINT_START: usize = HINT_START + params.OMEGA;

var seed_a: keygen.KeyGenerationSeed = [_]u8{0} ** params.SEED_BYTES;
var seed_b: keygen.KeyGenerationSeed = [_]u8{0} ** params.SEED_BYTES;
var pk_a: packing.PublicKeyBytes = [_]u8{0} ** params.PUBLIC_KEY_BYTES;
var sk_a: packing.SecretKeyBytes = [_]u8{0} ** params.SECRET_KEY_BYTES;
var pk_b: packing.PublicKeyBytes = [_]u8{0} ** params.PUBLIC_KEY_BYTES;
var sk_b: packing.SecretKeyBytes = [_]u8{0} ** params.SECRET_KEY_BYTES;
var valid_signature: packing.SignatureBytes = [_]u8{0} ** params.SIGNATURE_BYTES;
var candidate: packing.SignatureBytes = [_]u8{0} ** params.SIGNATURE_BYTES;
var zero_signature: packing.SignatureBytes = [_]u8{0} ** params.SIGNATURE_BYTES;
var zero_public_key: packing.PublicKeyBytes = [_]u8{0} ** params.PUBLIC_KEY_BYTES;
var mutated_public_key: packing.PublicKeyBytes = [_]u8{0} ** params.PUBLIC_KEY_BYTES;

pub fn run() Results {
    clearWorkspace();
    defer clearWorkspace();
    initializeSeeds();

    const setup = keygen.generateFromSeed(&pk_a, &sk_a, &seed_a) and
        keygen.generateFromSeed(&pk_b, &sk_b, &seed_b) and
        signing.signDeterministic(
            &valid_signature,
            message,
            context,
            &sk_a,
        );

    if (!setup) return failedSetupResult();

    const valid_control = verification.verify(
        &valid_signature,
        message,
        context,
        &pk_a,
    );

    const modified_message_ok = !verification.verify(
        &valid_signature,
        altered_message,
        context,
        &pk_a,
    );

    const wrong_context_ok = !verification.verify(
        &valid_signature,
        message,
        other_context,
        &pk_a,
    );

    const wrong_key_ok = !verification.verify(
        &valid_signature,
        message,
        context,
        &pk_b,
    );

    candidate = valid_signature;
    candidate[0] ^= 1;
    const challenge_mutation_ok = rejects(&candidate);

    candidate = valid_signature;
    candidate[params.CTILDE_BYTES] ^= 1;
    const z_mutation_ok = rejects(&candidate);

    // Construct canonical-decoding failures directly in the hint encoding.
    // Endpoint[0] = 2 means the first two index bytes belong to row zero.
    candidate = valid_signature;
    zeroHintArea(&candidate);
    candidate[HINT_START] = 7;
    candidate[HINT_START + 1] = 7;
    candidate[ENDPOINT_START] = 2;
    fillRemainingEndpoints(&candidate, 2);
    const duplicate_hint_ok = rejects(&candidate);

    candidate = valid_signature;
    zeroHintArea(&candidate);
    candidate[HINT_START] = 9;
    candidate[HINT_START + 1] = 3;
    candidate[ENDPOINT_START] = 2;
    fillRemainingEndpoints(&candidate, 2);
    const descending_hint_ok = rejects(&candidate);

    candidate = valid_signature;
    zeroHintArea(&candidate);
    candidate[ENDPOINT_START] = 2;
    candidate[ENDPOINT_START + 1] = 1;
    var endpoint_index: usize = 2;
    while (endpoint_index < params.K) : (endpoint_index += 1) {
        candidate[ENDPOINT_START + endpoint_index] = 1;
    }
    const decreasing_endpoint_ok = rejects(&candidate);

    candidate = valid_signature;
    zeroHintArea(&candidate);
    candidate[ENDPOINT_START] = @intCast(params.OMEGA + 1);
    fillRemainingEndpoints(&candidate, params.OMEGA + 1);
    const endpoint_overflow_ok = rejects(&candidate);

    candidate = valid_signature;
    zeroHintArea(&candidate);
    candidate[HINT_START] = 1; // unused because all endpoints remain zero
    const nonzero_unused_ok = rejects(&candidate);

    @memset(zero_signature[0..], 0);
    const zero_signature_ok = rejects(&zero_signature);

    @memset(zero_public_key[0..], 0);
    const zero_public_key_ok = !verification.verify(
        &valid_signature,
        message,
        context,
        &zero_public_key,
    );

    mutated_public_key = pk_a;
    mutated_public_key[params.SEED_BYTES] ^= 1;
    const public_key_mutation_ok = !verification.verify(
        &valid_signature,
        message,
        context,
        &mutated_public_key,
    );

    const oversized = [_]u8{0x58} ** 256;
    const oversized_context_ok = !verification.verify(
        &valid_signature,
        message,
        &oversized,
        &pk_a,
    );

    return .{
        .setup = true,
        .valid_control = valid_control,
        .modified_message = modified_message_ok,
        .wrong_context = wrong_context_ok,
        .wrong_key = wrong_key_ok,
        .challenge_mutation = challenge_mutation_ok,
        .z_mutation = z_mutation_ok,
        .duplicate_hint = duplicate_hint_ok,
        .descending_hint = descending_hint_ok,
        .decreasing_endpoint = decreasing_endpoint_ok,
        .endpoint_overflow = endpoint_overflow_ok,
        .nonzero_unused_hint = nonzero_unused_ok,
        .all_zero_signature = zero_signature_ok,
        .all_zero_public_key = zero_public_key_ok,
        .public_key_mutation = public_key_mutation_ok,
        .oversized_context = oversized_context_ok,
    };
}

pub fn selfTest() bool {
    return run().allPassed();
}

fn rejects(signature: *const packing.SignatureBytes) bool {
    return !verification.verify(signature, message, context, &pk_a);
}

fn zeroHintArea(signature: *packing.SignatureBytes) void {
    @memset(signature[HINT_START..params.SIGNATURE_BYTES], 0);
}

fn fillRemainingEndpoints(signature: *packing.SignatureBytes, value: usize) void {
    var row: usize = 1;
    while (row < params.K) : (row += 1) {
        signature[ENDPOINT_START + row] = @intCast(value);
    }
}

fn initializeSeeds() void {
    var i: usize = 0;
    while (i < params.SEED_BYTES) : (i += 1) {
        seed_a[i] = @truncate(i * 13 + 5);
        seed_b[i] = @truncate(i * 17 + 9);
    }
}

fn failedSetupResult() Results {
    return .{
        .setup = false,
        .valid_control = false,
        .modified_message = false,
        .wrong_context = false,
        .wrong_key = false,
        .challenge_mutation = false,
        .z_mutation = false,
        .duplicate_hint = false,
        .descending_hint = false,
        .decreasing_endpoint = false,
        .endpoint_overflow = false,
        .nonzero_unused_hint = false,
        .all_zero_signature = false,
        .all_zero_public_key = false,
        .public_key_mutation = false,
        .oversized_context = false,
    };
}

fn clearWorkspace() void {
    @memset(seed_a[0..], 0);
    @memset(seed_b[0..], 0);
    @memset(pk_a[0..], 0);
    @memset(sk_a[0..], 0);
    @memset(pk_b[0..], 0);
    @memset(sk_b[0..], 0);
    @memset(valid_signature[0..], 0);
    @memset(candidate[0..], 0);
    @memset(zero_signature[0..], 0);
    @memset(zero_public_key[0..], 0);
    @memset(mutated_public_key[0..], 0);
}
