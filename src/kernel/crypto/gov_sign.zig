//! Zamrud OS - GOV.2 governance-signature compatibility boundary.
//!
//! This is the only public signature API for identity, authority, chain,
//! persistence, export/import, and P2P governance code.
//!
//! Backend policy:
//! - exactly one backend: slor_dsa.zig (native ML-DSA-65);
//! - no import of slor_sign.zig;
//! - no legacy verification fallback;
//! - all production operations fail closed until the backend is operational;
//! - wrapper structs preserve the V5 identity/export serialization contract.

const backend_impl = @import("slor_dsa.zig");
const constant_time = @import("constant_time.zig");

// =============================================================================
// Public constants and metadata
// =============================================================================

pub const RAW_PUBLIC_KEY_BYTES: usize = backend_impl.PUBLIC_KEY_BYTES;
pub const RAW_SECRET_KEY_BYTES: usize = backend_impl.SECRET_KEY_BYTES;
pub const RAW_SIGNATURE_BYTES: usize = backend_impl.SIGNATURE_BYTES;
pub const MAX_CONTEXT_BYTES: usize = backend_impl.MAX_CONTEXT_BYTES;

pub const PUBLIC_KEY_BYTES: usize = RAW_PUBLIC_KEY_BYTES;
pub const SECRET_KEY_BYTES: usize = RAW_SECRET_KEY_BYTES;
pub const SIGNATURE_BYTES: usize = RAW_SIGNATURE_BYTES;

pub const SERIAL_HEADER_BYTES: usize = 10;
pub const PUBLIC_KEY_BLOB_BYTES: usize = SERIAL_HEADER_BYTES + RAW_PUBLIC_KEY_BYTES;
pub const SECRET_KEY_BLOB_BYTES: usize = SERIAL_HEADER_BYTES + RAW_SECRET_KEY_BYTES;
pub const SIGNATURE_BLOB_BYTES: usize = SERIAL_HEADER_BYTES + RAW_SIGNATURE_BYTES;

pub const Backend = enum(u8) {
    none = 0,
    native_ml_dsa = 1,
};

pub const ParameterSet = enum(u8) {
    none = 0,
    ml_dsa_65 = 2,
};

pub const DEFAULT_BACKEND: Backend = .native_ml_dsa;
pub const DEFAULT_PARAMETER_SET: ParameterSet = .ml_dsa_65;

pub const BackendState = backend_impl.BackendState;
pub const Health = backend_impl.Health;

pub const VerifyResult = enum(u8) {
    valid = 0,
    invalid = 1,
    backend_unavailable = 2,
    malformed_key = 3,
    malformed_signature = 4,
    invalid_context = 5,
};

pub const DOMAIN_IDENTITY = "ZAMRUD:GOV.2:IDENTITY";
pub const DOMAIN_AUTHORITY = "ZAMRUD:GOV.2:AUTHORITY";
pub const DOMAIN_CHAIN = "ZAMRUD:GOV.2:CHAIN";
pub const DOMAIN_EVICTION_VOTE = "ZAMRUD:GOV.2:EVICTION:VOTE";
pub const DOMAIN_EVICTION_COMMIT = "ZAMRUD:GOV.2:EVICTION:COMMIT";
pub const DOMAIN_TRUST_CEREMONY = "ZAMRUD:GOV.2:CEREMONY";
pub const DOMAIN_KEY_ROTATION = "ZAMRUD:GOV.2:KEY-ROTATION";
pub const DOMAIN_EXPORT_MANIFEST = "ZAMRUD:GOV.2:EXPORT";
pub const DOMAIN_TEST = "ZAMRUD:GOV.2:TEST";

const PUBLIC_MAGIC = [4]u8{ 'G', 'P', 'K', '2' };
const SECRET_MAGIC = [4]u8{ 'G', 'S', 'K', '2' };
const SIGNATURE_MAGIC = [4]u8{ 'G', 'S', 'G', '2' };
const SERIAL_VERSION: u8 = 1;

// =============================================================================
// Compatibility containers
// =============================================================================

pub const PublicKey = struct {
    bytes: [RAW_PUBLIC_KEY_BYTES]u8 = [_]u8{0} ** RAW_PUBLIC_KEY_BYTES,
    len: usize = 0,
    valid: bool = false,
    backend: Backend = .none,
    parameter_set: ParameterSet = .none,
};

pub const SecretKey = struct {
    bytes: [RAW_SECRET_KEY_BYTES]u8 = [_]u8{0} ** RAW_SECRET_KEY_BYTES,
    len: usize = 0,
    valid: bool = false,
    backend: Backend = .none,
    parameter_set: ParameterSet = .none,
};

pub const Signature = struct {
    bytes: [RAW_SIGNATURE_BYTES]u8 = [_]u8{0} ** RAW_SIGNATURE_BYTES,
    len: usize = 0,
    valid: bool = false,
    backend: Backend = .none,
    parameter_set: ParameterSet = .none,
};

// =============================================================================
// Backend lifecycle
// =============================================================================

pub fn initialize() bool {
    return backend_impl.initialize();
}

pub fn isInitialized() bool {
    return backend_impl.isInitialized();
}

pub fn isAvailable() bool {
    return backend_impl.isAvailable();
}

pub fn isProductionBackendAvailable() bool {
    if (!backend_impl.isInitialized()) {
        _ = backend_impl.initialize();
    }
    return backend_impl.isAvailable();
}

pub fn getState() BackendState {
    return backend_impl.getState();
}

pub fn getHealth() Health {
    return backend_impl.getHealth();
}

// =============================================================================
// Key generation, signing, and verification
// =============================================================================

pub fn generateKeyPair(
    parameter_set: ParameterSet,
    public_key: *PublicKey,
    secret_key: *SecretKey,
) bool {
    clearPublicKey(public_key);
    clearSecretKey(secret_key);

    if (parameter_set != DEFAULT_PARAMETER_SET) return false;
    if (!isProductionBackendAvailable()) return false;

    if (!backend_impl.generateKeyPair(
        &public_key.bytes,
        &secret_key.bytes,
    )) {
        clearPublicKey(public_key);
        clearSecretKey(secret_key);
        return false;
    }

    public_key.len = RAW_PUBLIC_KEY_BYTES;
    public_key.valid = true;
    public_key.backend = DEFAULT_BACKEND;
    public_key.parameter_set = DEFAULT_PARAMETER_SET;

    secret_key.len = RAW_SECRET_KEY_BYTES;
    secret_key.valid = true;
    secret_key.backend = DEFAULT_BACKEND;
    secret_key.parameter_set = DEFAULT_PARAMETER_SET;
    return true;
}

pub fn sign(
    secret_key: *const SecretKey,
    domain: []const u8,
    payload: []const u8,
    signature: *Signature,
) bool {
    clearSignature(signature);

    if (!isProductionBackendAvailable()) return false;
    if (!validSecretKey(secret_key)) return false;
    if (!validDomain(domain)) return false;

    if (!backend_impl.sign(
        &signature.bytes,
        payload,
        domain,
        &secret_key.bytes,
    )) {
        clearSignature(signature);
        return false;
    }

    signature.len = RAW_SIGNATURE_BYTES;
    signature.valid = true;
    signature.backend = DEFAULT_BACKEND;
    signature.parameter_set = DEFAULT_PARAMETER_SET;
    return true;
}

pub fn verify(
    public_key: *const PublicKey,
    domain: []const u8,
    payload: []const u8,
    signature: *const Signature,
) VerifyResult {
    if (!isProductionBackendAvailable()) return .backend_unavailable;
    if (!validDomain(domain)) return .invalid_context;
    if (!validPublicKey(public_key)) return .malformed_key;
    if (!validSignature(signature)) return .malformed_signature;

    return if (backend_impl.verify(
        &signature.bytes,
        payload,
        domain,
        &public_key.bytes,
    )) .valid else .invalid;
}

pub fn verifyBool(
    public_key: *const PublicKey,
    domain: []const u8,
    payload: []const u8,
    signature: *const Signature,
) bool {
    return verify(public_key, domain, payload, signature) == .valid;
}

// =============================================================================
// Serialization compatibility API
// Header: magic[4], version[1], backend[1], parameter[1], flags[1], len[2 LE]
// =============================================================================

pub fn serializePublicKey(key: *const PublicKey, output: []u8) usize {
    if (!validPublicKey(key)) return 0;
    return serializeContainer(
        &PUBLIC_MAGIC,
        key.backend,
        key.parameter_set,
        key.bytes[0..key.len],
        output,
    );
}

pub fn serializeSecretKey(key: *const SecretKey, output: []u8) usize {
    if (!validSecretKey(key)) return 0;
    return serializeContainer(
        &SECRET_MAGIC,
        key.backend,
        key.parameter_set,
        key.bytes[0..key.len],
        output,
    );
}

pub fn serializeSignature(value: *const Signature, output: []u8) usize {
    if (!validSignature(value)) return 0;
    return serializeContainer(
        &SIGNATURE_MAGIC,
        value.backend,
        value.parameter_set,
        value.bytes[0..value.len],
        output,
    );
}

pub fn deserializePublicKey(input: []const u8, key: *PublicKey) bool {
    clearPublicKey(key);
    const metadata = parseContainer(&PUBLIC_MAGIC, input) orelse return false;
    if (metadata.payload.len != RAW_PUBLIC_KEY_BYTES) return false;
    @memcpy(key.bytes[0..], metadata.payload);
    key.len = metadata.payload.len;
    key.valid = true;
    key.backend = metadata.backend;
    key.parameter_set = metadata.parameter_set;
    return true;
}

pub fn deserializeSecretKey(input: []const u8, key: *SecretKey) bool {
    clearSecretKey(key);
    const metadata = parseContainer(&SECRET_MAGIC, input) orelse return false;
    if (metadata.payload.len != RAW_SECRET_KEY_BYTES) return false;
    @memcpy(key.bytes[0..], metadata.payload);
    key.len = metadata.payload.len;
    key.valid = true;
    key.backend = metadata.backend;
    key.parameter_set = metadata.parameter_set;
    return true;
}

pub fn deserializeSignature(input: []const u8, value: *Signature) bool {
    clearSignature(value);
    const metadata = parseContainer(&SIGNATURE_MAGIC, input) orelse return false;
    if (metadata.payload.len != RAW_SIGNATURE_BYTES) return false;
    @memcpy(value.bytes[0..], metadata.payload);
    value.len = metadata.payload.len;
    value.valid = true;
    value.backend = metadata.backend;
    value.parameter_set = metadata.parameter_set;
    return true;
}

const ParsedContainer = struct {
    backend: Backend,
    parameter_set: ParameterSet,
    payload: []const u8,
};

fn serializeContainer(
    magic: *const [4]u8,
    backend: Backend,
    parameter_set: ParameterSet,
    payload: []const u8,
    output: []u8,
) usize {
    if (payload.len > 0xffff) return 0;
    const total = SERIAL_HEADER_BYTES + payload.len;
    if (output.len < total) return 0;

    @memcpy(output[0..4], magic);
    output[4] = SERIAL_VERSION;
    output[5] = @intFromEnum(backend);
    output[6] = @intFromEnum(parameter_set);
    output[7] = 0;
    writeU16LE(output, 8, @intCast(payload.len));
    @memcpy(output[SERIAL_HEADER_BYTES..total], payload);
    return total;
}

fn parseContainer(
    expected_magic: *const [4]u8,
    input: []const u8,
) ?ParsedContainer {
    if (input.len < SERIAL_HEADER_BYTES) return null;
    if (!constantTimeEqual(input[0..4], expected_magic)) return null;
    if (input[4] != SERIAL_VERSION) return null;
    if (input[7] != 0) return null;

    const parsed_backend: Backend = switch (input[5]) {
        1 => .native_ml_dsa,
        else => return null,
    };

    const parsed_parameter: ParameterSet = switch (input[6]) {
        2 => .ml_dsa_65,
        else => return null,
    };

    if (parsed_backend != DEFAULT_BACKEND or
        parsed_parameter != DEFAULT_PARAMETER_SET)
    {
        return null;
    }

    const payload_len: usize = readU16LE(input, 8);
    if (input.len != SERIAL_HEADER_BYTES + payload_len) return null;

    return .{
        .backend = parsed_backend,
        .parameter_set = parsed_parameter,
        .payload = input[SERIAL_HEADER_BYTES..],
    };
}

// =============================================================================
// Clearing and validation
// =============================================================================

pub fn clearPublicKey(key: *PublicKey) void {
    constant_time.secureZero(&key.bytes);
    key.len = 0;
    key.valid = false;
    key.backend = .none;
    key.parameter_set = .none;
}

pub fn clearSecretKey(key: *SecretKey) void {
    constant_time.secureZero(&key.bytes);
    key.len = 0;
    key.valid = false;
    key.backend = .none;
    key.parameter_set = .none;
}

pub fn clearSignature(value: *Signature) void {
    constant_time.secureZero(&value.bytes);
    value.len = 0;
    value.valid = false;
    value.backend = .none;
    value.parameter_set = .none;
}

fn validPublicKey(key: *const PublicKey) bool {
    return key.valid and
        key.len == RAW_PUBLIC_KEY_BYTES and
        key.backend == DEFAULT_BACKEND and
        key.parameter_set == DEFAULT_PARAMETER_SET;
}

fn validSecretKey(key: *const SecretKey) bool {
    return key.valid and
        key.len == RAW_SECRET_KEY_BYTES and
        key.backend == DEFAULT_BACKEND and
        key.parameter_set == DEFAULT_PARAMETER_SET;
}

fn validSignature(value: *const Signature) bool {
    return value.valid and
        value.len == RAW_SIGNATURE_BYTES and
        value.backend == DEFAULT_BACKEND and
        value.parameter_set == DEFAULT_PARAMETER_SET;
}

fn validDomain(domain: []const u8) bool {
    return domain.len > 0 and domain.len <= MAX_CONTEXT_BYTES;
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

fn writeU16LE(output: []u8, offset: usize, value: u16) void {
    output[offset] = @truncate(value);
    output[offset + 1] = @truncate(value >> 8);
}

fn readU16LE(input: []const u8, offset: usize) u16 {
    return @as(u16, input[offset]) |
        (@as(u16, input[offset + 1]) << 8);
}
