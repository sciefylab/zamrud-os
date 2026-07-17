//! Zamrud OS - Identity Export/Import
//! H.7.2: Encrypted identity backup and recovery
//! H.10: SLOR KEM persistence
//! GOV.2: Production governance-signature container
//!
//! Security architecture:
//! - slor.zig is used only for KEM/key exchange.
//! - gov_sign.zig is the only governance-signature API.
//! - slor_sign.zig is not imported.
//! - Large export buffers use static storage, not kernel stack.
//! - GOV_SIGN key blobs use variable-length encoding.
//! - Missing production GOV_SIGN backend is represented as an empty,
//!   fail-closed key section.
//!
//! Bundle V3:
//! [magic:4]
//! [version:u16 LE]
//! [flags:1]
//! [reserved:1]
//! [salt:16]
//! [nonce:12]
//! [payload_len:u16 LE]
//! [encrypted payload]
//! [integrity tag:32]
//!
//! V3 payload:
//! [base identity:191]
//! [SLOR KEM:1057]
//! [GOV valid:1]
//! [GOV public length:u16]
//! [GOV public bytes]
//! [GOV secret length:u16]
//! [GOV secret bytes]

const serial = @import("../drivers/serial/serial.zig");
const keyring = @import("keyring.zig");
const wordlist = @import("../crypto/wordlist.zig");
const hash = @import("../crypto/hash.zig");
const crypto = @import("../crypto/crypto.zig");
const entropy = @import("../crypto/entropy.zig");
const constant_time = @import("../crypto/constant_time.zig");
const fat32 = @import("../fs/fat32.zig");
const slor = @import("../crypto/slor.zig");
const gov_sign = @import("../crypto/gov_sign.zig");

// =============================================================================
// Constants
// =============================================================================

pub const ZIB_MAGIC = [4]u8{ 'Z', 'I', 'B', 0x01 };
pub const ZPUB_MAGIC = [4]u8{ 'Z', 'P', 'U', 'B' };

pub const FORMAT_VERSION_V1: u16 = 1;
pub const FORMAT_VERSION_V3: u16 = 3;
pub const FORMAT_VERSION: u16 = FORMAT_VERSION_V3;

pub const ExportType = enum(u8) {
    full = 1,
    mnemonic = 2,
    public_only = 3,
};

pub const BundleFlags = packed struct {
    encrypted: bool = true,
    compressed: bool = false,
    has_metadata: bool = false,
    has_pin_backup: bool = false,
    _reserved: u4 = 0,
};

const KDF_ITERATIONS_EXPORT: u32 = 200_000;

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const INTEGRITY_SIZE: usize = 32;

const BUNDLE_HEADER_SIZE: usize = 38;

// Base identity payload:
// public key          32
// private key         32
// address             50
// address length       1
// name                32
// name length          1
// has-name             1
// trust hash          32
// credential type      1
// owner flag           1
// created-at           4
// last-used            4
// Total              191
const BASE_PAYLOAD_SIZE: usize = 191;

// SLOR KEM:
// valid                1
// public polynomial  512
// public seed         32
// secret polynomial  512
// Total             1057
const SLOR_KEM_PAYLOAD_SIZE: usize =
    1 +
    (slor.SLOR_N * @sizeOf(i16)) +
    32 +
    (slor.SLOR_N * @sizeOf(i16));

// Maximum serialized key containers.
// Serialization is variable-length. These are validation/work-buffer limits.
const GOV_SIGN_PUB_BLOB_MAX: usize = 10 + 3072;
const GOV_SIGN_SEC_BLOB_MAX: usize = 10 + 6144;

// Empty GOV_SIGN section:
// valid(1) + pub_len(2) + sec_len(2)
const GOV_SIGN_EMPTY_PAYLOAD_SIZE: usize = 5;

const V3_MIN_PAYLOAD_SIZE: usize =
    BASE_PAYLOAD_SIZE +
    SLOR_KEM_PAYLOAD_SIZE +
    GOV_SIGN_EMPTY_PAYLOAD_SIZE;

// Static storage allows a safe upper bound without consuming kernel stack.
const MAX_BUNDLE_SIZE: usize = 16 * 1024;

// =============================================================================
// Types
// =============================================================================

pub const ExportResult = struct {
    data: [MAX_BUNDLE_SIZE]u8,
    len: usize,
    export_type: ExportType,
    success: bool,
    error_msg: ?[]const u8,

    pub fn getData(self: *const ExportResult) []const u8 {
        return self.data[0..self.len];
    }
};

pub const ImportResult = struct {
    success: bool,
    identity_name: [32]u8,
    name_len: usize,
    error_msg: ?[]const u8,
    is_owner: bool,

    pub fn getName(self: *const ImportResult) []const u8 {
        return self.identity_name[0..self.name_len];
    }
};

pub const MnemonicResult = struct {
    words: [24][16]u8,
    word_lens: [24]u8,
    word_count: usize,
    success: bool,

    pub fn getWord(self: *const MnemonicResult, idx: usize) []const u8 {
        if (idx >= self.word_count) return "";
        return self.words[idx][0..self.word_lens[idx]];
    }

    pub fn format(self: *const MnemonicResult, out: []u8) usize {
        var pos: usize = 0;
        var i: usize = 0;

        while (i < self.word_count) : (i += 1) {
            const word = self.getWord(i);

            const required = word.len +
                (if (i + 1 < self.word_count) @as(usize, 1) else 0);

            if (pos + required > out.len) break;

            @memcpy(out[pos..][0..word.len], word);
            pos += word.len;

            if (i + 1 < self.word_count) {
                out[pos] = ' ';
                pos += 1;
            }
        }

        return pos;
    }
};

// =============================================================================
// Static State
// =============================================================================

var initialized: bool = false;

// IMPORTANT: Large results/buffers are static to avoid kernel stack overflow.
var static_export_result: ExportResult = .{
    .data = [_]u8{0} ** MAX_BUNDLE_SIZE,
    .len = 0,
    .export_type = .full,
    .success = false,
    .error_msg = null,
};

var work_buffer: [MAX_BUNDLE_SIZE]u8 =
    [_]u8{0} ** MAX_BUNDLE_SIZE;

var kdf_buffer: [64]u8 =
    [_]u8{0} ** 64;

var derived_key: [32]u8 =
    [_]u8{0} ** 32;

var temp_privkey: [32]u8 =
    [_]u8{0} ** 32;

var tmp_gov_pub_blob: [GOV_SIGN_PUB_BLOB_MAX]u8 =
    [_]u8{0} ** GOV_SIGN_PUB_BLOB_MAX;

var tmp_gov_sec_blob: [GOV_SIGN_SEC_BLOB_MAX]u8 =
    [_]u8{0} ** GOV_SIGN_SEC_BLOB_MAX;

// Snapshot untuk menjaga full bundle ketika static_export_result dipakai ulang
// oleh exportPublic(). Diletakkan di static storage agar tidak membebani
// kernel stack.
var static_saved_bundle: [MAX_BUNDLE_SIZE]u8 =
    [_]u8{0} ** MAX_BUNDLE_SIZE;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    if (initialized) return;

    wipeBuffers();

    // resetExportResult() mengembalikan *ExportResult.
    // Zig 0.15 mewajibkan return non-void dipakai atau dibuang eksplisit.
    _ = resetExportResult(.full);

    constant_time.secureZero(&static_saved_bundle);

    initialized = true;

    serial.writeString(
        "[IDENTITY_EXPORT] Initialized " ++
            "(V3 variable GOV_SIGN, static buffers)\n",
    );
}

fn resetExportResult(export_type: ExportType) *ExportResult {
    constant_time.secureZero(&static_export_result.data);

    static_export_result.len = 0;
    static_export_result.export_type = export_type;
    static_export_result.success = false;
    static_export_result.error_msg = null;

    return &static_export_result;
}

fn wipeBuffers() void {
    constant_time.secureZero(&work_buffer);
    constant_time.secureZero(&kdf_buffer);
    constant_time.secureZero32(&derived_key);
    constant_time.secureZero32(&temp_privkey);
    constant_time.secureZero(&tmp_gov_pub_blob);
    constant_time.secureZero(&tmp_gov_sec_blob);
}

// =============================================================================
// Full Encrypted Export
// =============================================================================

pub fn exportFull(
    identity_name: []const u8,
    credential: []const u8,
    export_password: []const u8,
) *const ExportResult {
    if (!initialized) init();

    const result = resetExportResult(.full);
    wipeBuffers();

    const id = keyring.findIdentity(identity_name) orelse {
        result.error_msg = "Identity not found";
        return result;
    };

    if (!keyring.decryptPrivateKey(id, credential, &temp_privkey)) {
        result.error_msg = "Invalid credential";
        return result;
    }

    var payload_len: usize = 0;

    payload_len = writeBasePayload(id, payload_len);
    payload_len = writeSlorKemPayload(id, payload_len);
    payload_len = writeGovSignPayload(id, payload_len);

    if (payload_len < V3_MIN_PAYLOAD_SIZE or
        payload_len > work_buffer.len)
    {
        result.error_msg = "Invalid payload size";
        wipeBuffers();
        return result;
    }

    if (BUNDLE_HEADER_SIZE +
        payload_len +
        INTEGRITY_SIZE > result.data.len)
    {
        result.error_msg = "Bundle exceeds export buffer";
        wipeBuffers();
        return result;
    }

    var salt: [SALT_SIZE]u8 = undefined;
    var nonce: [NONCE_SIZE]u8 = undefined;

    entropy.getSecureBytes(&salt) catch {
        crypto.random.getBytes(&salt);
    };

    entropy.getSecureBytes(&nonce) catch {
        crypto.random.getBytes(&nonce);
    };

    deriveExportKey(export_password, &salt, &derived_key);

    encryptPayload(
        work_buffer[0..payload_len],
        &derived_key,
        &nonce,
    );

    var pos: usize = 0;

    @memcpy(result.data[pos..][0..4], &ZIB_MAGIC);
    pos += 4;

    writeU16LE(&result.data, pos, FORMAT_VERSION);
    pos += 2;

    const flags = BundleFlags{
        .encrypted = true,
        .has_metadata = true,
    };

    result.data[pos] = @bitCast(flags);
    pos += 1;

    result.data[pos] = 0;
    pos += 1;

    @memcpy(
        result.data[pos..][0..SALT_SIZE],
        &salt,
    );
    pos += SALT_SIZE;

    @memcpy(
        result.data[pos..][0..NONCE_SIZE],
        &nonce,
    );
    pos += NONCE_SIZE;

    writeU16LE(
        &result.data,
        pos,
        @intCast(payload_len),
    );
    pos += 2;

    @memcpy(
        result.data[pos..][0..payload_len],
        work_buffer[0..payload_len],
    );
    pos += payload_len;

    var integrity_tag: [32]u8 = undefined;

    computeHmac(
        result.data[0..pos],
        &derived_key,
        &integrity_tag,
    );

    @memcpy(
        result.data[pos..][0..32],
        &integrity_tag,
    );
    pos += 32;

    result.len = pos;
    result.success = true;

    constant_time.secureZero32(&integrity_tag);
    constant_time.secureZero(&salt);
    constant_time.secureZero(&nonce);
    wipeBuffers();

    serial.writeString(
        "[IDENTITY_EXPORT] Full V3 bundle exported (",
    );
    printU32(@intCast(result.len));
    serial.writeString(" bytes)\n");

    return result;
}

fn writeBasePayload(
    id: *const keyring.Identity,
    start: usize,
) usize {
    var pos = start;

    @memcpy(
        work_buffer[pos..][0..32],
        &id.keypair.public_key,
    );
    pos += 32;

    @memcpy(
        work_buffer[pos..][0..32],
        &temp_privkey,
    );
    pos += 32;

    @memcpy(
        work_buffer[pos..][0..keyring.ADDRESS_LEN],
        &id.address,
    );
    pos += keyring.ADDRESS_LEN;

    work_buffer[pos] = id.address_len;
    pos += 1;

    @memcpy(
        work_buffer[pos..][0..keyring.NAME_MAX_LEN],
        &id.name,
    );
    pos += keyring.NAME_MAX_LEN;

    work_buffer[pos] = id.name_len;
    pos += 1;

    work_buffer[pos] = if (id.has_name) 1 else 0;
    pos += 1;

    @memcpy(
        work_buffer[pos..][0..32],
        &id.trust_hash,
    );
    pos += 32;

    work_buffer[pos] = @intFromEnum(id.credential_type);
    pos += 1;

    work_buffer[pos] = if (id.is_owner) 1 else 0;
    pos += 1;

    writeU32LE(
        &work_buffer,
        pos,
        id.created_at,
    );
    pos += 4;

    writeU32LE(
        &work_buffer,
        pos,
        id.last_used,
    );
    pos += 4;

    return pos;
}

fn writeSlorKemPayload(
    id: *const keyring.Identity,
    start: usize,
) usize {
    var pos = start;

    work_buffer[pos] =
        if (id.keypair.slor_valid) 1 else 0;
    pos += 1;

    var i: usize = 0;

    while (i < slor.SLOR_N) : (i += 1) {
        writeI16LE(
            &work_buffer,
            pos,
            id.keypair.slor_pub_key.t[i],
        );
        pos += 2;
    }

    @memcpy(
        work_buffer[pos..][0..32],
        &id.keypair.slor_pub_key.seed,
    );
    pos += 32;

    i = 0;
    while (i < slor.SLOR_N) : (i += 1) {
        writeI16LE(
            &work_buffer,
            pos,
            id.keypair.slor_sec_key_encrypted.s[i],
        );
        pos += 2;
    }

    return pos;
}

fn writeGovSignPayload(
    id: *const keyring.Identity,
    start: usize,
) usize {
    var pos = start;

    constant_time.secureZero(&tmp_gov_pub_blob);
    constant_time.secureZero(&tmp_gov_sec_blob);

    var pub_len: usize = 0;
    var sec_len: usize = 0;

    if (id.keypair.gov_sign_valid) {
        pub_len = gov_sign.serializePublicKey(
            &id.keypair.gov_sign_pub_key,
            &tmp_gov_pub_blob,
        );

        sec_len = gov_sign.serializeSecretKey(
            &id.keypair.gov_sign_sec_key_encrypted,
            &tmp_gov_sec_blob,
        );
    }

    const section_valid =
        id.keypair.gov_sign_valid and
        pub_len > 0 and
        sec_len > 0 and
        pub_len <= GOV_SIGN_PUB_BLOB_MAX and
        sec_len <= GOV_SIGN_SEC_BLOB_MAX;

    if (!section_valid) {
        pub_len = 0;
        sec_len = 0;
    }

    work_buffer[pos] =
        if (section_valid) 1 else 0;
    pos += 1;

    writeU16LE(
        &work_buffer,
        pos,
        @intCast(pub_len),
    );
    pos += 2;

    if (pub_len > 0) {
        @memcpy(
            work_buffer[pos..][0..pub_len],
            tmp_gov_pub_blob[0..pub_len],
        );
        pos += pub_len;
    }

    writeU16LE(
        &work_buffer,
        pos,
        @intCast(sec_len),
    );
    pos += 2;

    if (sec_len > 0) {
        @memcpy(
            work_buffer[pos..][0..sec_len],
            tmp_gov_sec_blob[0..sec_len],
        );
        pos += sec_len;
    }

    constant_time.secureZero(&tmp_gov_pub_blob);
    constant_time.secureZero(&tmp_gov_sec_blob);

    return pos;
}

// =============================================================================
// Mnemonic Export
// =============================================================================

pub fn exportMnemonic(
    identity_name: []const u8,
    credential: []const u8,
) MnemonicResult {
    var result = MnemonicResult{
        .words = [_][16]u8{
            [_]u8{0} ** 16,
        } ** 24,
        .word_lens = [_]u8{0} ** 24,
        .word_count = 0,
        .success = false,
    };

    if (!initialized) init();

    const id = keyring.findIdentity(identity_name) orelse return result;

    if (!keyring.decryptPrivateKey(
        id,
        credential,
        &temp_privkey,
    )) {
        return result;
    }

    var checksum_hash: [32]u8 = undefined;

    hash.sha256Into(
        &temp_privkey,
        &checksum_hash,
    );

    var entropy_bytes: [33]u8 = undefined;

    @memcpy(
        entropy_bytes[0..32],
        &temp_privkey,
    );

    entropy_bytes[32] = checksum_hash[0];

    var bit_pos: usize = 0;
    var word_idx: usize = 0;

    while (word_idx < 24) : (word_idx += 1) {
        const index = extractBits(
            &entropy_bytes,
            bit_pos,
            11,
        );

        bit_pos += 11;

        const word = wordlist.getWord(index);
        const copy_len = @min(word.len, 16);

        @memcpy(
            result.words[word_idx][0..copy_len],
            word[0..copy_len],
        );

        result.word_lens[word_idx] =
            @intCast(copy_len);
    }

    result.word_count = 24;
    result.success = true;

    constant_time.secureZero32(&temp_privkey);
    constant_time.secureZero32(&checksum_hash);
    constant_time.secureZero(&entropy_bytes);

    serial.writeString(
        "[IDENTITY_EXPORT] Mnemonic generated (24 words)\n",
    );

    return result;
}

// =============================================================================
// Public Export
// =============================================================================

pub fn exportPublic(
    identity_name: []const u8,
) *const ExportResult {
    if (!initialized) init();

    const result = resetExportResult(.public_only);

    const id = keyring.findIdentity(identity_name) orelse {
        result.error_msg = "Identity not found";
        return result;
    };

    var pos: usize = 0;

    @memcpy(result.data[pos..][0..4], &ZPUB_MAGIC);
    pos += 4;

    writeU16LE(
        &result.data,
        pos,
        FORMAT_VERSION,
    );
    pos += 2;

    @memcpy(
        result.data[pos..][0..32],
        &id.keypair.public_key,
    );
    pos += 32;

    result.data[pos] = id.address_len;
    pos += 1;

    @memcpy(
        result.data[pos..][0..keyring.ADDRESS_LEN],
        &id.address,
    );
    pos += keyring.ADDRESS_LEN;

    result.data[pos] = id.name_len;
    pos += 1;

    @memcpy(
        result.data[pos..][0..keyring.NAME_MAX_LEN],
        &id.name,
    );
    pos += keyring.NAME_MAX_LEN;

    @memcpy(
        result.data[pos..][0..32],
        &id.trust_hash,
    );
    pos += 32;

    constant_time.secureZero(&tmp_gov_pub_blob);

    var pub_len: usize = 0;

    if (id.keypair.gov_sign_valid) {
        pub_len = gov_sign.serializePublicKey(
            &id.keypair.gov_sign_pub_key,
            &tmp_gov_pub_blob,
        );
    }

    const public_valid =
        id.keypair.gov_sign_valid and
        pub_len > 0 and
        pub_len <= GOV_SIGN_PUB_BLOB_MAX;

    if (!public_valid) {
        pub_len = 0;
    }

    result.data[pos] =
        if (public_valid) 1 else 0;
    pos += 1;

    writeU16LE(
        &result.data,
        pos,
        @intCast(pub_len),
    );
    pos += 2;

    if (pub_len > 0) {
        if (pos + pub_len > result.data.len) {
            result.error_msg = "Public export too large";
            constant_time.secureZero(&tmp_gov_pub_blob);
            return result;
        }

        @memcpy(
            result.data[pos..][0..pub_len],
            tmp_gov_pub_blob[0..pub_len],
        );
        pos += pub_len;
    }

    constant_time.secureZero(&tmp_gov_pub_blob);

    result.len = pos;
    result.success = true;

    serial.writeString(
        "[IDENTITY_EXPORT] Public V3 export (",
    );
    printU32(@intCast(result.len));
    serial.writeString(" bytes)\n");

    return result;
}

// =============================================================================
// Import from Full Bundle
// =============================================================================

pub fn importFromBundle(
    bundle_data: []const u8,
    export_password: []const u8,
    new_credential: []const u8,
) ImportResult {
    var result = emptyImportResult();

    if (!initialized) init();

    if (bundle_data.len <
        BUNDLE_HEADER_SIZE + INTEGRITY_SIZE)
    {
        result.error_msg = "Bundle too small";
        return result;
    }

    if (!bytesEqual(
        bundle_data[0..4],
        &ZIB_MAGIC,
    )) {
        result.error_msg = "Invalid bundle magic";
        return result;
    }

    const version = readU16LE(bundle_data, 4);

    if (version != FORMAT_VERSION_V1 and
        version != FORMAT_VERSION_V3)
    {
        result.error_msg = "Unsupported bundle version";
        return result;
    }

    var pos: usize = 8;

    var salt: [SALT_SIZE]u8 = undefined;
    @memcpy(&salt, bundle_data[pos..][0..SALT_SIZE]);
    pos += SALT_SIZE;

    var nonce: [NONCE_SIZE]u8 = undefined;
    @memcpy(&nonce, bundle_data[pos..][0..NONCE_SIZE]);
    pos += NONCE_SIZE;

    const payload_len: usize =
        readU16LE(bundle_data, pos);
    pos += 2;

    if (payload_len > work_buffer.len or
        pos + payload_len + INTEGRITY_SIZE >
            bundle_data.len)
    {
        result.error_msg = "Invalid bundle structure";
        return result;
    }

    deriveExportKey(
        export_password,
        &salt,
        &derived_key,
    );

    const integrity_offset = pos + payload_len;

    var expected_tag: [32]u8 = undefined;

    computeHmac(
        bundle_data[0..integrity_offset],
        &derived_key,
        &expected_tag,
    );

    if (!constant_time.constantTimeCompare32(
        &expected_tag,
        bundle_data[integrity_offset..][0..32],
    )) {
        result.error_msg =
            "Invalid password or corrupted bundle";

        constant_time.secureZero32(&derived_key);
        constant_time.secureZero32(&expected_tag);

        return result;
    }

    @memcpy(
        work_buffer[0..payload_len],
        bundle_data[pos..][0..payload_len],
    );

    decryptPayload(
        work_buffer[0..payload_len],
        &derived_key,
        &nonce,
    );

    constant_time.secureZero32(&derived_key);
    constant_time.secureZero32(&expected_tag);
    constant_time.secureZero(&salt);
    constant_time.secureZero(&nonce);

    return importPayload(
        version,
        payload_len,
        new_credential,
    );
}

fn importPayload(
    version: u16,
    payload_len: usize,
    new_credential: []const u8,
) ImportResult {
    var result = emptyImportResult();

    if (payload_len < BASE_PAYLOAD_SIZE) {
        result.error_msg = "Payload too small";
        wipeBuffers();
        return result;
    }

    var pos: usize = 0;

    var public_key: [32]u8 = undefined;

    @memcpy(
        &public_key,
        work_buffer[pos..][0..32],
    );
    pos += 32;

    @memcpy(
        &temp_privkey,
        work_buffer[pos..][0..32],
    );
    pos += 32;

    var calculated_public_key: [32]u8 = undefined;

    hash.sha256Into(
        &temp_privkey,
        &calculated_public_key,
    );

    if (!constant_time.constantTimeCompare32(
        &calculated_public_key,
        &public_key,
    )) {
        result.error_msg = "Key verification failed";

        constant_time.secureZero32(
            &calculated_public_key,
        );
        wipeBuffers();

        return result;
    }

    constant_time.secureZero32(
        &calculated_public_key,
    );

    var address: [keyring.ADDRESS_LEN]u8 =
        undefined;

    @memcpy(
        &address,
        work_buffer[pos..][0..keyring.ADDRESS_LEN],
    );
    pos += keyring.ADDRESS_LEN;

    const address_len = work_buffer[pos];
    pos += 1;

    var name: [keyring.NAME_MAX_LEN]u8 =
        undefined;

    @memcpy(
        &name,
        work_buffer[pos..][0..keyring.NAME_MAX_LEN],
    );
    pos += keyring.NAME_MAX_LEN;

    const name_len = work_buffer[pos];
    pos += 1;

    const has_name = work_buffer[pos] == 1;
    pos += 1;

    var trust_hash: [32]u8 = undefined;

    @memcpy(
        &trust_hash,
        work_buffer[pos..][0..32],
    );
    pos += 32;

    _ = work_buffer[pos]; // original credential type
    pos += 1;

    const is_owner = work_buffer[pos] == 1;
    pos += 1;

    const created_at =
        readU32LE(&work_buffer, pos);
    pos += 4;

    const last_used =
        readU32LE(&work_buffer, pos);
    pos += 4;

    if (address_len > keyring.ADDRESS_LEN or
        name_len > keyring.NAME_MAX_LEN)
    {
        result.error_msg = "Invalid identity metadata";
        wipeBuffers();
        return result;
    }

    const name_slice =
        if (has_name and name_len > 0)
            name[0..name_len]
        else
            "";

    if (has_name and
        name_len > 0 and
        keyring.findIdentity(name_slice) != null)
    {
        result.error_msg = "Identity already exists";
        wipeBuffers();
        return result;
    }

    const id_count = keyring.getIdentityCount();

    if (id_count >= keyring.MAX_IDENTITIES) {
        result.error_msg = "Identity storage full";
        wipeBuffers();
        return result;
    }

    const new_id = keyring.getSlotPtr(id_count) orelse {
        result.error_msg =
            "Cannot allocate identity";
        wipeBuffers();
        return result;
    };

    clearImportedIdentity(new_id);

    @memcpy(
        &new_id.keypair.public_key,
        &public_key,
    );

    @memcpy(
        &new_id.address,
        &address,
    );

    new_id.address_len = address_len;

    @memcpy(
        &new_id.name,
        &name,
    );

    new_id.name_len = name_len;
    new_id.has_name = has_name;

    @memcpy(
        &new_id.trust_hash,
        &trust_hash,
    );

    new_id.is_owner = is_owner;
    new_id.created_at = created_at;
    new_id.last_used = last_used;
    new_id.active = true;
    new_id.unlocked = false;
    new_id.has_pin = false;

    crypto.random.getBytes(&new_id.keypair.salt);

    var credential_key: [32]u8 = undefined;

    deriveKeyringCompatibleKey(
        new_credential,
        &new_id.keypair.salt,
        &credential_key,
    );

    var i: usize = 0;

    while (i < 32) : (i += 1) {
        new_id.keypair.private_key_encrypted[i] =
            temp_privkey[i] ^ credential_key[i];
    }

    while (i < 48) : (i += 1) {
        new_id.keypair.private_key_encrypted[i] = 0;
    }

    new_id.keypair.valid = true;

    new_id.credential_type =
        keyring.detectCredentialType(new_credential);

    if (version == FORMAT_VERSION_V3) {
        if (payload_len < V3_MIN_PAYLOAD_SIZE) {
            result.error_msg = "V3 payload too small";
            clearImportedIdentity(new_id);
            wipeBuffers();
            return result;
        }

        pos = readSlorKemPayload(
            new_id,
            pos,
            payload_len,
        ) orelse {
            result.error_msg =
                "Invalid SLOR KEM payload";
            clearImportedIdentity(new_id);
            wipeBuffers();
            return result;
        };

        pos = readGovSignPayload(
            new_id,
            pos,
            payload_len,
        ) orelse {
            result.error_msg =
                "Invalid GOV_SIGN payload";
            clearImportedIdentity(new_id);
            wipeBuffers();
            return result;
        };

        if (pos != payload_len) {
            result.error_msg =
                "Unexpected payload trailing data";
            clearImportedIdentity(new_id);
            wipeBuffers();
            return result;
        }
    } else {
        new_id.keypair.slor_valid = false;

        gov_sign.clearPublicKey(
            &new_id.keypair.gov_sign_pub_key,
        );

        gov_sign.clearSecretKey(
            &new_id.keypair.gov_sign_sec_key_encrypted,
        );

        new_id.keypair.gov_sign_valid = false;
    }

    keyring.setIdentityCount(id_count + 1);
    keyring.ensureCurrentIdentity();

    const result_name_len: usize =
        @min(@as(usize, name_len), result.identity_name.len);

    if (result_name_len > 0) {
        @memcpy(
            result.identity_name[0..result_name_len],
            name[0..result_name_len],
        );
    }

    result.name_len = result_name_len;
    result.is_owner = is_owner;
    result.success = true;

    constant_time.secureZero32(&credential_key);
    constant_time.secureZero32(&public_key);
    constant_time.secureZero(&address);
    constant_time.secureZero(&name);
    constant_time.secureZero32(&trust_hash);

    wipeBuffers();

    serial.writeString(
        "[IDENTITY_EXPORT] Identity imported successfully\n",
    );

    return result;
}

fn readSlorKemPayload(
    id: *keyring.Identity,
    start: usize,
    payload_end: usize,
) ?usize {
    var pos = start;

    if (pos + SLOR_KEM_PAYLOAD_SIZE >
        payload_end)
    {
        return null;
    }

    id.keypair.slor_valid =
        work_buffer[pos] == 1;
    pos += 1;

    var i: usize = 0;

    while (i < slor.SLOR_N) : (i += 1) {
        id.keypair.slor_pub_key.t[i] =
            readI16LE(&work_buffer, pos);
        pos += 2;
    }

    @memcpy(
        &id.keypair.slor_pub_key.seed,
        work_buffer[pos..][0..32],
    );
    pos += 32;

    i = 0;

    while (i < slor.SLOR_N) : (i += 1) {
        id.keypair.slor_sec_key_encrypted.s[i] =
            readI16LE(&work_buffer, pos);
        pos += 2;
    }

    return pos;
}

fn readGovSignPayload(
    id: *keyring.Identity,
    start: usize,
    payload_end: usize,
) ?usize {
    var pos = start;

    gov_sign.clearPublicKey(
        &id.keypair.gov_sign_pub_key,
    );

    gov_sign.clearSecretKey(
        &id.keypair.gov_sign_sec_key_encrypted,
    );

    id.keypair.gov_sign_valid = false;

    if (pos + GOV_SIGN_EMPTY_PAYLOAD_SIZE >
        payload_end)
    {
        return null;
    }

    const marked_valid =
        work_buffer[pos] == 1;
    pos += 1;

    const pub_len: usize =
        readU16LE(&work_buffer, pos);
    pos += 2;

    if (pub_len > GOV_SIGN_PUB_BLOB_MAX) {
        return null;
    }

    if (pos + pub_len + 2 > payload_end) {
        return null;
    }

    const pub_start = pos;
    pos += pub_len;

    const sec_len: usize =
        readU16LE(&work_buffer, pos);
    pos += 2;

    if (sec_len > GOV_SIGN_SEC_BLOB_MAX) {
        return null;
    }

    if (pos + sec_len > payload_end) {
        return null;
    }

    const sec_start = pos;
    pos += sec_len;

    if (!marked_valid) {
        if (pub_len != 0 or sec_len != 0) {
            return null;
        }

        return pos;
    }

    if (pub_len == 0 or sec_len == 0) {
        return null;
    }

    const public_ok =
        gov_sign.deserializePublicKey(
            work_buffer[pub_start .. pub_start + pub_len],
            &id.keypair.gov_sign_pub_key,
        );

    const secret_ok =
        gov_sign.deserializeSecretKey(
            work_buffer[sec_start .. sec_start + sec_len],
            &id.keypair.gov_sign_sec_key_encrypted,
        );

    id.keypair.gov_sign_valid =
        public_ok and secret_ok;

    if (!id.keypair.gov_sign_valid) {
        gov_sign.clearPublicKey(
            &id.keypair.gov_sign_pub_key,
        );

        gov_sign.clearSecretKey(
            &id.keypair.gov_sign_sec_key_encrypted,
        );

        return null;
    }

    return pos;
}

// =============================================================================
// Mnemonic Import
// =============================================================================

pub fn importFromMnemonic(
    words: []const []const u8,
    new_name: []const u8,
    new_credential: []const u8,
) ImportResult {
    var result = emptyImportResult();

    if (!initialized) init();

    if (words.len != 24) {
        result.error_msg =
            "Must provide exactly 24 words";
        return result;
    }

    if (keyring.findIdentity(new_name) != null) {
        result.error_msg = "Name already exists";
        return result;
    }

    var indices: [24]u16 = undefined;

    for (words, 0..) |word, index| {
        indices[index] =
            wordlist.findWord(word) orelse {
                result.error_msg =
                    "Invalid mnemonic word";
                return result;
            };
    }

    var entropy_bytes: [33]u8 =
        [_]u8{0} ** 33;

    var bit_pos: usize = 0;

    for (indices) |index| {
        var bits_written: usize = 0;

        while (bits_written < 11) {
            const byte_index = bit_pos / 8;
            const bit_offset = bit_pos % 8;

            const count = @min(
                8 - bit_offset,
                11 - bits_written,
            );

            const source_shift: u4 =
                @intCast(
                    11 - bits_written - count,
                );

            const mask: u16 =
                (@as(u16, 1) <<
                    @intCast(count)) - 1;

            const value: u8 =
                @truncate(
                    (index >> source_shift) & mask,
                );

            const destination_shift: u3 =
                @intCast(
                    8 - bit_offset - count,
                );

            entropy_bytes[byte_index] |=
                value << destination_shift;

            bit_pos += count;
            bits_written += count;
        }
    }

    @memcpy(
        &temp_privkey,
        entropy_bytes[0..32],
    );

    var checksum_hash: [32]u8 = undefined;

    hash.sha256Into(
        &temp_privkey,
        &checksum_hash,
    );

    if (checksum_hash[0] != entropy_bytes[32]) {
        result.error_msg =
            "Invalid mnemonic checksum";

        constant_time.secureZero32(&temp_privkey);
        constant_time.secureZero32(&checksum_hash);
        constant_time.secureZero(&entropy_bytes);

        return result;
    }

    const count = keyring.getIdentityCount();

    if (count >= keyring.MAX_IDENTITIES) {
        result.error_msg = "Identity storage full";
        return result;
    }

    const id = keyring.getSlotPtr(count) orelse {
        result.error_msg =
            "Cannot allocate identity";
        return result;
    };

    clearImportedIdentity(id);

    hash.sha256Into(
        &temp_privkey,
        &id.keypair.public_key,
    );

    id.has_name = true;
    id.name_len =
        @intCast(
            @min(
                new_name.len,
                keyring.NAME_MAX_LEN,
            ),
        );

    @memcpy(
        id.name[0..id.name_len],
        new_name[0..id.name_len],
    );

    generateAddress(id);

    crypto.random.getBytes(&id.keypair.salt);

    var credential_key: [32]u8 = undefined;

    deriveKeyringCompatibleKey(
        new_credential,
        &id.keypair.salt,
        &credential_key,
    );

    var i: usize = 0;

    while (i < 32) : (i += 1) {
        id.keypair.private_key_encrypted[i] =
            temp_privkey[i] ^ credential_key[i];
    }

    while (i < 48) : (i += 1) {
        id.keypair.private_key_encrypted[i] = 0;
    }

    id.keypair.valid = true;

    id.credential_type =
        keyring.detectCredentialType(new_credential);

    id.is_owner = count == 0;
    id.created_at = 1700000000;
    id.last_used = id.created_at;
    id.active = true;
    id.unlocked = false;
    id.has_pin = false;

    // A mnemonic only restores the identity private key.
    // KEM and governance keys require a full encrypted bundle.
    id.keypair.slor_valid = false;
    id.keypair.gov_sign_valid = false;

    generateTrustHash(id);

    keyring.setIdentityCount(count + 1);
    keyring.ensureCurrentIdentity();

    const copy_len =
        @min(
            @as(usize, id.name_len),
            result.identity_name.len,
        );

    @memcpy(
        result.identity_name[0..copy_len],
        id.name[0..copy_len],
    );

    result.name_len = copy_len;
    result.is_owner = id.is_owner;
    result.success = true;

    constant_time.secureZero32(&temp_privkey);
    constant_time.secureZero32(&checksum_hash);
    constant_time.secureZero32(&credential_key);
    constant_time.secureZero(&entropy_bytes);

    serial.writeString(
        "[IDENTITY_EXPORT] Identity recovered from mnemonic\n",
    );

    return result;
}

// =============================================================================
// Backup Verification
// =============================================================================

pub fn verifyBackup(
    bundle_data: []const u8,
    export_password: []const u8,
    identity_name: []const u8,
) bool {
    if (!initialized) init();

    const id = keyring.findIdentity(identity_name) orelse return false;

    if (bundle_data.len <
        BUNDLE_HEADER_SIZE + INTEGRITY_SIZE)
    {
        return false;
    }

    if (!bytesEqual(
        bundle_data[0..4],
        &ZIB_MAGIC,
    )) {
        return false;
    }

    const payload_len: usize =
        readU16LE(bundle_data, 36);

    const integrity_offset =
        BUNDLE_HEADER_SIZE + payload_len;

    if (payload_len > work_buffer.len or
        integrity_offset + INTEGRITY_SIZE >
            bundle_data.len)
    {
        return false;
    }

    var salt: [SALT_SIZE]u8 = undefined;
    var nonce: [NONCE_SIZE]u8 = undefined;

    @memcpy(
        &salt,
        bundle_data[8..][0..SALT_SIZE],
    );

    @memcpy(
        &nonce,
        bundle_data[24..][0..NONCE_SIZE],
    );

    deriveExportKey(
        export_password,
        &salt,
        &derived_key,
    );

    var expected_tag: [32]u8 = undefined;

    computeHmac(
        bundle_data[0..integrity_offset],
        &derived_key,
        &expected_tag,
    );

    if (!constant_time.constantTimeCompare32(
        &expected_tag,
        bundle_data[integrity_offset..][0..32],
    )) {
        constant_time.secureZero32(&derived_key);
        constant_time.secureZero32(&expected_tag);
        return false;
    }

    @memcpy(
        work_buffer[0..payload_len],
        bundle_data[BUNDLE_HEADER_SIZE .. BUNDLE_HEADER_SIZE + payload_len],
    );

    decryptPayload(
        work_buffer[0..payload_len],
        &derived_key,
        &nonce,
    );

    const matches =
        constant_time.constantTimeCompare32(
            work_buffer[0..32],
            &id.keypair.public_key,
        );

    constant_time.secureZero32(&expected_tag);
    wipeBuffers();

    return matches;
}

// =============================================================================
// File I/O
// =============================================================================

pub fn saveToFile(
    filename: []const u8,
    data: []const u8,
) bool {
    if (!fat32.isMounted()) return false;

    if (fat32.findInRoot(filename) != null) {
        _ = fat32.deleteFile(filename);
    }

    return fat32.createFile(filename, data);
}

pub fn loadFromFile(
    filename: []const u8,
    buffer: []u8,
) ?usize {
    if (!fat32.isMounted()) return null;

    const info =
        fat32.findInRoot(filename) orelse return null;

    const read_size =
        @min(@as(usize, info.size), buffer.len);

    const bytes =
        fat32.readFile(
            info.cluster,
            buffer[0..read_size],
        );

    if (bytes == 0) return null;

    return bytes;
}

// =============================================================================
// KDF and Encryption
// =============================================================================

fn deriveExportKey(
    password: []const u8,
    salt: *const [SALT_SIZE]u8,
    out: *[32]u8,
) void {
    constant_time.secureZero(&kdf_buffer);

    const password_len =
        @min(password.len, @as(usize, 48));

    if (password_len > 0) {
        @memcpy(
            kdf_buffer[0..password_len],
            password[0..password_len],
        );
    }

    @memcpy(
        kdf_buffer[48..64],
        salt,
    );

    hash.sha256Into(&kdf_buffer, out);

    var round: u32 = 0;

    while (round < KDF_ITERATIONS_EXPORT) : (round += 1) {
        @memcpy(
            kdf_buffer[0..32],
            out,
        );

        kdf_buffer[32] = @truncate(round);
        kdf_buffer[33] = @truncate(round >> 8);
        kdf_buffer[34] = @truncate(round >> 16);
        kdf_buffer[35] = @truncate(round >> 24);

        hash.sha256Into(
            kdf_buffer[0..36],
            out,
        );
    }

    constant_time.secureZero(&kdf_buffer);
}

fn deriveKeyringCompatibleKey(
    credential: []const u8,
    salt: *const [16]u8,
    out: *[32]u8,
) void {
    var buffer: [64]u8 =
        [_]u8{0} ** 64;

    const credential_len =
        @min(credential.len, @as(usize, 48));

    if (credential_len > 0) {
        @memcpy(
            buffer[0..credential_len],
            credential[0..credential_len],
        );
    }

    @memcpy(buffer[48..64], salt);

    hash.sha256Into(&buffer, out);

    var round: u32 = 0;

    while (round < keyring.KDF_ROUNDS) : (round += 1) {
        @memcpy(buffer[0..32], out);
        @memcpy(buffer[32..48], salt);

        buffer[48] = @truncate(round);
        buffer[49] = @truncate(round >> 8);
        buffer[50] = @truncate(round >> 16);
        buffer[51] = @truncate(round >> 24);

        hash.sha256Into(
            buffer[0..52],
            out,
        );
    }

    constant_time.secureZero(&buffer);
}

fn encryptPayload(
    data: []u8,
    key: *const [32]u8,
    nonce: *const [NONCE_SIZE]u8,
) void {
    var counter: u32 = 0;
    var input: [48]u8 = undefined;
    var stream: [32]u8 = undefined;

    var pos: usize = 0;

    while (pos < data.len) {
        @memcpy(input[0..32], key);
        @memcpy(input[32..44], nonce);

        input[44] = @truncate(counter);
        input[45] = @truncate(counter >> 8);
        input[46] = @truncate(counter >> 16);
        input[47] = @truncate(counter >> 24);

        hash.sha256Into(&input, &stream);

        const remaining = data.len - pos;
        const block_len =
            @min(remaining, @as(usize, 32));

        var i: usize = 0;
        while (i < block_len) : (i += 1) {
            data[pos + i] ^= stream[i];
        }

        pos += block_len;
        counter +%= 1;
    }

    constant_time.secureZero(&input);
    constant_time.secureZero32(&stream);
}

fn decryptPayload(
    data: []u8,
    key: *const [32]u8,
    nonce: *const [NONCE_SIZE]u8,
) void {
    encryptPayload(data, key, nonce);
}

fn computeHmac(
    data: []const u8,
    key: *const [32]u8,
    out: *[32]u8,
) void {
    var inner_key: [64]u8 =
        [_]u8{0x36} ** 64;

    var outer_key: [64]u8 =
        [_]u8{0x5c} ** 64;

    var i: usize = 0;

    while (i < 32) : (i += 1) {
        inner_key[i] ^= key[i];
        outer_key[i] ^= key[i];
    }

    var inner_hasher = hash.Sha256.init();
    inner_hasher.update(&inner_key);
    inner_hasher.update(data);

    var inner_hash: [32]u8 = undefined;
    inner_hasher.final(&inner_hash);

    var outer_hasher = hash.Sha256.init();
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    outer_hasher.final(out);

    constant_time.secureZero(&inner_key);
    constant_time.secureZero(&outer_key);
    constant_time.secureZero32(&inner_hash);
}

// =============================================================================
// Imported Identity Helpers
// =============================================================================

fn emptyImportResult() ImportResult {
    return .{
        .success = false,
        .identity_name = [_]u8{0} ** 32,
        .name_len = 0,
        .error_msg = null,
        .is_owner = false,
    };
}

fn clearImportedIdentity(
    id: *keyring.Identity,
) void {
    constant_time.secureZero(
        id.address[0..],
    );

    constant_time.secureZero(
        id.name[0..],
    );

    constant_time.secureZero32(
        &id.keypair.public_key,
    );

    constant_time.secureZero(
        id.keypair.private_key_encrypted[0..],
    );

    constant_time.secureZero(
        id.keypair.salt[0..],
    );

    constant_time.secureZero32(
        &id.trust_hash,
    );

    constant_time.secureZero32(
        &id.pin_encrypted,
    );

    constant_time.secureZero(
        id.pin_salt[0..],
    );

    var i: usize = 0;

    while (i < slor.SLOR_N) : (i += 1) {
        id.keypair.slor_pub_key.t[i] = 0;
        id.keypair.slor_sec_key_encrypted.s[i] = 0;
    }

    constant_time.secureZero32(
        &id.keypair.slor_pub_key.seed,
    );

    gov_sign.clearPublicKey(
        &id.keypair.gov_sign_pub_key,
    );

    gov_sign.clearSecretKey(
        &id.keypair.gov_sign_sec_key_encrypted,
    );

    id.address_len = 0;
    id.name_len = 0;
    id.has_name = false;

    id.keypair.valid = false;
    id.keypair.slor_valid = false;
    id.keypair.gov_sign_valid = false;

    id.created_at = 0;
    id.last_used = 0;
    id.active = false;
    id.unlocked = false;
    id.credential_type = .none;
    id.is_owner = false;
    id.has_pin = false;
}

fn generateAddress(
    id: *keyring.Identity,
) void {
    const prefix = "zamrud1";
    const alphabet =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    @memcpy(
        id.address[0..prefix.len],
        prefix,
    );

    var pos: usize = prefix.len;
    var i: usize = 0;

    while (i < 32 and
        pos < keyring.ADDRESS_LEN) : (i += 1)
    {
        id.address[pos] =
            alphabet[id.keypair.public_key[i] % 58];
        pos += 1;
    }

    id.address_len = @intCast(pos);
}

fn generateTrustHash(
    id: *keyring.Identity,
) void {
    var buffer: [64]u8 =
        [_]u8{0} ** 64;

    @memcpy(
        buffer[0..32],
        &id.keypair.public_key,
    );

    const address_copy_len =
        @min(
            @as(usize, id.address_len),
            @as(usize, 32),
        );

    @memcpy(
        buffer[32 .. 32 + address_copy_len],
        id.address[0..address_copy_len],
    );

    var intermediate: [32]u8 = undefined;

    hash.sha256Into(
        &buffer,
        &intermediate,
    );

    constant_time.secureZero(&buffer);

    @memcpy(buffer[0..32], &intermediate);

    buffer[32] = @truncate(id.created_at);
    buffer[33] = @truncate(id.created_at >> 8);
    buffer[34] = @truncate(id.created_at >> 16);
    buffer[35] = @truncate(id.created_at >> 24);

    const domain = "zamrud-trust-v1";

    @memcpy(
        buffer[36 .. 36 + domain.len],
        domain,
    );

    hash.sha256Into(
        buffer[0 .. 36 + domain.len],
        &id.trust_hash,
    );

    constant_time.secureZero(&buffer);
    constant_time.secureZero32(&intermediate);
}

// =============================================================================
// Encoding Utilities
// =============================================================================

fn bytesEqual(
    left: []const u8,
    right: []const u8,
) bool {
    if (left.len != right.len) return false;

    var value: u8 = 0;

    for (left, right) |a, b| {
        value |= a ^ b;
    }

    return value == 0;
}

fn extractBits(
    data: []const u8,
    bit_pos: usize,
    bit_count: usize,
) u16 {
    var result: u16 = 0;

    var i: usize = 0;

    while (i < bit_count) : (i += 1) {
        const absolute_bit = bit_pos + i;
        const byte_index = absolute_bit / 8;
        const bit_index: u3 =
            @intCast(7 - (absolute_bit % 8));

        const bit: u16 =
            if (byte_index < data.len)
                (data[byte_index] >> bit_index) & 1
            else
                0;

        result = (result << 1) | bit;
    }

    return result;
}

fn writeU16LE(
    buffer: []u8,
    offset: usize,
    value: u16,
) void {
    buffer[offset] = @truncate(value);
    buffer[offset + 1] = @truncate(value >> 8);
}

fn readU16LE(
    buffer: []const u8,
    offset: usize,
) u16 {
    return @as(u16, buffer[offset]) |
        (@as(u16, buffer[offset + 1]) << 8);
}

fn writeU32LE(
    buffer: []u8,
    offset: usize,
    value: u32,
) void {
    buffer[offset] = @truncate(value);
    buffer[offset + 1] = @truncate(value >> 8);
    buffer[offset + 2] = @truncate(value >> 16);
    buffer[offset + 3] = @truncate(value >> 24);
}

fn readU32LE(
    buffer: []const u8,
    offset: usize,
) u32 {
    return @as(u32, buffer[offset]) |
        (@as(u32, buffer[offset + 1]) << 8) |
        (@as(u32, buffer[offset + 2]) << 16) |
        (@as(u32, buffer[offset + 3]) << 24);
}

fn writeI16LE(
    buffer: []u8,
    offset: usize,
    value: i16,
) void {
    const raw: u16 = @bitCast(value);

    buffer[offset] = @truncate(raw);
    buffer[offset + 1] = @truncate(raw >> 8);
}

fn readI16LE(
    buffer: []const u8,
    offset: usize,
) i16 {
    const raw =
        @as(u16, buffer[offset]) |
        (@as(u16, buffer[offset + 1]) << 8);

    return @bitCast(raw);
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
        buffer[count] =
            @intCast((remaining % 10) + '0');

        remaining /= 10;
    }

    while (count > 0) {
        count -= 1;
        serial.writeChar(buffer[count]);
    }
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString(
        "\n========================================\n",
    );

    serial.writeString(
        "  H.7.2 IDENTITY EXPORT/IMPORT TESTS V3\n",
    );

    serial.writeString(
        "========================================\n\n",
    );

    var passed: u32 = 0;
    var failed: u32 = 0;

    init();
    keyring.init();

    // Bundle snapshot harus berada di static storage.
    constant_time.secureZero(&static_saved_bundle);

    const identity_password = "TestPass123";
    const backup_password = "BackupPass456";
    const restored_password = "NewPass789";

    // =========================================================================
    // Test 1: Create identity
    // =========================================================================

    serial.writeString(
        "  [1/8] Create test identity............",
    );

    const identity = keyring.createIdentityWithPassword(
        "export_test",
        identity_password,
    );

    if (identity != null) {
        serial.writeString(" PASS\n");
        passed += 1;
    } else {
        serial.writeString(" FAIL\n");

        constant_time.secureZero(&static_saved_bundle);
        keyring.init();

        return false;
    }

    // =========================================================================
    // Test 2: Full bundle export
    // =========================================================================

    serial.writeString(
        "  [2/8] Export full V3 bundle...........",
    );

    const exported = exportFull(
        "export_test",
        identity_password,
        backup_password,
    );

    var saved_bundle_len: usize = 0;

    if (exported.success and
        exported.len >=
            BUNDLE_HEADER_SIZE +
                V3_MIN_PAYLOAD_SIZE +
                INTEGRITY_SIZE and
        exported.len <= MAX_BUNDLE_SIZE)
    {
        saved_bundle_len = exported.len;

        @memcpy(
            static_saved_bundle[0..saved_bundle_len],
            exported.data[0..saved_bundle_len],
        );

        serial.writeString(" PASS (");
        printU32(@intCast(exported.len));
        serial.writeString(" bytes)\n");

        passed += 1;
    } else {
        serial.writeString(" FAIL");

        if (exported.error_msg) |error_message| {
            serial.writeString(" (");
            serial.writeString(error_message);
            serial.writeString(")");
        }

        serial.writeString("\n");
        failed += 1;
    }

    // =========================================================================
    // Test 3: Mnemonic export
    // =========================================================================

    serial.writeString(
        "  [3/8] Export mnemonic.................",
    );

    const mnemonic = exportMnemonic(
        "export_test",
        identity_password,
    );

    if (mnemonic.success and mnemonic.word_count == 24) {
        serial.writeString(" PASS\n");
        passed += 1;
    } else {
        serial.writeString(" FAIL\n");
        failed += 1;
    }

    // =========================================================================
    // Test 4: Public export
    // =========================================================================

    serial.writeString(
        "  [4/8] Export public V3................",
    );

    // exportPublic() menggunakan static_export_result yang sama dengan
    // exportFull(). Full bundle sudah diamankan ke static_saved_bundle.
    const public_export = exportPublic("export_test");

    if (public_export.success and
        public_export.len > 100 and
        public_export.len <= MAX_BUNDLE_SIZE)
    {
        serial.writeString(" PASS (");
        printU32(@intCast(public_export.len));
        serial.writeString(" bytes)\n");

        passed += 1;
    } else {
        serial.writeString(" FAIL");

        if (public_export.error_msg) |error_message| {
            serial.writeString(" (");
            serial.writeString(error_message);
            serial.writeString(")");
        }

        serial.writeString("\n");
        failed += 1;
    }

    // =========================================================================
    // Test 5: Correct password verification
    // =========================================================================

    serial.writeString(
        "  [5/8] Verify backup...................",
    );

    if (saved_bundle_len > 0 and
        verifyBackup(
            static_saved_bundle[0..saved_bundle_len],
            backup_password,
            "export_test",
        ))
    {
        serial.writeString(" PASS\n");
        passed += 1;
    } else {
        serial.writeString(" FAIL\n");
        failed += 1;
    }

    // =========================================================================
    // Test 6: Wrong password rejection
    // =========================================================================

    serial.writeString(
        "  [6/8] Wrong password rejected.........",
    );

    if (saved_bundle_len > 0 and
        !verifyBackup(
            static_saved_bundle[0..saved_bundle_len],
            "WrongPass",
            "export_test",
        ))
    {
        serial.writeString(" PASS\n");
        passed += 1;
    } else {
        serial.writeString(" FAIL\n");
        failed += 1;
    }

    // =========================================================================
    // Test 7: Import bundle
    // =========================================================================

    serial.writeString(
        "  [7/8] Import from V3 bundle...........",
    );

    _ = keyring.deleteIdentity("export_test");

    var import_succeeded = false;

    if (saved_bundle_len > 0) {
        const imported = importFromBundle(
            static_saved_bundle[0..saved_bundle_len],
            backup_password,
            restored_password,
        );

        import_succeeded = imported.success;

        if (imported.success) {
            serial.writeString(" PASS\n");
            passed += 1;
        } else {
            serial.writeString(" FAIL");

            if (imported.error_msg) |error_message| {
                serial.writeString(" (");
                serial.writeString(error_message);
                serial.writeString(")");
            }

            serial.writeString("\n");
            failed += 1;
        }
    } else {
        serial.writeString(" FAIL (no exported bundle)\n");
        failed += 1;
    }

    // =========================================================================
    // Test 8: Restored identity validation
    // =========================================================================

    serial.writeString(
        "  [8/8] Imported identity works.........",
    );

    if (import_succeeded) {
        if (keyring.findIdentity("export_test")) |restored_identity| {
            var restored_private_key: [32]u8 =
                [_]u8{0} ** 32;

            const decrypted = keyring.decryptPrivateKey(
                restored_identity,
                restored_password,
                &restored_private_key,
            );

            if (decrypted) {
                var restored_public_key: [32]u8 =
                    [_]u8{0} ** 32;

                hash.sha256Into(
                    &restored_private_key,
                    &restored_public_key,
                );

                const public_key_matches =
                    constant_time.constantTimeCompare32(
                        &restored_public_key,
                        &restored_identity.keypair.public_key,
                    );

                if (public_key_matches) {
                    serial.writeString(" PASS\n");
                    passed += 1;
                } else {
                    serial.writeString(
                        " FAIL (public key mismatch)\n",
                    );
                    failed += 1;
                }

                constant_time.secureZero32(
                    &restored_public_key,
                );
            } else {
                serial.writeString(
                    " FAIL (private key decrypt failed)\n",
                );
                failed += 1;
            }

            constant_time.secureZero32(
                &restored_private_key,
            );
        } else {
            serial.writeString(
                " FAIL (identity not found)\n",
            );
            failed += 1;
        }
    } else {
        serial.writeString(" SKIP\n");
        failed += 1;
    }

    // =========================================================================
    // Cleanup
    // =========================================================================

    constant_time.secureZero(&static_saved_bundle);
    wipeBuffers();

    _ = resetExportResult(.full);

    keyring.init();

    // =========================================================================
    // Summary
    // =========================================================================

    serial.writeString(
        "\n  H.7.2 V3 Results: ",
    );

    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed");

    if (failed == 0) {
        serial.writeString(" OK\n");
    } else {
        serial.writeString(" FAILED\n");
    }

    serial.writeString(
        "========================================\n",
    );

    return failed == 0;
}
