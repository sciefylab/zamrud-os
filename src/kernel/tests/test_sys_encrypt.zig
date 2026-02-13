//! Zamrud OS - F4.2: System Data Encryption Test Suite
//! Tests: 25/25
//!
//! Coverage:
//!   1-5:   Core sys_encrypt (init, master key, domain keys)
//!   6-10:  Encrypt/decrypt for each domain (config, identity, ipc, chain)
//!   11-13: IPC message encryption (encryptIpcMsg / decryptIpcMsg)
//!   14-15: isEncrypted utility, magic header validation
//!   16-17: Config store encrypted round-trip
//!   18-19: Identity store encrypted round-trip
//!   20-21: IPC message.zig encrypted send/recv
//!   22-23: Pipe encrypted write/read
//!   24:    Shared memory encrypted write/read
//!   25:    Stats tracking & key clearing

const serial = @import("../drivers/serial/serial.zig");
const sys_encrypt = @import("../crypto/sys_encrypt.zig");
const aes = @import("../crypto/aes.zig");
const hash = @import("../crypto/hash.zig");
const capability = @import("../security/capability.zig");
const violation = @import("../security/violation.zig");
const message = @import("../ipc/message.zig");
const pipe = @import("../ipc/pipe.zig");
const shared_mem = @import("../ipc/shared_mem.zig");

// ============================================================================
// State
// ============================================================================

var tests_run: u32 = 0;
var tests_passed: u32 = 0;
var tests_failed: u32 = 0;

// ============================================================================
// Test Key Material (deterministic for testing)
// ============================================================================

const TEST_PASSPHRASE = "zamrud-test-master-key-2024";

fn getTestKey() [32]u8 {
    var key: [32]u8 = [_]u8{0} ** 32;
    key[0] = 0x5A; // Z
    key[1] = 0x4D; // M
    key[2] = 0x52; // R
    key[3] = 0x44; // D
    var i: usize = 4;
    while (i < 32) : (i += 1) {
        key[i] = @intCast((i * 7 + 0x42) & 0xFF);
    }
    return key;
}

// ============================================================================
// Helpers
// ============================================================================

fn pass(name: []const u8) void {
    tests_run += 1;
    tests_passed += 1;
    serial.writeString("  [PASS] ");
    serial.writeString(name);
    serial.writeString("\n");
}

fn fail(name: []const u8) void {
    tests_run += 1;
    tests_failed += 1;
    serial.writeString("  [FAIL] ");
    serial.writeString(name);
    serial.writeString("\n");
}

fn failMsg(name: []const u8, reason: []const u8) void {
    tests_run += 1;
    tests_failed += 1;
    serial.writeString("  [FAIL] ");
    serial.writeString(name);
    serial.writeString(" (");
    serial.writeString(reason);
    serial.writeString(")\n");
}

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn memEqual(a: []const u8, b: []const u8, len: usize) bool {
    if (a.len < len or b.len < len) return false;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn allZero(data: []const u8) bool {
    for (data) |b| {
        if (b != 0) return false;
    }
    return true;
}

// ============================================================================
// Setup: Initialize all subsystems needed for testing
// ============================================================================

fn setupSubsystems() void {
    if (!capability.isInitialized()) capability.init();
    if (!violation.isInitialized()) violation.init();
    if (!message.isInitialized()) message.init();
    if (!pipe.isInitialized()) pipe.init();
    if (!shared_mem.isInitialized()) shared_mem.init();
    sys_encrypt.init();
}

fn setupWithMasterKey() void {
    setupSubsystems();
    var key = getTestKey();
    sys_encrypt.setMasterKeyDirect(&key);
}

// ============================================================================
// Test 1: Initialization
// ============================================================================

fn test01_init() void {
    const name = "01: sys_encrypt init";
    sys_encrypt.init();

    if (!sys_encrypt.isInitialized()) {
        failMsg(name, "not initialized");
        return;
    }

    if (sys_encrypt.isMasterKeySet()) {
        failMsg(name, "master key should not be set");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 2: Set master key from passphrase
// ============================================================================

fn test02_master_key_passphrase() void {
    const name = "02: Master key from passphrase";
    sys_encrypt.init();

    sys_encrypt.setMasterKeyFromPassphrase(TEST_PASSPHRASE);

    if (!sys_encrypt.isMasterKeySet()) {
        failMsg(name, "master key not set");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 3: Set master key directly
// ============================================================================

fn test03_master_key_direct() void {
    const name = "03: Master key direct set";
    sys_encrypt.init();

    var key = getTestKey();
    sys_encrypt.setMasterKeyDirect(&key);

    if (!sys_encrypt.isMasterKeySet()) {
        failMsg(name, "master key not set");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 4: Set master key from identity (public key)
// ============================================================================

fn test04_master_key_identity() void {
    const name = "04: Master key from identity";
    sys_encrypt.init();

    var pubkey: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        pubkey[i] = @intCast((i * 13 + 0xAB) & 0xFF);
    }

    sys_encrypt.setMasterKeyFromIdentity(&pubkey);

    if (!sys_encrypt.isMasterKeySet()) {
        failMsg(name, "master key not set");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 5: Domain key derivation — 4 domains all different
// ============================================================================

fn test05_domain_keys() void {
    const name = "05: Domain key derivation";
    setupWithMasterKey();

    const config_key = sys_encrypt.getDomainKey(.config) orelse {
        failMsg(name, "config key null");
        return;
    };

    const identity_key = sys_encrypt.getDomainKey(.identity) orelse {
        failMsg(name, "identity key null");
        return;
    };

    const ipc_key = sys_encrypt.getDomainKey(.ipc) orelse {
        failMsg(name, "ipc key null");
        return;
    };

    const chain_key = sys_encrypt.getDomainKey(.chain) orelse {
        failMsg(name, "chain key null");
        return;
    };

    if (allZero(config_key)) {
        failMsg(name, "config key all zeros");
        return;
    }

    if (memEqual(config_key, identity_key, 32)) {
        failMsg(name, "config == identity");
        return;
    }

    if (memEqual(config_key, ipc_key, 32)) {
        failMsg(name, "config == ipc");
        return;
    }

    if (memEqual(ipc_key, chain_key, 32)) {
        failMsg(name, "ipc == chain");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 6: Encrypt/Decrypt config domain
// ============================================================================

fn test06_encrypt_config() void {
    const name = "06: Encrypt/decrypt config";
    setupWithMasterKey();

    const plaintext = "hostname=zamrud-node";

    const encrypted = sys_encrypt.encryptConfig(plaintext) orelse {
        failMsg(name, "encrypt failed");
        return;
    };

    if (encrypted.len <= plaintext.len) {
        failMsg(name, "encrypted too short");
        return;
    }

    const decrypted = sys_encrypt.decryptConfig(encrypted) orelse {
        failMsg(name, "decrypt failed");
        return;
    };

    if (!strEqual(decrypted, plaintext)) {
        failMsg(name, "content mismatch");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 7: Encrypt/Decrypt identity domain
// ============================================================================

fn test07_encrypt_identity() void {
    const name = "07: Encrypt/decrypt identity";
    setupWithMasterKey();

    const plaintext = "PRIVKEY:abcdef0123456789";

    const encrypted = sys_encrypt.encryptIdentity(plaintext) orelse {
        failMsg(name, "encrypt failed");
        return;
    };

    const decrypted = sys_encrypt.decryptIdentity(encrypted) orelse {
        failMsg(name, "decrypt failed");
        return;
    };

    if (!strEqual(decrypted, plaintext)) {
        failMsg(name, "content mismatch");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 8: Encrypt/Decrypt IPC domain
// ============================================================================

fn test08_encrypt_ipc() void {
    const name = "08: Encrypt/decrypt IPC";
    setupWithMasterKey();

    const plaintext = "ipc:message:hello-world";

    const encrypted = sys_encrypt.encryptIpc(plaintext) orelse {
        failMsg(name, "encrypt failed");
        return;
    };

    const decrypted = sys_encrypt.decryptIpc(encrypted) orelse {
        failMsg(name, "decrypt failed");
        return;
    };

    if (!strEqual(decrypted, plaintext)) {
        failMsg(name, "content mismatch");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 9: Encrypt/Decrypt chain domain
// ============================================================================

fn test09_encrypt_chain() void {
    const name = "09: Encrypt/decrypt chain";
    setupWithMasterKey();

    const plaintext = "block:hash:0xdeadbeef";

    const encrypted = sys_encrypt.encryptChain(plaintext) orelse {
        failMsg(name, "encrypt failed");
        return;
    };

    const decrypted = sys_encrypt.decryptChain(encrypted) orelse {
        failMsg(name, "decrypt failed");
        return;
    };

    if (!strEqual(decrypted, plaintext)) {
        failMsg(name, "content mismatch");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 10: Cross-domain decrypt must fail
// ============================================================================

fn test10_cross_domain_fail() void {
    const name = "10: Cross-domain rejected";
    setupWithMasterKey();

    const plaintext = "secret-config-data";

    const encrypted = sys_encrypt.encryptConfig(plaintext) orelse {
        failMsg(name, "encrypt failed");
        return;
    };

    // Try decrypt with IDENTITY key — should fail or produce garbage
    if (sys_encrypt.decryptIdentity(encrypted)) |decrypted| {
        if (strEqual(decrypted, plaintext)) {
            failMsg(name, "cross-domain decrypted!");
            return;
        }
    }

    pass(name);
}

// ============================================================================
// Test 11: IPC message encryption (small payload)
// ============================================================================

fn test11_ipc_msg_encrypt() void {
    const name = "11: IPC msg encrypt/decrypt";
    setupWithMasterKey();

    const plaintext = "hello-ipc";
    var enc_buf: [96]u8 = [_]u8{0} ** 96;

    const enc_len = sys_encrypt.encryptIpcMsg(plaintext, &enc_buf);
    if (enc_len == 0) {
        failMsg(name, "encrypt returned 0");
        return;
    }

    if (enc_len < sys_encrypt.IV_SIZE + sys_encrypt.BLOCK_SIZE) {
        failMsg(name, "encrypted too short");
        return;
    }

    var dec_buf: [64]u8 = [_]u8{0} ** 64;
    const dec_len = sys_encrypt.decryptIpcMsg(enc_buf[0..enc_len], &dec_buf);
    if (dec_len == 0) {
        failMsg(name, "decrypt returned 0");
        return;
    }

    if (dec_len != plaintext.len) {
        failMsg(name, "length mismatch");
        return;
    }

    if (!memEqual(&dec_buf, plaintext, plaintext.len)) {
        failMsg(name, "content mismatch");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 12: IPC msg too large rejected
// ============================================================================

fn test12_ipc_msg_too_large() void {
    const name = "12: IPC msg >64 bytes rejected";
    setupWithMasterKey();

    var large_data: [65]u8 = [_]u8{'A'} ** 65;
    var enc_buf: [128]u8 = [_]u8{0} ** 128;

    const enc_len = sys_encrypt.encryptIpcMsg(&large_data, &enc_buf);
    if (enc_len != 0) {
        failMsg(name, "should reject >64 bytes");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 13: IPC msg without master key fails
// ============================================================================

fn test13_ipc_msg_no_key() void {
    const name = "13: IPC msg no key = fail";
    sys_encrypt.init();

    const plaintext = "test";
    var enc_buf: [96]u8 = [_]u8{0} ** 96;

    const enc_len = sys_encrypt.encryptIpcMsg(plaintext, &enc_buf);
    if (enc_len != 0) {
        failMsg(name, "should fail without key");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 14: isEncrypted utility
// ============================================================================

fn test14_is_encrypted() void {
    const name = "14: isEncrypted detection";
    setupWithMasterKey();

    const encrypted = sys_encrypt.encryptConfig("test-data") orelse {
        failMsg(name, "encrypt failed");
        return;
    };

    if (!sys_encrypt.isEncrypted(encrypted)) {
        failMsg(name, "should detect encrypted");
        return;
    }

    const plain = "ZCFG-not-encrypted";
    if (sys_encrypt.isEncrypted(plain)) {
        failMsg(name, "false positive");
        return;
    }

    const short = "ZS";
    if (sys_encrypt.isEncrypted(short)) {
        failMsg(name, "false positive short");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 15: Magic header validation (ZSED)
// ============================================================================

fn test15_magic_header() void {
    const name = "15: ZSED magic header";
    setupWithMasterKey();

    const encrypted = sys_encrypt.encryptConfig("verify-magic") orelse {
        failMsg(name, "encrypt failed");
        return;
    };

    if (encrypted[0] != 'Z' or encrypted[1] != 'S' or
        encrypted[2] != 'E' or encrypted[3] != 'D')
    {
        failMsg(name, "wrong magic bytes");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 16: Config domain encrypt round-trip (larger data)
// ============================================================================

fn test16_config_roundtrip() void {
    const name = "16: Config encrypt round-trip";
    setupWithMasterKey();

    const config_data = "ZCFG\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00key=val";

    const encrypted = sys_encrypt.encryptForDomain(.config, config_data) orelse {
        failMsg(name, "encrypt failed");
        return;
    };

    if (!sys_encrypt.isEncrypted(encrypted)) {
        failMsg(name, "not marked encrypted");
        return;
    }

    const decrypted = sys_encrypt.decryptForDomain(.config, encrypted) orelse {
        failMsg(name, "decrypt failed");
        return;
    };

    if (!strEqual(decrypted, config_data)) {
        failMsg(name, "content mismatch");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 17: Config domain key is deterministic
// ============================================================================

fn test17_config_key_deterministic() void {
    const name = "17: Config key deterministic";

    var key = getTestKey();

    sys_encrypt.init();
    sys_encrypt.setMasterKeyDirect(&key);
    const key1 = sys_encrypt.getDomainKey(.config) orelse {
        failMsg(name, "key1 null");
        return;
    };
    var key1_copy: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        key1_copy[i] = key1[i];
    }

    sys_encrypt.init();
    sys_encrypt.setMasterKeyDirect(&key);
    const key2 = sys_encrypt.getDomainKey(.config) orelse {
        failMsg(name, "key2 null");
        return;
    };

    if (!memEqual(&key1_copy, key2, 32)) {
        failMsg(name, "keys differ");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 18: Identity double encryption concept
// ============================================================================

fn test18_identity_double_encrypt() void {
    const name = "18: Identity double encryption";
    setupWithMasterKey();

    const pin_encrypted_privkey = "PIN_ENC:a1b2c3d4e5f6789012345678";

    const disk_encrypted = sys_encrypt.encryptIdentity(pin_encrypted_privkey) orelse {
        failMsg(name, "disk encrypt failed");
        return;
    };

    const disk_decrypted = sys_encrypt.decryptIdentity(disk_encrypted) orelse {
        failMsg(name, "disk decrypt failed");
        return;
    };

    if (!strEqual(disk_decrypted, pin_encrypted_privkey)) {
        failMsg(name, "content mismatch");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 19: Identity encrypt without key returns null
// ============================================================================

fn test19_identity_no_key() void {
    const name = "19: Identity encrypt no key";
    sys_encrypt.init();

    const result = sys_encrypt.encryptIdentity("should-fail");
    if (result != null) {
        failMsg(name, "should return null");
        return;
    }

    pass(name);
}

// ============================================================================
// Test 20: IPC message.zig encrypted mailbox
// ============================================================================

fn test20_message_encrypted_mailbox() void {
    const name = "20: Message encrypted mailbox";
    setupWithMasterKey();

    message.init();

    const sender_pid: u16 = 50;
    const receiver_pid: u16 = 51;
    _ = capability.registerProcess(sender_pid, capability.CAP_IPC);
    _ = capability.registerProcess(receiver_pid, capability.CAP_IPC);

    if (!message.createMailbox(sender_pid)) {
        failMsg(name, "sender mailbox failed");
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }
    if (!message.createMailbox(receiver_pid)) {
        failMsg(name, "receiver mailbox failed");
        message.destroyMailbox(sender_pid);
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }

    if (!message.setEncryptMode(receiver_pid, true)) {
        failMsg(name, "setEncryptMode failed");
        message.destroyMailbox(sender_pid);
        message.destroyMailbox(receiver_pid);
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }

    const send_data = "encrypted-msg";
    const result = message.send(sender_pid, receiver_pid, .data, send_data);
    if (result != .ok) {
        failMsg(name, "send failed");
        message.destroyMailbox(sender_pid);
        message.destroyMailbox(receiver_pid);
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }

    const recv_result = message.recv(receiver_pid);
    if (!recv_result.success) {
        failMsg(name, "recv failed");
        message.destroyMailbox(sender_pid);
        message.destroyMailbox(receiver_pid);
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }

    if (recv_result.message) |msg| {
        if (msg.data_len == send_data.len and memEqual(msg.getData(), send_data, send_data.len)) {
            // Content matches — success
        } else {
            failMsg(name, "content mismatch");
            message.destroyMailbox(sender_pid);
            message.destroyMailbox(receiver_pid);
            capability.unregisterProcess(sender_pid);
            capability.unregisterProcess(receiver_pid);
            return;
        }
    } else {
        failMsg(name, "no message received");
        message.destroyMailbox(sender_pid);
        message.destroyMailbox(receiver_pid);
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }

    message.destroyMailbox(sender_pid);
    message.destroyMailbox(receiver_pid);
    capability.unregisterProcess(sender_pid);
    capability.unregisterProcess(receiver_pid);

    pass(name);
}

// ============================================================================
// Test 21: IPC sendEncrypted explicit
// ============================================================================

fn test21_send_encrypted_explicit() void {
    const name = "21: sendEncrypted explicit";
    setupWithMasterKey();

    message.init();

    const sender_pid: u16 = 60;
    const receiver_pid: u16 = 61;
    _ = capability.registerProcess(sender_pid, capability.CAP_IPC);
    _ = capability.registerProcess(receiver_pid, capability.CAP_IPC);

    _ = message.createMailbox(sender_pid);
    _ = message.createMailbox(receiver_pid);

    const send_data = "secret-data";
    const result = message.sendEncrypted(sender_pid, receiver_pid, send_data);
    if (result != .ok) {
        failMsg(name, "sendEncrypted failed");
        message.destroyMailbox(sender_pid);
        message.destroyMailbox(receiver_pid);
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }

    const recv_result = message.recv(receiver_pid);
    if (!recv_result.success or recv_result.message == null) {
        failMsg(name, "recv failed");
        message.destroyMailbox(sender_pid);
        message.destroyMailbox(receiver_pid);
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }

    const msg = recv_result.message.?;
    if (msg.data_len != send_data.len or !memEqual(msg.getData(), send_data, send_data.len)) {
        failMsg(name, "content mismatch");
        message.destroyMailbox(sender_pid);
        message.destroyMailbox(receiver_pid);
        capability.unregisterProcess(sender_pid);
        capability.unregisterProcess(receiver_pid);
        return;
    }

    message.destroyMailbox(sender_pid);
    message.destroyMailbox(receiver_pid);
    capability.unregisterProcess(sender_pid);
    capability.unregisterProcess(receiver_pid);

    pass(name);
}

// ============================================================================
// Test 22: Pipe encrypted create and write/read
// ============================================================================

fn test22_pipe_encrypted() void {
    const name = "22: Pipe encrypted write/read";
    setupWithMasterKey();

    pipe.init();

    const writer_pid: u16 = 70;
    const reader_pid: u16 = 71;
    _ = capability.registerProcess(writer_pid, capability.CAP_IPC);
    _ = capability.registerProcess(reader_pid, capability.CAP_IPC);

    const pipe_id = pipe.createEncrypted(writer_pid, reader_pid) orelse {
        failMsg(name, "createEncrypted failed");
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    };

    if (!pipe.isEncrypted(pipe_id)) {
        failMsg(name, "pipe not encrypted");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    const write_data = "pipe-secret";
    const write_result = pipe.write(pipe_id, writer_pid, write_data);
    if (write_result.result != .ok) {
        failMsg(name, "write failed");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    var read_buf: [64]u8 = [_]u8{0} ** 64;
    const read_result = pipe.read(pipe_id, reader_pid, &read_buf);
    if (read_result.result != .ok) {
        failMsg(name, "read failed");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    if (read_result.bytes_read != write_data.len) {
        failMsg(name, "length mismatch");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    if (!memEqual(&read_buf, write_data, write_data.len)) {
        failMsg(name, "content mismatch");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    _ = pipe.close(pipe_id);
    capability.unregisterProcess(writer_pid);
    capability.unregisterProcess(reader_pid);

    pass(name);
}

// ============================================================================
// Test 23: Pipe non-encrypted still works
// ============================================================================

fn test23_pipe_plain() void {
    const name = "23: Pipe plain works";
    setupWithMasterKey();

    pipe.init();

    const writer_pid: u16 = 80;
    const reader_pid: u16 = 81;
    _ = capability.registerProcess(writer_pid, capability.CAP_IPC);
    _ = capability.registerProcess(reader_pid, capability.CAP_IPC);

    const pipe_id = pipe.create(writer_pid, reader_pid) orelse {
        failMsg(name, "create failed");
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    };

    if (pipe.isEncrypted(pipe_id)) {
        failMsg(name, "should NOT be encrypted");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    const write_data = "plain-pipe-data";
    const write_result = pipe.write(pipe_id, writer_pid, write_data);
    if (write_result.result != .ok) {
        failMsg(name, "write failed");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    var read_buf: [64]u8 = [_]u8{0} ** 64;
    const read_result = pipe.read(pipe_id, reader_pid, &read_buf);
    if (read_result.result != .ok or read_result.bytes_read != write_data.len) {
        failMsg(name, "read failed");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    if (!memEqual(&read_buf, write_data, write_data.len)) {
        failMsg(name, "content mismatch");
        _ = pipe.close(pipe_id);
        capability.unregisterProcess(writer_pid);
        capability.unregisterProcess(reader_pid);
        return;
    }

    _ = pipe.close(pipe_id);
    capability.unregisterProcess(writer_pid);
    capability.unregisterProcess(reader_pid);

    pass(name);
}

// ============================================================================
// Test 24: Shared memory encrypted region
// ============================================================================

fn test24_shared_mem_encrypted() void {
    const name = "24: Shared mem encrypted";
    setupWithMasterKey();

    shared_mem.init();

    const owner_pid: u16 = 90;
    _ = capability.registerProcess(owner_pid, capability.CAP_MEMORY | capability.CAP_IPC);

    const create_result = shared_mem.createEncrypted(owner_pid, "enc-test", 1024);
    if (create_result.result != .ok) {
        failMsg(name, "createEncrypted failed");
        capability.unregisterProcess(owner_pid);
        return;
    }

    const region_id = create_result.id;

    if (!shared_mem.isRegionEncrypted(region_id)) {
        failMsg(name, "region not encrypted");
        _ = shared_mem.destroy(owner_pid, region_id);
        capability.unregisterProcess(owner_pid);
        return;
    }

    const write_data = "shm-encrypted-payload";
    const write_result = shared_mem.writeData(owner_pid, region_id, 0, write_data);
    if (write_result.result != .ok) {
        failMsg(name, "write failed");
        _ = shared_mem.destroy(owner_pid, region_id);
        capability.unregisterProcess(owner_pid);
        return;
    }

    var read_buf: [64]u8 = [_]u8{0} ** 64;
    const read_result = shared_mem.readData(owner_pid, region_id, 0, read_buf[0..write_data.len]);
    if (read_result.result != .ok) {
        failMsg(name, "read failed");
        _ = shared_mem.destroy(owner_pid, region_id);
        capability.unregisterProcess(owner_pid);
        return;
    }

    if (read_result.bytes_read != write_data.len) {
        failMsg(name, "length mismatch");
        _ = shared_mem.destroy(owner_pid, region_id);
        capability.unregisterProcess(owner_pid);
        return;
    }

    if (!memEqual(&read_buf, write_data, write_data.len)) {
        failMsg(name, "content mismatch");
        _ = shared_mem.destroy(owner_pid, region_id);
        capability.unregisterProcess(owner_pid);
        return;
    }

    _ = shared_mem.destroy(owner_pid, region_id);
    capability.unregisterProcess(owner_pid);

    pass(name);
}

// ============================================================================
// Test 25: Stats tracking and key clearing
// ============================================================================

fn test25_stats_and_clear() void {
    const name = "25: Stats & key clear";
    setupWithMasterKey();
    sys_encrypt.resetStats();

    // Encrypt #1 — config
    const enc1 = sys_encrypt.encryptConfig("stats-test-1") orelse {
        failMsg(name, "encrypt 1 failed");
        return;
    };

    // IMPORTANT: copy enc1 to local buffer before next encrypt
    // because sys_encrypt uses a single static encrypt_buf
    var enc1_copy: [256]u8 = [_]u8{0} ** 256;
    const enc1_len = enc1.len;
    var ci: usize = 0;
    while (ci < enc1_len) : (ci += 1) {
        enc1_copy[ci] = enc1[ci];
    }

    // Encrypt #2 — identity (this overwrites sys_encrypt's static buffer)
    _ = sys_encrypt.encryptIdentity("stats-test-2");

    // Decrypt #1 using our saved copy
    _ = sys_encrypt.decryptConfig(enc1_copy[0..enc1_len]) orelse {
        failMsg(name, "decrypt failed");
        return;
    };

    // Check stats
    const s = sys_encrypt.getStats();
    if (s.encrypts < 2) {
        failMsg(name, "encrypt count wrong");
        return;
    }
    if (s.decrypts < 1) {
        failMsg(name, "decrypt count wrong");
        return;
    }

    // Clear master key
    sys_encrypt.clearMasterKey();

    if (sys_encrypt.isMasterKeySet()) {
        failMsg(name, "key should be cleared");
        return;
    }

    // Operations should fail after clearing
    if (sys_encrypt.encryptConfig("should-fail") != null) {
        failMsg(name, "should fail after clear");
        return;
    }

    // Domain keys should be gone
    if (sys_encrypt.getDomainKey(.config) != null) {
        failMsg(name, "domain key should be null");
        return;
    }

    pass(name);
}

// ============================================================================
// Main Test Runner
// ============================================================================

pub fn runTests() bool {
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;

    serial.writeString("\n");
    serial.writeString("+=============================================+\n");
    serial.writeString("|  F4.2: System Data Encryption Tests         |\n");
    serial.writeString("+=============================================+\n");

    test01_init();
    test02_master_key_passphrase();
    test03_master_key_direct();
    test04_master_key_identity();
    test05_domain_keys();
    test06_encrypt_config();
    test07_encrypt_identity();
    test08_encrypt_ipc();
    test09_encrypt_chain();
    test10_cross_domain_fail();
    test11_ipc_msg_encrypt();
    test12_ipc_msg_too_large();
    test13_ipc_msg_no_key();
    test14_is_encrypted();
    test15_magic_header();
    test16_config_roundtrip();
    test17_config_key_deterministic();
    test18_identity_double_encrypt();
    test19_identity_no_key();
    test20_message_encrypted_mailbox();
    test21_send_encrypted_explicit();
    test22_pipe_encrypted();
    test23_pipe_plain();
    test24_shared_mem_encrypted();
    test25_stats_and_clear();

    serial.writeString("+=============================================+\n");
    serial.writeString("|  Results: ");
    printNum(tests_passed);
    serial.writeString("/");
    printNum(tests_run);

    if (tests_failed == 0) {
        serial.writeString(" ALL PASSED              |\n");
    } else {
        serial.writeString(" FAILED: ");
        printNum(tests_failed);
        serial.writeString("                  |\n");
    }

    serial.writeString("+=============================================+\n\n");

    return tests_failed == 0;
}

// ============================================================================
// Print Helper
// ============================================================================

fn printNum(n: u32) void {
    if (n == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = n;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
