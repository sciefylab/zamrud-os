//! Zamrud OS - F1: IPC Message Passing
//! F4.2: Optional encrypted message channels
//! Capability-gated: requires CAP_IPC

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");
const capability = @import("../security/capability.zig");
const violation = @import("../security/violation.zig");
const sys_encrypt = @import("../crypto/sys_encrypt.zig");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_MAILBOXES = 64;
pub const MAX_MESSAGES_PER_BOX = 16;
pub const MAX_MSG_DATA = 64;
pub const MAX_MSG_TOTAL = MAX_MAILBOXES * MAX_MESSAGES_PER_BOX;

// F4.2: Encrypted message buffer (IV + ciphertext for 64-byte payload)
pub const MAX_ENC_MSG_DATA = 96; // IV(16) + encrypted(80 max with padding)

// ============================================================================
// Types
// ============================================================================

pub const MsgType = enum(u8) {
    data = 0,
    signal = 1,
    request = 2,
    reply = 3,
    broadcast = 4,
    system = 5,
    encrypted = 6, // F4.2: encrypted payload
};

pub const Message = struct {
    sender_pid: u16 = 0,
    receiver_pid: u16 = 0,
    msg_type: MsgType = .data,
    msg_id: u32 = 0,
    timestamp: u64 = 0,
    data: [MAX_MSG_DATA]u8 = [_]u8{0} ** MAX_MSG_DATA,
    data_len: u8 = 0,
    valid: bool = false,
    /// F4.2: encrypted data (stored alongside or instead of .data)
    enc_data: [MAX_ENC_MSG_DATA]u8 = [_]u8{0} ** MAX_ENC_MSG_DATA,
    enc_data_len: u8 = 0,
    is_encrypted: bool = false,

    pub fn getData(self: *const Message) []const u8 {
        return self.data[0..self.data_len];
    }
};

pub const Mailbox = struct {
    pid: u16 = 0,
    active: bool = false,
    messages: [MAX_MESSAGES_PER_BOX]Message = [_]Message{.{}} ** MAX_MESSAGES_PER_BOX,
    head: u8 = 0,
    tail: u8 = 0,
    count: u8 = 0,
    total_received: u64 = 0,
    total_dropped: u64 = 0,
    /// F4.2: if true, ALL messages to this mailbox are auto-encrypted
    encrypt_mode: bool = false,
};

pub const SendResult = enum(u8) {
    ok = 0,
    no_cap = 1,
    no_mailbox = 2,
    mailbox_full = 3,
    invalid_pid = 4,
    self_send = 5,
    killed = 6,
    encrypt_failed = 7, // F4.2
};

pub const RecvResult = struct {
    success: bool,
    message: ?Message,
};

pub const MsgStats = struct {
    total_sent: u64 = 0,
    total_received: u64 = 0,
    total_dropped: u64 = 0,
    total_broadcasts: u64 = 0,
    cap_violations: u64 = 0,
    encrypted_sent: u64 = 0, // F4.2
    encrypted_recv: u64 = 0, // F4.2
};

// ============================================================================
// Storage
// ============================================================================

var mailboxes: [MAX_MAILBOXES]Mailbox = undefined;
var mailbox_count: usize = 0;
var next_msg_id: u32 = 1;
pub var stats = MsgStats{};
var initialized: bool = false;

// ============================================================================
// Init
// ============================================================================

pub fn init() void {
    for (&mailboxes) |*mb| {
        mb.* = Mailbox{};
    }
    mailbox_count = 0;
    next_msg_id = 1;
    stats = MsgStats{};
    initialized = true;

    serial.writeString("[IPC-MSG] Message passing initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Mailbox Management
// ============================================================================

pub fn createMailbox(pid: u16) bool {
    if (!initialized) return false;
    if (findMailbox(pid) != null) return true;

    for (&mailboxes) |*mb| {
        if (!mb.active) {
            mb.* = Mailbox{};
            mb.pid = pid;
            mb.active = true;
            mailbox_count += 1;

            serial.writeString("[IPC-MSG] Mailbox created pid=");
            printNum(pid);
            serial.writeString("\n");
            return true;
        }
    }
    return false;
}

pub fn destroyMailbox(pid: u16) void {
    if (findMailbox(pid)) |mb| {
        mb.active = false;
        mb.pid = 0;
        mb.count = 0;
        if (mailbox_count > 0) mailbox_count -= 1;
    }
}

pub fn hasMailbox(pid: u16) bool {
    return findMailbox(pid) != null;
}

/// F4.2: Enable encryption mode for a mailbox
pub fn setEncryptMode(pid: u16, enabled: bool) bool {
    const mb = findMailbox(pid) orelse return false;
    mb.encrypt_mode = enabled;
    serial.writeString("[IPC-MSG] Encrypt mode ");
    serial.writeString(if (enabled) "ON" else "OFF");
    serial.writeString(" for pid=");
    printNum(pid);
    serial.writeString("\n");
    return true;
}

/// F4.2: Check if mailbox has encryption mode
pub fn isEncryptMode(pid: u16) bool {
    const mb = findMailbox(pid) orelse return false;
    return mb.encrypt_mode;
}

fn findMailbox(pid: u16) ?*Mailbox {
    for (&mailboxes) |*mb| {
        if (mb.active and mb.pid == pid) return mb;
    }
    return null;
}

// ============================================================================
// Send Message — CAP_IPC enforced
// ============================================================================

pub fn send(sender_pid: u16, receiver_pid: u16, msg_type: MsgType, data: []const u8) SendResult {
    if (sender_pid != 0) {
        if (!capability.check(sender_pid, capability.CAP_IPC)) {
            stats.cap_violations += 1;
            reportIpcViolation(sender_pid, "send without CAP_IPC");
            return .no_cap;
        }
    }

    if (sender_pid == receiver_pid and sender_pid != 0) return .self_send;

    const mb = findMailbox(receiver_pid) orelse return .no_mailbox;

    if (mb.count >= MAX_MESSAGES_PER_BOX) {
        mb.total_dropped += 1;
        stats.total_dropped += 1;
        return .mailbox_full;
    }

    const msg_id = next_msg_id;
    next_msg_id += 1;

    var msg = Message{};
    msg.sender_pid = sender_pid;
    msg.receiver_pid = receiver_pid;
    msg.msg_type = msg_type;
    msg.msg_id = msg_id;
    msg.timestamp = timer.getTicks();
    msg.valid = true;

    const copy_len = @min(data.len, MAX_MSG_DATA);
    for (0..copy_len) |i| {
        msg.data[i] = data[i];
    }
    msg.data_len = @intCast(copy_len);

    // F4.2: Auto-encrypt if receiver mailbox has encrypt_mode
    if (mb.encrypt_mode and msg_type != .encrypted) {
        if (sys_encrypt.isInitialized() and sys_encrypt.isMasterKeySet()) {
            const enc_len = sys_encrypt.encryptIpcMsg(
                data[0..copy_len],
                &msg.enc_data,
            );
            if (enc_len > 0) {
                msg.enc_data_len = @intCast(enc_len);
                msg.is_encrypted = true;
                msg.msg_type = .encrypted;
                // Clear plaintext
                for (0..MAX_MSG_DATA) |ci| {
                    msg.data[ci] = 0;
                }
                msg.data_len = 0;
                stats.encrypted_sent += 1;
            }
            // If encryption fails, send plaintext (graceful degradation)
        }
    }

    mb.messages[mb.tail] = msg;
    mb.tail = (mb.tail + 1) % MAX_MESSAGES_PER_BOX;
    mb.count += 1;
    mb.total_received += 1;
    stats.total_sent += 1;

    return .ok;
}

// ============================================================================
// F4.2: Send Encrypted Message (explicit)
// ============================================================================

/// Send a message with explicit encryption regardless of mailbox mode
pub fn sendEncrypted(sender_pid: u16, receiver_pid: u16, data: []const u8) SendResult {
    if (!sys_encrypt.isInitialized() or !sys_encrypt.isMasterKeySet()) {
        return .encrypt_failed;
    }

    if (sender_pid != 0) {
        if (!capability.check(sender_pid, capability.CAP_IPC)) {
            stats.cap_violations += 1;
            reportIpcViolation(sender_pid, "sendEncrypted without CAP_IPC");
            return .no_cap;
        }
    }

    if (sender_pid == receiver_pid and sender_pid != 0) return .self_send;

    const mb = findMailbox(receiver_pid) orelse return .no_mailbox;

    if (mb.count >= MAX_MESSAGES_PER_BOX) {
        mb.total_dropped += 1;
        stats.total_dropped += 1;
        return .mailbox_full;
    }

    var msg = Message{};
    msg.sender_pid = sender_pid;
    msg.receiver_pid = receiver_pid;
    msg.msg_type = .encrypted;
    msg.msg_id = next_msg_id;
    next_msg_id += 1;
    msg.timestamp = timer.getTicks();
    msg.valid = true;
    msg.is_encrypted = true;

    const copy_len = @min(data.len, MAX_MSG_DATA);
    const enc_len = sys_encrypt.encryptIpcMsg(
        data[0..copy_len],
        &msg.enc_data,
    );
    if (enc_len == 0) return .encrypt_failed;

    msg.enc_data_len = @intCast(enc_len);
    stats.encrypted_sent += 1;

    mb.messages[mb.tail] = msg;
    mb.tail = (mb.tail + 1) % MAX_MESSAGES_PER_BOX;
    mb.count += 1;
    mb.total_received += 1;
    stats.total_sent += 1;

    return .ok;
}

// ============================================================================
// Receive Message — CAP_IPC enforced, auto-decrypt
// ============================================================================

pub fn recv(pid: u16) RecvResult {
    if (pid != 0) {
        if (!capability.check(pid, capability.CAP_IPC)) {
            stats.cap_violations += 1;
            reportIpcViolation(pid, "recv without CAP_IPC");
            return .{ .success = false, .message = null };
        }
    }

    const mb = findMailbox(pid) orelse {
        return .{ .success = false, .message = null };
    };

    if (mb.count == 0) {
        return .{ .success = true, .message = null };
    }

    var msg = mb.messages[mb.head];
    mb.messages[mb.head] = Message{};
    mb.head = (mb.head + 1) % MAX_MESSAGES_PER_BOX;
    mb.count -= 1;
    stats.total_received += 1;

    // F4.2: Auto-decrypt encrypted messages
    if (msg.is_encrypted and msg.enc_data_len > 0) {
        if (sys_encrypt.isInitialized() and sys_encrypt.isMasterKeySet()) {
            var dec_buf: [MAX_MSG_DATA]u8 = [_]u8{0} ** MAX_MSG_DATA;
            const dec_len = sys_encrypt.decryptIpcMsg(
                msg.enc_data[0..msg.enc_data_len],
                &dec_buf,
            );
            if (dec_len > 0) {
                // Restore plaintext
                for (0..dec_len) |di| {
                    msg.data[di] = dec_buf[di];
                }
                msg.data_len = @intCast(dec_len);
                msg.is_encrypted = false;
                msg.msg_type = .data; // Restore original type
                stats.encrypted_recv += 1;
            }
            // If decrypt fails, return encrypted message as-is
        }
    }

    return .{ .success = true, .message = msg };
}

pub fn peek(pid: u16) ?*const Message {
    const mb = findMailbox(pid) orelse return null;
    if (mb.count == 0) return null;
    return &mb.messages[mb.head];
}

pub fn pendingCount(pid: u16) u8 {
    const mb = findMailbox(pid) orelse return 0;
    return mb.count;
}

// ============================================================================
// Broadcast
// ============================================================================

pub fn broadcast(sender_pid: u16, msg_type: MsgType, data: []const u8) u32 {
    if (sender_pid != 0) {
        if (!capability.check(sender_pid, capability.CAP_IPC)) {
            stats.cap_violations += 1;
            reportIpcViolation(sender_pid, "broadcast without CAP_IPC");
            return 0;
        }
    }

    var sent: u32 = 0;
    for (&mailboxes) |*mb| {
        if (mb.active and mb.pid != sender_pid) {
            const result = send(sender_pid, mb.pid, msg_type, data);
            if (result == .ok) sent += 1;
        }
    }

    stats.total_broadcasts += 1;
    return sent;
}

// ============================================================================
// Violation Reporting
// ============================================================================

fn reportIpcViolation(pid: u16, reason: []const u8) void {
    if (!violation.isInitialized()) return;

    _ = violation.reportViolation(.{
        .violation_type = .ipc_unauthorized,
        .severity = .medium,
        .pid = pid,
        .source_ip = 0,
        .detail = reason,
    });
}

// ============================================================================
// Query API
// ============================================================================

pub fn getStats() MsgStats {
    return stats;
}

pub fn resetStats() void {
    stats = MsgStats{};
}

pub fn getMailboxCount() usize {
    var count: usize = 0;
    for (&mailboxes) |*mb| {
        if (mb.active) count += 1;
    }
    return count;
}

pub fn getMailboxInfo(pid: u16) ?struct {
    pending: u8,
    total_received: u64,
    total_dropped: u64,
    encrypt_mode: bool,
} {
    const mb = findMailbox(pid) orelse return null;
    return .{
        .pending = mb.count,
        .total_received = mb.total_received,
        .total_dropped = mb.total_dropped,
        .encrypt_mode = mb.encrypt_mode,
    };
}

// ============================================================================
// Display
// ============================================================================

pub fn printStatus() void {
    serial.writeString("\n=== IPC MESSAGE STATUS ===\n");
    serial.writeString("  Mailboxes: ");
    printNum(getMailboxCount());
    serial.writeString("/");
    printNum(MAX_MAILBOXES);
    serial.writeString("\n  Sent:      ");
    printNum64(stats.total_sent);
    serial.writeString("\n  Received:  ");
    printNum64(stats.total_received);
    serial.writeString("\n  Dropped:   ");
    printNum64(stats.total_dropped);
    serial.writeString("\n  Broadcasts:");
    printNum64(stats.total_broadcasts);
    serial.writeString("\n  CAP viols: ");
    printNum64(stats.cap_violations);
    serial.writeString("\n  Enc sent:  ");
    printNum64(stats.encrypted_sent);
    serial.writeString("\n  Enc recv:  ");
    printNum64(stats.encrypted_recv);
    serial.writeString("\n");
}

// ============================================================================
// Helpers
// ============================================================================

fn printNum(n: anytype) void {
    const val: u32 = @intCast(n);
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

fn printNum64(n: u64) void {
    if (n <= 0xFFFFFFFF) {
        printNum(@as(u32, @intCast(n)));
    } else {
        serial.writeString(">4G");
    }
}
