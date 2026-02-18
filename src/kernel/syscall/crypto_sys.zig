//! Zamrud OS - Crypto Syscall Dispatcher
//! SC1: Fixed types (i64/u64), added dispatch(), matches numbers.zig

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const numbers = @import("numbers.zig");

// =============================================================================
// Dispatcher — called from table.zig
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64) i64 {
    return switch (num) {
        numbers.SYS_CRYPTO_HASH => sysCryptoHash(a1, a2, a3),
        numbers.SYS_CRYPTO_HMAC => numbers.ENOSYS, // TODO
        numbers.SYS_CRYPTO_RANDOM => sysCryptoRandom(a1, a2),
        numbers.SYS_CRYPTO_SIGN => numbers.ENOSYS, // TODO
        numbers.SYS_CRYPTO_VERIFY => numbers.ENOSYS, // TODO
        numbers.SYS_CRYPTO_DERIVE_KEY => numbers.ENOSYS, // TODO
        else => numbers.ENOSYS,
    };
}

// =============================================================================
// Pointer Validation
// =============================================================================

fn validatePtr(ptr: u64, len: u64) bool {
    if (ptr == 0) return false;
    if (len == 0) return true;
    const result = @addWithOverflow(ptr, len);
    return result[1] == 0;
}

// =============================================================================
// Hashing
// =============================================================================

fn sysCryptoHash(data_ptr: u64, data_len: u64, out_hash: u64) i64 {
    if (!validatePtr(data_ptr, data_len)) return numbers.EFAULT;
    if (!validatePtr(out_hash, 32)) return numbers.EFAULT;
    if (data_len > 0x100000) return numbers.EINVAL; // Max 1MB

    const data: []const u8 = @as([*]const u8, @ptrFromInt(data_ptr))[0..@intCast(data_len)];
    const out: *[32]u8 = @ptrFromInt(out_hash);

    crypto.hash.sha256Into(data, out);

    return 32;
}

// =============================================================================
// Random
// =============================================================================

fn sysCryptoRandom(out_buf: u64, count: u64) i64 {
    if (!validatePtr(out_buf, count)) return numbers.EFAULT;
    if (count == 0 or count > 256) return numbers.EINVAL;

    const buf: [*]u8 = @ptrFromInt(out_buf);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        var byte: [1]u8 = undefined;
        crypto.random.getBytes(&byte);
        buf[i] = byte[0];
    }

    return @intCast(count);
}
