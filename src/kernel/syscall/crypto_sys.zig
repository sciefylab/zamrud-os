//! Zamrud OS - Crypto Syscalls
//! System call handlers for cryptographic operations

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const hash = crypto.hash;
const random = crypto.random;
const numbers = @import("numbers.zig");

// =============================================================================
// Hashing
// =============================================================================

/// SYS_CRYPTO_HASH: Compute SHA-256 hash
/// Args: rdi = data_ptr, rsi = data_len, rdx = out_hash (32 bytes)
/// Returns: 32 on success
pub fn sysCryptoHash(data_ptr: usize, data_len: usize, out_hash: usize) isize {
    if (data_ptr == 0 or out_hash == 0) return numbers.EFAULT;
    if (data_len > 0x100000) return numbers.EINVAL; // Max 1MB

    const data: []const u8 = @as([*]const u8, @ptrFromInt(data_ptr))[0..data_len];
    const out: *[32]u8 = @ptrFromInt(out_hash);

    hash.sha256Into(data, out);

    return 32;
}

// =============================================================================
// Random
// =============================================================================

/// SYS_CRYPTO_RANDOM: Get random bytes
/// Args: rdi = out_buf, rsi = count
/// Returns: Number of bytes written
pub fn sysCryptoRandom(out_buf: usize, count: usize) isize {
    if (out_buf == 0) return numbers.EFAULT;
    if (count == 0 or count > 256) return numbers.EINVAL;

    const buf: [*]u8 = @ptrFromInt(out_buf);

    // Fill buffer with random bytes
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var byte: [1]u8 = undefined;
        random.getBytes(&byte);
        buf[i] = byte[0];
    }

    return @intCast(count);
}
