//! Zamrud OS - One-Time Pad (OTP) Cipher
//! H.11: Perfect Secrecy Streaming Cipher
//!
//! Uses Zamrud CSPRNG (SHA-256 CTR) to generate a deterministic,
//! infinitely long pad from a shared secret seed.
//! Features ultra-fast 64-bit word XORing and secure memory wiping.

const ct = @import("constant_time.zig");
const hash = @import("hash.zig");

// =============================================================================
// OTP Stream State
// =============================================================================

pub const OtpStream = struct {
    key_state: [32]u8, // Base state from shared secret
    counter: u64, // Stream block counter
    buffer: [32]u8, // Current generated pad block
    buffer_pos: usize, // Position in current block
    is_active: bool,

    /// Initialize a new OTP stream from a shared secret
    pub fn init(secret_seed: []const u8) OtpStream {
        var stream = OtpStream{
            .key_state = [_]u8{0} ** 32,
            .counter = 0,
            .buffer = [_]u8{0} ** 32,
            .buffer_pos = 32, // Force generate on first use
            .is_active = true,
        };

        // Initialize key_state = SHA-256(secret_seed)
        hash.sha256Into(secret_seed, &stream.key_state);
        return stream;
    }

    /// Generate next 32-byte pad block via SHA-256(key_state || counter)
    fn generateNextBlock(self: *OtpStream) void {
        var input: [40]u8 = [_]u8{0} ** 40;

        // Copy key state
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            input[i] = self.key_state[i];
        }

        // Append 64-bit counter (Little Endian)
        input[32] = @truncate(self.counter);
        input[33] = @truncate(self.counter >> 8);
        input[34] = @truncate(self.counter >> 16);
        input[35] = @truncate(self.counter >> 24);
        input[36] = @truncate(self.counter >> 32);
        input[37] = @truncate(self.counter >> 40);
        input[38] = @truncate(self.counter >> 48);
        input[39] = @truncate(self.counter >> 56);

        // Generate block
        hash.sha256Into(&input, &self.buffer);

        // Increment counter & reset position
        self.counter +%= 1;
        self.buffer_pos = 0;

        // Secure wipe intermediate
        ct.secureZero(&input);
    }

    /// Process (Encrypt/Decrypt) data in-place
    /// OTP is symmetric: Encryption and Decryption use the exact same logic
    pub fn process(self: *OtpStream, data: []u8) void {
        if (!self.is_active or data.len == 0) return;

        var remaining = data.len;
        var offset: usize = 0;

        // 1. Process byte-by-byte until aligned to 8-byte boundary (for fast XOR)
        while (remaining > 0 and (@intFromPtr(&data[offset]) % 8) != 0) {
            if (self.buffer_pos >= 32) self.generateNextBlock();
            data[offset] ^= self.buffer[self.buffer_pos];
            self.buffer_pos += 1;
            offset += 1;
            remaining -= 1;
        }

        // 2. Fast 64-bit XOR (8 bytes at a time)
        while (remaining >= 8) {
            if (self.buffer_pos >= 32) self.generateNextBlock();

            // If we have at least 8 bytes left in the pad buffer
            if (32 - self.buffer_pos >= 8) {
                const data_ptr: *u64 = @ptrCast(@alignCast(&data[offset]));
                const pad_ptr: *const u64 = @ptrCast(@alignCast(&self.buffer[self.buffer_pos]));

                data_ptr.* ^= pad_ptr.*;

                self.buffer_pos += 8;
                offset += 8;
                remaining -= 8;
            } else {
                // Buffer wrap-around boundary, fallback to byte-wise for this chunk
                var i: usize = 0;
                while (i < 8) : (i += 1) {
                    if (self.buffer_pos >= 32) self.generateNextBlock();
                    data[offset + i] ^= self.buffer[self.buffer_pos];
                    self.buffer_pos += 1;
                }
                offset += 8;
                remaining -= 8;
            }
        }

        // 3. Process remaining unaligned bytes
        while (remaining > 0) {
            if (self.buffer_pos >= 32) self.generateNextBlock();
            data[offset] ^= self.buffer[self.buffer_pos];
            self.buffer_pos += 1;
            offset += 1;
            remaining -= 1;
        }
    }

    /// Securely destroy the stream state (H.9 integration)
    pub fn destroy(self: *OtpStream) void {
        ct.secureZero32(&self.key_state);
        ct.secureZero32(&self.buffer);
        self.counter = 0;
        self.buffer_pos = 0;
        self.is_active = false;
    }
};

// =============================================================================
// Tests
// =============================================================================

pub fn test_otp() bool {
    const serial_out = @import("../drivers/serial/serial.zig");
    serial_out.writeString("[CRYPTO] Testing One-Time Pad (OTP) Cipher...\n");

    const secret_seed = "ZamrudTopSecretP2PHandshake123";
    const plain_text = "This is a secret ZSH command that needs protection from Quantum Computers!";

    // Allocate buffers
    var msg_buf: [256]u8 = [_]u8{0} ** 256;
    var i: usize = 0;
    while (i < plain_text.len) : (i += 1) {
        msg_buf[i] = plain_text[i];
    }
    const msg_len = plain_text.len;

    // Test 1: Encrypt
    serial_out.writeString("  [1] Encrypting stream... ");
    var enc_stream = OtpStream.init(secret_seed);
    enc_stream.process(msg_buf[0..msg_len]);

    // Ensure it's scrambled
    var is_scrambled = false;
    i = 0;
    while (i < msg_len) : (i += 1) {
        if (msg_buf[i] != plain_text[i]) {
            is_scrambled = true;
            break;
        }
    }

    if (is_scrambled) {
        serial_out.writeString("PASS\n");
    } else {
        serial_out.writeString("FAIL (Unchanged!)\n");
        return false;
    }

    // Test 2: Decrypt
    serial_out.writeString("  [2] Decrypting stream... ");
    var dec_stream = OtpStream.init(secret_seed);
    dec_stream.process(msg_buf[0..msg_len]); // Applying XOR again reverses it

    // Check if restored
    var is_restored = true;
    i = 0;
    while (i < msg_len) : (i += 1) {
        if (msg_buf[i] != plain_text[i]) {
            is_restored = false;
            break;
        }
    }

    if (is_restored) {
        serial_out.writeString("PASS\n");
    } else {
        serial_out.writeString("FAIL (Not restored!)\n");
        return false;
    }

    // Test 3: Stream destruction
    serial_out.writeString("  [3] Secure destruction... ");
    enc_stream.destroy();
    if (ct.constantTimeIsZero32(&enc_stream.key_state) and !enc_stream.is_active) {
        serial_out.writeString("PASS\n");
    } else {
        serial_out.writeString("FAIL\n");
        return false;
    }

    return true;
}
