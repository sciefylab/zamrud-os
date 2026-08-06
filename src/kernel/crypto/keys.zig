//! Zamrud OS - Key Management & Seed Phrases
//!
//! This module owns mnemonic generation and deterministic 32-byte seed
//! derivation only. It deliberately does not own a signature key pair.
//! Production signatures are handled by crypto/gov_sign.zig.

const serial = @import("../drivers/serial/serial.zig");
const random = @import("random.zig");
const hash = @import("hash.zig");
const constant_time = @import("constant_time.zig");
const wordlist = @import("wordlist.zig");

pub const SEED_SIZE: usize = 32;
pub const WORDLIST = wordlist.WORDLIST;
pub const WORDLIST_SIZE = wordlist.WORDLIST_SIZE;
pub const getWord = wordlist.getWord;
pub const findWord = wordlist.findWord;
pub const isValidWord = wordlist.isValidWord;

pub const MNEMONIC_12_WORDS: usize = 12;
pub const MNEMONIC_24_WORDS: usize = 24;

var static_indices: [MNEMONIC_24_WORDS]u16 =
    [_]u16{0} ** MNEMONIC_24_WORDS;
var static_entropy: [SEED_SIZE]u8 = [_]u8{0} ** SEED_SIZE;
var static_data: [MNEMONIC_24_WORDS * 2]u8 =
    [_]u8{0} ** (MNEMONIC_24_WORDS * 2);
var static_seed_result: [SEED_SIZE]u8 = [_]u8{0} ** SEED_SIZE;
var static_test_seed_a: [SEED_SIZE]u8 = [_]u8{0} ** SEED_SIZE;
var static_test_seed_b: [SEED_SIZE]u8 = [_]u8{0} ** SEED_SIZE;

pub const SeedPhrase = struct {
    word_count: usize,

    pub fn generate() SeedPhrase {
        return generateWithLength(MNEMONIC_12_WORDS);
    }

    pub fn generateWithLength(count: usize) SeedPhrase {
        const word_count = if (count == MNEMONIC_24_WORDS)
            MNEMONIC_24_WORDS
        else
            MNEMONIC_12_WORDS;

        clearMnemonicState();
        random.getBytes(&static_entropy);

        var bit_pos: usize = 0;
        var i: usize = 0;
        while (i < word_count) : (i += 1) {
            static_indices[i] = extractBits(&static_entropy, bit_pos, 11);
            bit_pos += 11;
        }

        constant_time.secureZero32(&static_entropy);
        return .{ .word_count = word_count };
    }

    pub fn getWordAt(self: *const SeedPhrase, position: usize) []const u8 {
        if (position >= self.word_count) return "";
        return wordlist.getWord(static_indices[position]);
    }

    /// Derive the seed into caller-owned storage.
    ///
    /// This avoids binding mnemonic handling to any signature implementation.
    pub fn deriveSeed(self: *const SeedPhrase, out: *[SEED_SIZE]u8) void {
        constant_time.secureZero(&static_data);
        constant_time.secureZero32(out);

        var i: usize = 0;
        while (i < self.word_count) : (i += 1) {
            static_data[i * 2] = @truncate(static_indices[i] >> 8);
            static_data[i * 2 + 1] = @truncate(static_indices[i] & 0xff);
        }

        hash.sha256Into(static_data[0 .. self.word_count * 2], out);

        var round: usize = 0;
        while (round < 2048) : (round += 1) {
            // hash.sha256Into supports in-place output in the existing codebase.
            hash.sha256Into(out, out);
        }

        constant_time.secureZero(&static_data);
    }

    /// Compatibility accessor for callers that only need seed bytes.
    /// The returned pointer refers to shared static storage and must not be
    /// retained across another mnemonic operation.
    pub fn toSeedPtr(self: *const SeedPhrase) *const [SEED_SIZE]u8 {
        self.deriveSeed(&static_seed_result);
        return &static_seed_result;
    }

    pub fn isValid(self: *const SeedPhrase) bool {
        if (self.word_count != MNEMONIC_12_WORDS and
            self.word_count != MNEMONIC_24_WORDS)
        {
            return false;
        }

        var i: usize = 0;
        while (i < self.word_count) : (i += 1) {
            if (static_indices[i] >= wordlist.WORDLIST_SIZE) return false;
        }
        return true;
    }

    pub fn fromWords(words: []const []const u8) ?SeedPhrase {
        if (words.len != MNEMONIC_12_WORDS and
            words.len != MNEMONIC_24_WORDS)
        {
            return null;
        }

        clearMnemonicState();

        var i: usize = 0;
        while (i < words.len) : (i += 1) {
            static_indices[i] = wordlist.findWord(words[i]) orelse return null;
        }

        return .{ .word_count = words.len };
    }
};

fn clearMnemonicState() void {
    @memset(static_indices[0..], 0);
    constant_time.secureZero32(&static_entropy);
    constant_time.secureZero(&static_data);
    constant_time.secureZero32(&static_seed_result);
}

fn extractBits(data: []const u8, bit_pos: usize, bit_count: usize) u16 {
    var result: u16 = 0;
    var i: usize = 0;

    while (i < bit_count) : (i += 1) {
        const byte_index = (bit_pos + i) / 8;
        const bit_index: u3 = @intCast(7 - ((bit_pos + i) % 8));
        if (byte_index < data.len) {
            const bit: u16 = (data[byte_index] >> bit_index) & 1;
            result = (result << 1) | bit;
        }
    }

    return result;
}

pub fn test_keys() bool {
    serial.writeString("[CRYPTO] Testing seed phrase management...\n");

    if (wordlist.findWord("abandon") == null or
        wordlist.findWord("zoo") == null or
        wordlist.findWord("satoshi") == null)
    {
        serial.writeString("  Wordlist lookup: FAIL\n");
        return false;
    }
    serial.writeString("  Wordlist lookup: OK\n");

    const phrase = SeedPhrase.generate();
    if (!phrase.isValid()) {
        serial.writeString("  Phrase validity: FAIL\n");
        return false;
    }
    serial.writeString("  Phrase validity: OK\n");

    phrase.deriveSeed(&static_test_seed_a);
    phrase.deriveSeed(&static_test_seed_b);

    if (!bytesEqual(&static_test_seed_a, &static_test_seed_b)) {
        serial.writeString("  Deterministic seed: FAIL\n");
        clearTestSeeds();
        return false;
    }

    if (constant_time.constantTimeIsZero32(&static_test_seed_a)) {
        serial.writeString("  Non-zero seed: FAIL\n");
        clearTestSeeds();
        return false;
    }

    serial.writeString("  Deterministic seed: OK\n");
    serial.writeString("  Seed prefix: ");
    printBytes(&static_test_seed_a, 8);
    serial.writeString("...\n");

    clearTestSeeds();
    serial.writeString("  Seed phrase test: OK\n");
    return true;
}

fn clearTestSeeds() void {
    constant_time.secureZero32(&static_test_seed_a);
    constant_time.secureZero32(&static_test_seed_b);
}

fn bytesEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

fn printBytes(data: []const u8, maximum: usize) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < maximum and i < data.len) : (i += 1) {
        serial.writeChar(hex[data[i] >> 4]);
        serial.writeChar(hex[data[i] & 0x0f]);
    }
}
