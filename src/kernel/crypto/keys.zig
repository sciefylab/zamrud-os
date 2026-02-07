//! Zamrud OS - Key Management & Seed Phrases

const serial = @import("../drivers/serial/serial.zig");
const random = @import("random.zig");
const hash = @import("hash.zig");
const signature = @import("signature.zig");
const wordlist = @import("wordlist.zig");

pub const KeyPair = signature.KeyPair;
pub const SEED_SIZE = signature.SEED_SIZE;

pub const WORDLIST = wordlist.WORDLIST;
pub const WORDLIST_SIZE = wordlist.WORDLIST_SIZE;
pub const getWord = wordlist.getWord;
pub const findWord = wordlist.findWord;
pub const isValidWord = wordlist.isValidWord;

pub const MNEMONIC_12_WORDS: usize = 12;
pub const MNEMONIC_24_WORDS: usize = 24;

var static_indices: [24]u16 = [_]u16{0} ** 24;
var static_entropy: [32]u8 = [_]u8{0} ** 32;
var static_data: [48]u8 = [_]u8{0} ** 48;
var static_seed_result: [32]u8 = [_]u8{0} ** 32;
var static_pub1: [32]u8 = [_]u8{0} ** 32; // For deterministic test

pub const SeedPhrase = struct {
    word_count: usize,

    pub fn generate() SeedPhrase {
        return generateWithLength(MNEMONIC_12_WORDS);
    }

    pub fn generateWithLength(count: usize) SeedPhrase {
        const wc = if (count == 24) @as(usize, 24) else @as(usize, 12);

        var i: usize = 0;
        while (i < 24) : (i += 1) {
            static_indices[i] = 0;
        }
        i = 0;
        while (i < 32) : (i += 1) {
            static_entropy[i] = 0;
        }

        random.getBytes(&static_entropy);

        var bit_pos: usize = 0;
        i = 0;
        while (i < wc) : (i += 1) {
            static_indices[i] = extractBits(&static_entropy, bit_pos, 11);
            bit_pos += 11;
        }

        return SeedPhrase{ .word_count = wc };
    }

    pub fn getWordAt(self: *const SeedPhrase, pos: usize) []const u8 {
        if (pos >= self.word_count) return "";
        return wordlist.getWord(static_indices[pos]);
    }

    pub fn toSeedPtr(self: *const SeedPhrase) *const [SEED_SIZE]u8 {
        var i: usize = 0;
        while (i < 48) : (i += 1) {
            static_data[i] = 0;
        }

        i = 0;
        while (i < 32) : (i += 1) {
            static_seed_result[i] = 0;
        }

        i = 0;
        while (i < self.word_count) : (i += 1) {
            static_data[i * 2] = @truncate(static_indices[i] >> 8);
            static_data[i * 2 + 1] = @truncate(static_indices[i] & 0xFF);
        }

        hash.sha256Into(static_data[0 .. self.word_count * 2], &static_seed_result);

        var round: usize = 0;
        while (round < 2048) : (round += 1) {
            hash.sha256Into(&static_seed_result, &static_seed_result);
        }

        return &static_seed_result;
    }

    pub fn toKeyPair(self: *const SeedPhrase) void {
        const seed_ptr = self.toSeedPtr();
        KeyPair.fromSeedSlice(seed_ptr);
    }

    pub fn isValid(self: *const SeedPhrase) bool {
        var i: usize = 0;
        while (i < self.word_count) : (i += 1) {
            if (static_indices[i] >= wordlist.WORDLIST_SIZE) {
                return false;
            }
        }
        return true;
    }

    pub fn fromWords(words: []const []const u8) ?SeedPhrase {
        if (words.len != 12 and words.len != 24) return null;

        var i: usize = 0;
        while (i < 24) : (i += 1) {
            static_indices[i] = 0;
        }

        i = 0;
        while (i < words.len) : (i += 1) {
            const idx = wordlist.findWord(words[i]) orelse return null;
            static_indices[i] = idx;
        }

        return SeedPhrase{ .word_count = words.len };
    }
};

fn extractBits(data: []const u8, bit_pos: usize, n_bits: usize) u16 {
    var result: u16 = 0;
    var i: usize = 0;

    while (i < n_bits) : (i += 1) {
        const byte_idx = (bit_pos + i) / 8;
        const bit_idx: u3 = @intCast(7 - ((bit_pos + i) % 8));

        if (byte_idx < data.len) {
            const bit: u16 = (data[byte_idx] >> bit_idx) & 1;
            result = (result << 1) | bit;
        }
    }

    return result;
}

pub fn test_keys() bool {
    serial.writeString("[CRYPTO] Testing key generation...\n");

    serial.writeString("  Wordlist size: ");
    printU32(wordlist.WORDLIST_SIZE);
    serial.writeString(" words\n");

    serial.writeString("  Word 'abandon': ");
    if (wordlist.findWord("abandon") != null) {
        serial.writeString("OK\n");
    } else {
        serial.writeString("NOT FOUND\n");
        return false;
    }

    serial.writeString("  Word 'zoo': ");
    if (wordlist.findWord("zoo") != null) {
        serial.writeString("OK\n");
    } else {
        serial.writeString("NOT FOUND\n");
        return false;
    }

    serial.writeString("  Word 'satoshi': ");
    if (wordlist.findWord("satoshi") != null) {
        serial.writeString("OK\n");
    } else {
        serial.writeString("NOT FOUND\n");
        return false;
    }

    serial.writeString("  Generating seed phrase...\n");
    const phrase = SeedPhrase.generate();

    serial.writeString("  Generated 12-word seed phrase:\n");
    var i: usize = 0;
    while (i < 12) : (i += 1) {
        if (i % 4 == 0) {
            serial.writeString("    ");
        }
        serial.writeString(phrase.getWordAt(i));
        if ((i + 1) % 4 == 0) {
            serial.writeString("\n");
        } else {
            serial.writeString(" ");
        }
    }

    serial.writeString("  Phrase valid: ");
    if (phrase.isValid()) {
        serial.writeString("YES\n");
    } else {
        serial.writeString("NO\n");
        return false;
    }

    serial.writeString("  Deriving seed...\n");
    const seed_ptr = phrase.toSeedPtr();

    serial.writeString("  Seed: ");
    printBytes(seed_ptr, 8);
    serial.writeString("...\n");

    serial.writeString("  Creating key pair...\n");
    KeyPair.fromSeedSlice(seed_ptr);

    serial.writeString("  Derived public key: ");
    printBytes(KeyPair.getPublicKey(), 8);
    serial.writeString("...\n");

    // Deterministic test - use static buffer
    serial.writeString("  Deterministic: ");

    // Zero static_pub1
    i = 0;
    while (i < 32) : (i += 1) {
        static_pub1[i] = 0;
    }

    // Copy current public key to static_pub1
    i = 0;
    while (i < 32) : (i += 1) {
        static_pub1[i] = KeyPair.getPublicKey()[i];
    }

    // Regenerate from same seed
    KeyPair.fromSeedSlice(seed_ptr);

    // Compare
    if (bytesEqual(&static_pub1, KeyPair.getPublicKey())) {
        serial.writeString("OK\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    serial.writeString("  Key generation test: OK\n");
    return true;
}

fn bytesEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn printBytes(data: []const u8, max: usize) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < max and i < data.len) : (i += 1) {
        serial.writeChar(hex[data[i] >> 4]);
        serial.writeChar(hex[data[i] & 0xF]);
    }
}

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [10]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf[i] = @as(u8, @intCast(v % 10)) + '0';
        v = v / 10;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
