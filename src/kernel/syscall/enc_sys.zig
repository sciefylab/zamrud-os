//! Zamrud OS - Encrypted FS & ELF Syscalls (SC7)
//! SYS_ENC_WRITE (260), SYS_ENC_READ (261), SYS_ENC_SETKEY (262),
//! SYS_ENC_STATUS (263), SYS_EXEC_ELF (270), SYS_EXEC_ZAM (271)

const numbers = @import("numbers.zig");
const process = @import("../proc/process.zig");
const encryptfs = @import("../fs/encryptfs.zig");
const sys_encrypt = @import("../crypto/sys_encrypt.zig");
const elf_exec = @import("../loader/elf_exec.zig");

// =============================================================================
// Dispatcher
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return switch (num) {
        numbers.SYS_ENC_WRITE => sysEncWrite(a1, a2, a3, a4),
        numbers.SYS_ENC_READ => sysEncRead(a1, a2, a3, a4),
        numbers.SYS_ENC_SETKEY => sysEncSetkey(a1, a2, a3),
        numbers.SYS_ENC_STATUS => sysEncStatus(a1),
        numbers.SYS_EXEC_ELF => sysExecElf(a1, a2, a3, a4),
        numbers.SYS_EXEC_ZAM => sysExecZam(a1, a2, a3, a4),
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
// SYS_ENC_WRITE (260) — Encrypt and store a file
//   a1 = name_ptr
//   a2 = name_len
//   a3 = data_ptr (plaintext)
//   a4 = data_len
//   Returns: 0 on success, negative error
// =============================================================================

fn sysEncWrite(name_ptr: u64, name_len_raw: u64, data_ptr: u64, data_len_raw: u64) i64 {
    if (!encryptfs.isInitialized()) {
        encryptfs.init();
    }

    if (!encryptfs.isKeySet()) return numbers.EACCES;

    const name_len = @min(name_len_raw, encryptfs.MAX_FILENAME);
    const data_len = @min(data_len_raw, encryptfs.MAX_FILE_DATA);

    if (name_ptr == 0 or name_len == 0) return numbers.EINVAL;
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
    if (data_ptr == 0 or data_len == 0) return numbers.EINVAL;
    if (!validatePtr(data_ptr, data_len)) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];
    const data: []const u8 = @as([*]const u8, @ptrFromInt(data_ptr))[0..data_len];

    if (encryptfs.encryptFile(name, data)) {
        return numbers.SUCCESS;
    }

    // Could be duplicate or encryption failure
    if (encryptfs.fileExists(name)) return numbers.EEXIST;
    return numbers.EIO;
}

// =============================================================================
// SYS_ENC_READ (261) — Decrypt and read a file
//   a1 = name_ptr
//   a2 = name_len
//   a3 = buf_ptr (output buffer for plaintext)
//   a4 = buf_len
//   Returns: bytes read on success, negative error
// =============================================================================

fn sysEncRead(name_ptr: u64, name_len_raw: u64, buf_ptr: u64, buf_len: u64) i64 {
    if (!encryptfs.isInitialized()) return numbers.ENODEV;
    if (!encryptfs.isKeySet()) return numbers.EACCES;

    const name_len = @min(name_len_raw, encryptfs.MAX_FILENAME);

    if (name_ptr == 0 or name_len == 0) return numbers.EINVAL;
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
    if (buf_ptr == 0) return numbers.EFAULT;
    if (!validatePtr(buf_ptr, buf_len)) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];

    const decrypted = encryptfs.decryptFile(name) orelse {
        if (!encryptfs.fileExists(name)) return numbers.ENOENT;
        return numbers.EIO; // wrong key or corruption
    };

    const copy_len = @min(decrypted.len, buf_len);
    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    for (0..copy_len) |i| {
        buf[i] = decrypted[i];
    }

    return @intCast(copy_len);
}

// =============================================================================
// SYS_ENC_SETKEY (262) — Set encryption key
//   a1 = method: 0=passphrase, 1=identity_pubkey, 3=clear/lock
//   a2 = key_ptr (passphrase string, or 32-byte key/pubkey)
//   a3 = key_len
//   Returns: 0 on success, negative error
// =============================================================================

fn sysEncSetkey(method: u64, key_ptr: u64, key_len: u64) i64 {
    if (!encryptfs.isInitialized()) {
        encryptfs.init();
    }

    switch (method) {
        // Passphrase
        0 => {
            if (key_ptr == 0) return numbers.EINVAL;
            if (key_len < 4 or key_len > 128) return numbers.EINVAL;
            if (!validatePtr(key_ptr, key_len)) return numbers.EFAULT;
            const passphrase: []const u8 = @as([*]const u8, @ptrFromInt(key_ptr))[0..key_len];
            if (encryptfs.setKeyFromPassphrase(passphrase)) {
                if (sys_encrypt.isInitialized()) {
                    sys_encrypt.setMasterKeyFromPassphrase(passphrase);
                }
                return numbers.SUCCESS;
            }
            return numbers.EPERM;
        },
        // Identity public key (32 bytes)
        1 => {
            if (key_ptr == 0) return numbers.EINVAL;
            if (key_len < 32) return numbers.EINVAL;
            if (!validatePtr(key_ptr, 32)) return numbers.EFAULT;
            const pubkey: *const [32]u8 = @ptrFromInt(key_ptr);
            if (encryptfs.setKeyFromIdentity(pubkey)) {
                if (sys_encrypt.isInitialized()) {
                    sys_encrypt.setMasterKeyFromIdentity(pubkey);
                }
                return numbers.SUCCESS;
            }
            return numbers.EPERM;
        },
        // Clear key (lock) — no key_ptr needed
        3 => {
            encryptfs.clearKey();
            if (sys_encrypt.isInitialized()) {
                sys_encrypt.clearMasterKey();
            }
            return numbers.SUCCESS;
        },
        else => return numbers.EINVAL,
    }
}

// =============================================================================
// SYS_ENC_STATUS (263) — Get encryption status
//   a1 = info_ptr (optional, 32 bytes for EncStatusInfo)
//   Returns: status flags (bitfield)
//     bit 0: encryptfs initialized
//     bit 1: encryptfs key set
//     bit 2: sys_encrypt initialized
//     bit 3: sys_encrypt master key set
//     bit 4: elf_exec initialized
// =============================================================================

fn sysEncStatus(info_ptr: u64) i64 {
    var flags: i64 = 0;

    if (encryptfs.isInitialized()) flags |= 1;
    if (encryptfs.isKeySet()) flags |= 2;
    if (sys_encrypt.isInitialized()) flags |= 4;
    if (sys_encrypt.isMasterKeySet()) flags |= 8;
    if (elf_exec.isInitialized()) flags |= 16;

    // Fill info struct if requested
    if (info_ptr != 0 and validatePtr(info_ptr, 32)) {
        const info: *EncStatusInfo = @ptrFromInt(info_ptr);
        const enc_stats = encryptfs.getStats();
        const sys_stats = sys_encrypt.getStats();

        info.flags = @intCast(flags);
        info.enc_files = @intCast(enc_stats.files);
        info.enc_encrypts = @intCast(enc_stats.encrypts & 0xFFFFFFFF);
        info.enc_decrypts = @intCast(enc_stats.decrypts & 0xFFFFFFFF);
        info.sys_encrypts = @intCast(sys_stats.encrypts & 0xFFFFFFFF);
        info.sys_decrypts = @intCast(sys_stats.decrypts & 0xFFFFFFFF);
        info.elf_procs = @intCast(elf_exec.getProcessCount());
        info._pad = 0;
    }

    return flags;
}

const EncStatusInfo = extern struct {
    flags: u32 = 0,
    enc_files: u32 = 0,
    enc_encrypts: u32 = 0,
    enc_decrypts: u32 = 0,
    sys_encrypts: u32 = 0,
    sys_decrypts: u32 = 0,
    elf_procs: u16 = 0,
    _pad: u16 = 0,
};

// =============================================================================
// SYS_EXEC_ELF (270) — Load and execute raw ELF binary
//   a1 = elf_data_ptr
//   a2 = elf_data_len
//   a3 = name_ptr
//   a4 = name_len
//   Returns: PID on success, negative error
// =============================================================================

fn sysExecElf(data_ptr: u64, data_len: u64, name_ptr: u64, name_len_raw: u64) i64 {
    if (!elf_exec.isInitialized()) {
        elf_exec.init();
    }

    if (data_ptr == 0 or data_len == 0) return numbers.EINVAL;
    if (!validatePtr(data_ptr, data_len)) return numbers.EFAULT;

    const name_len = @min(name_len_raw, 32);
    const name: []const u8 = if (name_ptr != 0 and name_len > 0 and validatePtr(name_ptr, name_len))
        @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len]
    else
        "elf_proc";

    const elf_data: []const u8 = @as([*]const u8, @ptrFromInt(data_ptr))[0..data_len];

    // Default caps for raw ELF = user level
    const caps = @import("../security/capability.zig").CAP_USER_DEFAULT;

    const result = elf_exec.execRawElf(elf_data, name, caps);

    return switch (result.err) {
        .None => @intCast(result.pid),
        .ParseFailed => numbers.EINVAL,
        .VerifyFailed => numbers.EACCES,
        .LoadFailed => numbers.ENOMEM,
        .ProcessCreateFailed => numbers.EAGAIN,
        .CapabilityDenied => numbers.EPERM,
        .TooManyProcesses => numbers.EAGAIN,
        .InvalidEntry => numbers.EINVAL,
        .NotInitialized => numbers.ENODEV,
    };
}

// =============================================================================
// SYS_EXEC_ZAM (271) — Load and execute .zam binary (with verification)
//   a1 = zam_data_ptr
//   a2 = zam_data_len
//   a3 = name_ptr
//   a4 = name_len
//   Returns: PID on success, negative error
// =============================================================================

fn sysExecZam(data_ptr: u64, data_len: u64, name_ptr: u64, name_len_raw: u64) i64 {
    if (!elf_exec.isInitialized()) {
        elf_exec.init();
    }

    if (data_ptr == 0 or data_len == 0) return numbers.EINVAL;
    if (!validatePtr(data_ptr, data_len)) return numbers.EFAULT;

    const name_len = @min(name_len_raw, 32);
    const name: []const u8 = if (name_ptr != 0 and name_len > 0 and validatePtr(name_ptr, name_len))
        @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len]
    else
        "zam_proc";

    const zam_data: []const u8 = @as([*]const u8, @ptrFromInt(data_ptr))[0..data_len];

    const result = elf_exec.execZam(zam_data, name);

    return switch (result.err) {
        .None => @intCast(result.pid),
        .ParseFailed => numbers.EINVAL,
        .VerifyFailed => numbers.EACCES,
        .LoadFailed => numbers.ENOMEM,
        .ProcessCreateFailed => numbers.EAGAIN,
        .CapabilityDenied => numbers.EPERM,
        .TooManyProcesses => numbers.EAGAIN,
        .InvalidEntry => numbers.EINVAL,
        .NotInitialized => numbers.ENODEV,
    };
}
