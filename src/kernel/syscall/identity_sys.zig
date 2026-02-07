//! Zamrud OS - Identity Syscalls
//! System call handlers for identity management

const serial = @import("../drivers/serial/serial.zig");
const identity = @import("../identity/identity.zig");
const keyring = identity.keyring;
const auth = identity.auth;
const privacy = identity.privacy;
const names = identity.names;
const numbers = @import("numbers.zig");

// =============================================================================
// Identity Creation/Management
// =============================================================================

/// SYS_IDENTITY_CREATE: Create new identity
/// Args: rdi = name_ptr, rsi = name_len, rdx = pin_ptr, rcx = pin_len
/// Returns: 0 on success, negative error code on failure
pub fn sysIdentityCreate(name_ptr: usize, name_len: usize, pin_ptr: usize, pin_len: usize) isize {
    // Validate pointers (basic check)
    if (name_ptr == 0 or pin_ptr == 0) return numbers.EFAULT;
    if (name_len == 0 or name_len > 32) return numbers.EINVAL;
    if (pin_len < 4 or pin_len > 64) return numbers.EINVAL;

    // Convert to slices (would need proper user memory validation)
    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];
    const pin: []const u8 = @as([*]const u8, @ptrFromInt(pin_ptr))[0..pin_len];

    // Create identity
    if (keyring.createIdentity(name, pin)) |_| {
        return numbers.ESUCCESS;
    } else {
        return numbers.EIDENT_FULL;
    }
}

/// SYS_IDENTITY_DELETE: Delete identity by name
/// Args: rdi = name_ptr, rsi = name_len
/// Returns: 0 on success, negative error code on failure
pub fn sysIdentityDelete(name_ptr: usize, name_len: usize) isize {
    if (name_ptr == 0) return numbers.EFAULT;
    if (name_len == 0 or name_len > 32) return numbers.EINVAL;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];

    if (keyring.deleteIdentity(name)) {
        return numbers.ESUCCESS;
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

/// SYS_IDENTITY_LIST: Get identity count
/// Returns: Number of identities
pub fn sysIdentityList() isize {
    return @intCast(keyring.getIdentityCount());
}

/// SYS_IDENTITY_GET: Get identity info by index
/// Args: rdi = index, rsi = out_buf, rdx = buf_len
/// Returns: Bytes written or negative error
pub fn sysIdentityGet(index: usize, out_buf: usize, buf_len: usize) isize {
    if (out_buf == 0) return numbers.EFAULT;
    if (buf_len < 64) return numbers.EINVAL;

    if (keyring.getIdentityByIndex(index)) |id| {
        const buf: [*]u8 = @ptrFromInt(out_buf);
        const name = id.getName();

        // Copy name
        var i: usize = 0;
        while (i < name.len and i < buf_len) : (i += 1) {
            buf[i] = name[i];
        }

        return @intCast(i);
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

/// SYS_IDENTITY_GET_CURRENT: Get current identity name
/// Args: rdi = out_buf, rsi = buf_len
/// Returns: Bytes written or negative error
pub fn sysIdentityGetCurrent(out_buf: usize, buf_len: usize) isize {
    if (out_buf == 0) return numbers.EFAULT;

    if (keyring.getCurrentIdentity()) |id| {
        const buf: [*]u8 = @ptrFromInt(out_buf);
        const name = id.getName();

        var i: usize = 0;
        while (i < name.len and i < buf_len) : (i += 1) {
            buf[i] = name[i];
        }

        return @intCast(i);
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

/// SYS_IDENTITY_SET_CURRENT: Set current identity
/// Args: rdi = name_ptr, rsi = name_len
/// Returns: 0 on success
pub fn sysIdentitySetCurrent(name_ptr: usize, name_len: usize) isize {
    if (name_ptr == 0) return numbers.EFAULT;
    if (name_len == 0 or name_len > 32) return numbers.EINVAL;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];

    if (keyring.setCurrentIdentity(name)) {
        return numbers.ESUCCESS;
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

// =============================================================================
// Authentication
// =============================================================================

/// SYS_IDENTITY_UNLOCK: Unlock identity with PIN
/// Args: rdi = name_ptr, rsi = name_len, rdx = pin_ptr, rcx = pin_len
/// Returns: 0 on success
pub fn sysIdentityUnlock(name_ptr: usize, name_len: usize, pin_ptr: usize, pin_len: usize) isize {
    if (name_ptr == 0 or pin_ptr == 0) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];
    const pin: []const u8 = @as([*]const u8, @ptrFromInt(pin_ptr))[0..pin_len];

    if (keyring.findIdentity(name)) |id| {
        if (auth.unlock(id, pin)) {
            return numbers.ESUCCESS;
        } else {
            return numbers.EIDENT_BADPIN;
        }
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

/// SYS_IDENTITY_LOCK: Lock identity
/// Args: rdi = name_ptr, rsi = name_len
/// Returns: 0 on success
pub fn sysIdentityLock(name_ptr: usize, name_len: usize) isize {
    if (name_ptr == 0) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];

    if (keyring.findIdentity(name)) |id| {
        auth.lock(id);
        return numbers.ESUCCESS;
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

/// SYS_IDENTITY_IS_UNLOCKED: Check if identity is unlocked
/// Args: rdi = name_ptr, rsi = name_len
/// Returns: 1 if unlocked, 0 if locked, negative on error
pub fn sysIdentityIsUnlocked(name_ptr: usize, name_len: usize) isize {
    if (name_ptr == 0) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];

    if (keyring.findIdentity(name)) |id| {
        return if (auth.isUnlocked(id)) 1 else 0;
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

// =============================================================================
// Cryptographic Operations
// =============================================================================

/// SYS_IDENTITY_GET_ADDRESS: Get identity address
/// Args: rdi = name_ptr, rsi = name_len, rdx = out_buf, rcx = buf_len
/// Returns: Address length or negative error
pub fn sysIdentityGetAddress(name_ptr: usize, name_len: usize, out_buf: usize, buf_len: usize) isize {
    if (name_ptr == 0 or out_buf == 0) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];

    if (keyring.findIdentity(name)) |id| {
        const addr = id.getAddress();
        const buf: [*]u8 = @ptrFromInt(out_buf);

        var i: usize = 0;
        while (i < addr.len and i < buf_len) : (i += 1) {
            buf[i] = addr[i];
        }

        return @intCast(i);
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

/// SYS_IDENTITY_GET_PUBKEY: Get identity public key
/// Args: rdi = name_ptr, rsi = name_len, rdx = out_buf (32 bytes)
/// Returns: 32 on success, negative on error
pub fn sysIdentityGetPubkey(name_ptr: usize, name_len: usize, out_buf: usize) isize {
    if (name_ptr == 0 or out_buf == 0) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];

    if (keyring.findIdentity(name)) |id| {
        const pubkey = id.getPublicKey();
        const buf: [*]u8 = @ptrFromInt(out_buf);

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            buf[i] = pubkey[i];
        }

        return 32;
    } else {
        return numbers.EIDENT_NOTFOUND;
    }
}

// =============================================================================
// Privacy
// =============================================================================

/// SYS_PRIVACY_GET_MODE: Get current privacy mode
/// Returns: 0=stealth, 1=pseudonymous, 2=public
pub fn sysPrivacyGetMode() isize {
    return switch (privacy.getMode()) {
        .stealth => 0,
        .pseudonymous => 1,
        .public_mode => 2,
    };
}

/// SYS_PRIVACY_SET_MODE: Set privacy mode
/// Args: rdi = mode (0, 1, or 2)
/// Returns: 0 on success
pub fn sysPrivacySetMode(mode: usize) isize {
    switch (mode) {
        0 => privacy.setMode(.stealth),
        1 => privacy.setMode(.pseudonymous),
        2 => privacy.setMode(.public_mode),
        else => return numbers.EINVAL,
    }
    return numbers.ESUCCESS;
}

// =============================================================================
// Names
// =============================================================================

/// SYS_NAME_AVAILABLE: Check if name is available
/// Args: rdi = name_ptr, rsi = name_len
/// Returns: 1 if available, 0 if taken, negative on error
pub fn sysNameAvailable(name_ptr: usize, name_len: usize) isize {
    if (name_ptr == 0) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];

    return if (names.isAvailable(name)) 1 else 0;
}
