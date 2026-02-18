//! Zamrud OS - Identity Syscall Dispatcher
//! Wraps identity subsystem calls with unified dispatch function.
//! SC1: Fixed types (i64), added dispatch(), matches numbers.zig

const serial = @import("../drivers/serial/serial.zig");
const identity = @import("../identity/identity.zig");
const numbers = @import("numbers.zig");

// =============================================================================
// Dispatcher — called from table.zig
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return switch (num) {
        numbers.SYS_IDENTITY_CREATE => sysIdentityCreate(a1, a2, a3, a4),
        numbers.SYS_IDENTITY_DELETE => sysIdentityDelete(a1, a2),
        numbers.SYS_IDENTITY_LIST => sysIdentityList(),
        numbers.SYS_IDENTITY_GET => sysIdentityGet(a1, a2, a3),
        numbers.SYS_IDENTITY_GET_CURRENT => sysIdentityGetCurrent(a1, a2),
        numbers.SYS_IDENTITY_SET_CURRENT => sysIdentitySetCurrent(a1, a2),
        numbers.SYS_IDENTITY_UNLOCK => sysIdentityUnlock(a1, a2, a3, a4),
        numbers.SYS_IDENTITY_LOCK => sysIdentityLock(),
        numbers.SYS_IDENTITY_IS_UNLOCKED => sysIdentityIsUnlocked(),
        numbers.SYS_IDENTITY_SIGN => numbers.ENOSYS, // TODO
        numbers.SYS_IDENTITY_VERIFY => numbers.ENOSYS, // TODO
        numbers.SYS_IDENTITY_GET_ADDRESS => sysIdentityGetAddress(a1, a2, a3, a4),
        numbers.SYS_IDENTITY_GET_PUBKEY => sysIdentityGetPubkey(a1, a2, a3),
        numbers.SYS_PRIVACY_GET_MODE => sysPrivacyGetMode(),
        numbers.SYS_PRIVACY_SET_MODE => sysPrivacySetMode(a1),
        numbers.SYS_NAME_REGISTER => numbers.ENOSYS, // TODO
        numbers.SYS_NAME_LOOKUP => numbers.ENOSYS, // TODO
        numbers.SYS_NAME_AVAILABLE => sysNameAvailable(a1, a2),
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
// Identity Creation/Management
// =============================================================================

fn sysIdentityCreate(name_ptr: u64, name_len: u64, pin_ptr: u64, pin_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
    if (!validatePtr(pin_ptr, pin_len)) return numbers.EFAULT;
    if (name_len == 0 or name_len > 32) return numbers.EINVAL;
    if (pin_len < 4 or pin_len > 64) return numbers.EINVAL;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];
    const pin: []const u8 = @as([*]const u8, @ptrFromInt(pin_ptr))[0..@intCast(pin_len)];

    if (identity.keyring.createIdentity(name, pin)) |_| {
        return numbers.SUCCESS;
    }
    return numbers.EIDENT_FULL;
}

fn sysIdentityDelete(name_ptr: u64, name_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
    if (name_len == 0 or name_len > 32) return numbers.EINVAL;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    if (identity.keyring.deleteIdentity(name)) {
        return numbers.SUCCESS;
    }
    return numbers.EIDENT_NOTFOUND;
}

fn sysIdentityList() i64 {
    return @intCast(identity.keyring.getIdentityCount());
}

fn sysIdentityGet(index: u64, out_buf: u64, buf_len: u64) i64 {
    if (!validatePtr(out_buf, buf_len)) return numbers.EFAULT;
    if (buf_len < 64) return numbers.EINVAL;

    if (identity.keyring.getIdentityByIndex(@intCast(index))) |id| {
        const buf: [*]u8 = @ptrFromInt(out_buf);
        const name = id.getName();

        var i: usize = 0;
        while (i < name.len and i < buf_len) : (i += 1) {
            buf[i] = name[i];
        }
        return @intCast(i);
    }
    return numbers.EIDENT_NOTFOUND;
}

fn sysIdentityGetCurrent(out_buf: u64, buf_len: u64) i64 {
    if (!validatePtr(out_buf, buf_len)) return numbers.EFAULT;

    if (identity.keyring.getCurrentIdentity()) |id| {
        const buf: [*]u8 = @ptrFromInt(out_buf);
        const name = id.getName();

        var i: usize = 0;
        while (i < name.len and i < buf_len) : (i += 1) {
            buf[i] = name[i];
        }
        return @intCast(i);
    }
    return numbers.EIDENT_NOTFOUND;
}

fn sysIdentitySetCurrent(name_ptr: u64, name_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
    if (name_len == 0 or name_len > 32) return numbers.EINVAL;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    if (identity.keyring.setCurrentIdentity(name)) {
        return numbers.SUCCESS;
    }
    return numbers.EIDENT_NOTFOUND;
}

// =============================================================================
// Authentication
// =============================================================================

fn sysIdentityUnlock(name_ptr: u64, name_len: u64, pin_ptr: u64, pin_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
    if (!validatePtr(pin_ptr, pin_len)) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];
    const pin: []const u8 = @as([*]const u8, @ptrFromInt(pin_ptr))[0..@intCast(pin_len)];

    if (identity.auth.unlock(name, pin)) {
        return numbers.SUCCESS;
    }
    return numbers.EIDENT_BADPIN;
}

fn sysIdentityLock() i64 {
    identity.auth.lock();
    return numbers.SUCCESS;
}

fn sysIdentityIsUnlocked() i64 {
    return if (identity.auth.isUnlocked()) 1 else 0;
}

// =============================================================================
// Cryptographic Operations
// =============================================================================

fn sysIdentityGetAddress(name_ptr: u64, name_len: u64, out_buf: u64, buf_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
    if (!validatePtr(out_buf, buf_len)) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    if (identity.keyring.findIdentity(name)) |id| {
        const addr = id.getAddress();
        const buf: [*]u8 = @ptrFromInt(out_buf);

        var i: usize = 0;
        while (i < addr.len and i < buf_len) : (i += 1) {
            buf[i] = addr[i];
        }
        return @intCast(i);
    }
    return numbers.EIDENT_NOTFOUND;
}

fn sysIdentityGetPubkey(name_ptr: u64, name_len: u64, out_buf: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
    if (!validatePtr(out_buf, 32)) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    if (identity.keyring.findIdentity(name)) |id| {
        const pubkey = id.getPublicKey();
        const buf: [*]u8 = @ptrFromInt(out_buf);

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            buf[i] = pubkey[i];
        }
        return 32;
    }
    return numbers.EIDENT_NOTFOUND;
}

// =============================================================================
// Privacy
// =============================================================================

fn sysPrivacyGetMode() i64 {
    return switch (identity.privacy.getMode()) {
        .stealth => 0,
        .pseudonymous => 1,
        .public => 2,
    };
}

fn sysPrivacySetMode(mode: u64) i64 {
    switch (mode) {
        0 => identity.privacy.setMode(.stealth),
        1 => identity.privacy.setMode(.pseudonymous),
        2 => identity.privacy.setMode(.public),
        else => return numbers.EINVAL,
    }
    return numbers.SUCCESS;
}

// =============================================================================
// Names
// =============================================================================

fn sysNameAvailable(name_ptr: u64, name_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    return if (identity.names.isAvailable(name)) 1 else 0;
}
