//! Zamrud OS - User/Auth Syscalls (SC5)
//! SYS_SETUID (220), SYS_SETGID (221), SYS_GET_USERNAME (222),
//! SYS_LOGIN (223), SYS_LOGOUT (224)

const numbers = @import("numbers.zig");
const process = @import("../proc/process.zig");
const users = @import("../security/users.zig");

// =============================================================================
// Dispatcher
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return switch (num) {
        numbers.SYS_SETUID => sysSetuid(a1),
        numbers.SYS_SETGID => sysSetgid(a1),
        numbers.SYS_GET_USERNAME => sysGetUsername(a1, a2, a3),
        numbers.SYS_LOGIN => sysLogin(a1, a2, a3, a4),
        numbers.SYS_LOGOUT => sysLogout(),
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
// SYS_SETUID (220) — Set effective user ID
//   a1 = target_uid
//   Returns: 0 on success, negative error
//
//   Rules:
//     - Root (euid=0) can set to any uid
//     - Non-root can only set euid back to their real uid
// =============================================================================

fn sysSetuid(target_uid_raw: u64) i64 {
    if (!users.isInitialized()) return numbers.ENODEV;
    if (!users.isLoggedIn()) return numbers.EPERM;

    const target_uid: u16 = @truncate(target_uid_raw);
    const session = users.getCurrentSession();

    // Root can set any uid
    if (session.euid == users.ROOT_UID) {
        // Verify target user exists (unless setting to root)
        if (target_uid != users.ROOT_UID) {
            if (users.findUserByUid(target_uid) == null) {
                return numbers.ESRCH;
            }
        }
        // Modify session effective uid
        setSessionEuid(target_uid);
        return numbers.SUCCESS;
    }

    // Non-root: can only set back to own real uid
    if (target_uid == session.uid) {
        setSessionEuid(target_uid);
        return numbers.SUCCESS;
    }

    return numbers.EPERM;
}

// =============================================================================
// SYS_SETGID (221) — Set effective group ID
//   a1 = target_gid
//   Returns: 0 on success, negative error
//
//   Rules:
//     - Root can set to any gid
//     - Non-root can only set egid back to their real gid
//     - Non-root can set to a group they belong to
// =============================================================================

fn sysSetgid(target_gid_raw: u64) i64 {
    if (!users.isInitialized()) return numbers.ENODEV;
    if (!users.isLoggedIn()) return numbers.EPERM;

    const target_gid: u16 = @truncate(target_gid_raw);
    const session = users.getCurrentSession();

    // Root can set any gid
    if (session.euid == users.ROOT_UID) {
        setSessionEgid(target_gid);
        return numbers.SUCCESS;
    }

    // Non-root: can set back to own real gid
    if (target_gid == session.gid) {
        setSessionEgid(target_gid);
        return numbers.SUCCESS;
    }

    // Non-root: can set to a group they're a member of
    if (users.isInGroup(session.uid, target_gid)) {
        setSessionEgid(target_gid);
        return numbers.SUCCESS;
    }

    return numbers.EPERM;
}

// =============================================================================
// SYS_GET_USERNAME (222) — Get username for a uid
//   a1 = uid (0xFFFF = current user)
//   a2 = buf_ptr (output buffer)
//   a3 = buf_len
//   Returns: name length on success, negative error
// =============================================================================

fn sysGetUsername(uid_raw: u64, buf_ptr: u64, buf_len: u64) i64 {
    if (!users.isInitialized()) return numbers.ENODEV;
    if (buf_ptr == 0) return numbers.EFAULT;
    if (buf_len == 0) return numbers.EINVAL;
    if (!validatePtr(buf_ptr, buf_len)) return numbers.EFAULT;

    const uid: u16 = if (uid_raw == 0xFFFF or uid_raw == 0xFFFFFFFF)
        users.getCurrentUid()
    else
        @truncate(uid_raw);

    // Get username
    const name: []const u8 = blk: {
        if (!users.isLoggedIn() and (uid_raw == 0xFFFF or uid_raw == 0xFFFFFFFF)) {
            break :blk "nobody";
        }
        if (uid_raw == 0xFFFF or uid_raw == 0xFFFFFFFF) {
            const session = users.getCurrentSession();
            break :blk session.getName();
        }
        const user = users.findUserByUid(uid) orelse {
            break :blk "unknown";
        };
        break :blk user.getName();
    };

    // Copy to buffer
    const copy_len = @min(name.len, buf_len);
    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    for (0..copy_len) |i| {
        buf[i] = name[i];
    }
    // Null-terminate if space
    if (copy_len < buf_len) {
        buf[copy_len] = 0;
    }

    return @intCast(copy_len);
}

// =============================================================================
// SYS_LOGIN (223) — Login with identity name and PIN
//   a1 = name_ptr
//   a2 = name_len
//   a3 = pin_ptr
//   a4 = pin_len
//   Returns: uid on success, negative error
// =============================================================================

fn sysLogin(name_ptr: u64, name_len_raw: u64, pin_ptr: u64, pin_len_raw: u64) i64 {
    if (!users.isInitialized()) return numbers.ENODEV;

    // Already logged in
    if (users.isLoggedIn()) return numbers.EBUSY;

    const name_len = @min(name_len_raw, users.NAME_MAX);
    const pin_len = @min(pin_len_raw, 32);

    // Validate name
    if (name_ptr == 0 or name_len == 0) return numbers.EINVAL;
    if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;

    // Validate PIN
    if (pin_ptr == 0 or pin_len == 0) return numbers.EINVAL;
    if (!validatePtr(pin_ptr, pin_len)) return numbers.EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];
    const pin: []const u8 = @as([*]const u8, @ptrFromInt(pin_ptr))[0..pin_len];

    if (users.login(name, pin)) {
        return @intCast(users.getCurrentUid());
    }

    return numbers.EACCES;
}

// =============================================================================
// SYS_LOGOUT (224) — Logout current session
//   Returns: 0 on success, negative error
// =============================================================================

fn sysLogout() i64 {
    if (!users.isInitialized()) return numbers.ENODEV;
    if (!users.isLoggedIn()) return numbers.EPERM;

    users.logout();
    return numbers.SUCCESS;
}

// =============================================================================
// Session Mutation Helpers
// =============================================================================

// We need mutable access to the session. users.zig exposes getCurrentSession()
// as *const, but setuid/setgid need to mutate euid/egid.
// We access through the module's internal state via a wrapper.

fn setSessionEuid(uid: u16) void {
    // Access the mutable session through users module
    // users.getCurrentSession() returns *const, but we know the internal
    // current_session is module-level var. We use @constCast safely here
    // because this is a kernel syscall handler with exclusive access.
    const session_const = users.getCurrentSession();
    const session: *users.Session = @constCast(session_const);
    session.euid = uid;
}

fn setSessionEgid(gid: u16) void {
    const session_const = users.getCurrentSession();
    const session: *users.Session = @constCast(session_const);
    session.egid = gid;
}
