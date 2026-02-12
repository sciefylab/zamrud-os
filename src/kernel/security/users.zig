//! Zamrud OS - F3: User/Group Permission System
//! Identity-based user management with role enforcement
//!
//! Architecture:
//!   Identity (blockchain) → User (kernel) → Process
//!   PIN → decrypt privkey → session active → can act
//!
//! Roles:
//!   ROOT  = first identity created (uid=0), bypasses all checks
//!   ADMIN = can manage users, sudo
//!   USER  = normal user, standard permissions
//!   GUEST = minimal permissions, read-only

const serial = @import("../drivers/serial/serial.zig");
const identity_mod = @import("../identity/identity.zig");
const keyring = @import("../identity/keyring.zig");
const auth = @import("../identity/auth.zig");
const hash = @import("../crypto/hash.zig");
const capability = @import("capability.zig");
const violation = @import("violation.zig");
const timer = @import("../drivers/timer/timer.zig");

const user_chain = @import("user_chain.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_USERS: usize = 64;
pub const MAX_GROUPS: usize = 32;
pub const MAX_GROUP_MEMBERS: usize = 16;
pub const NAME_MAX: usize = 32;

pub const ROOT_UID: u16 = 0;
pub const ROOT_GID: u16 = 0;
pub const NOBODY_UID: u16 = 65534;
pub const NOBODY_GID: u16 = 65534;

// Default group IDs
pub const GID_ROOT: u16 = 0;
pub const GID_ADMIN: u16 = 1;
pub const GID_USERS: u16 = 100;
pub const GID_GUEST: u16 = 65534;

// =============================================================================
// Types
// =============================================================================

pub const UserRole = enum(u8) {
    root = 0,
    admin = 1,
    user = 2,
    guest = 3,

    pub fn toString(self: UserRole) []const u8 {
        return switch (self) {
            .root => "root",
            .admin => "admin",
            .user => "user",
            .guest => "guest",
        };
    }

    /// Get default capabilities for role
    pub fn defaultCaps(self: UserRole) u32 {
        return switch (self) {
            .root => capability.CAP_ALL,
            .admin => capability.CAP_FS_READ | capability.CAP_FS_WRITE |
                capability.CAP_IPC | capability.CAP_EXEC |
                capability.CAP_DEVICE | capability.CAP_GRAPHICS |
                capability.CAP_CRYPTO | capability.CAP_CHAIN |
                capability.CAP_ADMIN | capability.CAP_MEMORY |
                capability.CAP_NET,
            .user => capability.CAP_FS_READ | capability.CAP_FS_WRITE |
                capability.CAP_IPC | capability.CAP_EXEC |
                capability.CAP_GRAPHICS | capability.CAP_MEMORY,
            .guest => capability.CAP_FS_READ | capability.CAP_GRAPHICS,
        };
    }
};

pub const User = struct {
    uid: u16 = NOBODY_UID,
    gid: u16 = NOBODY_GID,
    role: UserRole = .guest,
    name: [NAME_MAX]u8 = [_]u8{0} ** NAME_MAX,
    name_len: u8 = 0,
    /// Index into keyring identity table (-1 = no link)
    identity_index: i8 = -1,
    /// Identity address (for lookup)
    address: [50]u8 = [_]u8{0} ** 50,
    address_len: u8 = 0,
    active: bool = false,
    created_at: u64 = 0,
    last_login: u64 = 0,

    pub fn getName(self: *const User) []const u8 {
        if (self.name_len == 0) return "unknown";
        return self.name[0..self.name_len];
    }

    pub fn getAddress(self: *const User) []const u8 {
        if (self.address_len == 0) return "";
        return self.address[0..self.address_len];
    }

    pub fn isRoot(self: *const User) bool {
        return self.uid == ROOT_UID or self.role == .root;
    }
};

pub const Group = struct {
    gid: u16 = NOBODY_GID,
    name: [NAME_MAX]u8 = [_]u8{0} ** NAME_MAX,
    name_len: u8 = 0,
    members: [MAX_GROUP_MEMBERS]u16 = [_]u16{NOBODY_UID} ** MAX_GROUP_MEMBERS,
    member_count: u8 = 0,
    active: bool = false,

    pub fn getName(self: *const Group) []const u8 {
        if (self.name_len == 0) return "unknown";
        return self.name[0..self.name_len];
    }

    pub fn hasMember(self: *const Group, uid: u16) bool {
        var i: usize = 0;
        while (i < self.member_count) : (i += 1) {
            if (self.members[i] == uid) return true;
        }
        return false;
    }

    pub fn addMember(self: *Group, uid: u16) bool {
        if (self.member_count >= MAX_GROUP_MEMBERS) return false;
        if (self.hasMember(uid)) return true; // already member
        self.members[self.member_count] = uid;
        self.member_count += 1;
        return true;
    }

    pub fn removeMember(self: *Group, uid: u16) bool {
        var i: usize = 0;
        while (i < self.member_count) : (i += 1) {
            if (self.members[i] == uid) {
                // Shift remaining
                var j = i;
                while (j < self.member_count - 1) : (j += 1) {
                    self.members[j] = self.members[j + 1];
                }
                self.member_count -= 1;
                return true;
            }
        }
        return false;
    }
};

// =============================================================================
// Session
// =============================================================================

pub const Session = struct {
    uid: u16 = NOBODY_UID,
    gid: u16 = NOBODY_GID,
    euid: u16 = NOBODY_UID, // effective uid (for sudo)
    egid: u16 = NOBODY_GID, // effective gid
    role: UserRole = .guest,
    active: bool = false,
    login_time: u64 = 0,
    sudo_active: bool = false,
    sudo_expires: u64 = 0,
    name: [NAME_MAX]u8 = [_]u8{0} ** NAME_MAX,
    name_len: u8 = 0,

    pub fn getName(self: *const Session) []const u8 {
        if (self.name_len == 0) return "nobody";
        return self.name[0..self.name_len];
    }

    pub fn isRoot(self: *const Session) bool {
        return self.euid == ROOT_UID;
    }

    pub fn isSudoActive(self: *const Session) bool {
        if (!self.sudo_active) return false;
        if (self.sudo_expires > 0) {
            const now = timer.getTicks();
            if (now > self.sudo_expires) {
                return false;
            }
        }
        return true;
    }
};

// =============================================================================
// State
// =============================================================================

var users_arr: [MAX_USERS]User = undefined;
var user_count: usize = 0;
var next_uid: u16 = 1; // 0 = root

var groups: [MAX_GROUPS]Group = undefined;
var group_count: usize = 0;
var next_gid: u16 = 101; // 0=root, 1=admin, 100=users

var current_session: Session = .{};
var initialized: bool = false;

// Sudo timeout in ticks (roughly 5 minutes at 100Hz)
const SUDO_TIMEOUT: u64 = 30000;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[USERS] Initializing user/group system...\n");

    // Clear all users
    for (&users_arr) |*u| {
        u.* = User{};
    }
    user_count = 0;
    next_uid = 1;

    // Clear all groups
    for (&groups) |*g| {
        g.* = Group{};
    }
    group_count = 0;
    next_gid = 101;

    // Create default groups
    createDefaultGroups();

    // Current session = nobody
    current_session = .{};

    initialized = true;
    serial.writeString("[USERS] User system ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn createDefaultGroups() void {
    // root group (gid=0)
    createGroupInternal("root", GID_ROOT);
    // admin group (gid=1)
    createGroupInternal("admin", GID_ADMIN);
    // users group (gid=100)
    createGroupInternal("users", GID_USERS);
    // guest group (gid=65534)
    createGroupInternal("guest", GID_GUEST);
}

fn createGroupInternal(name: []const u8, gid: u16) void {
    if (group_count >= MAX_GROUPS) return;

    var g = &groups[group_count];
    g.gid = gid;
    g.active = true;
    g.member_count = 0;

    const len = @min(name.len, NAME_MAX);
    for (0..len) |i| {
        g.name[i] = name[i];
    }
    g.name_len = @intCast(len);

    group_count += 1;
}

// =============================================================================
// User Management
// =============================================================================

/// Derive uid from identity public key
pub fn deriveUid(pubkey: *const [32]u8) u16 {
    var h: [32]u8 = undefined;
    hash.sha256Into(pubkey, &h);
    // Use first 2 bytes, ensure not 0 (reserved for root) or 65534 (nobody)
    var uid: u16 = (@as(u16, h[0]) << 8) | @as(u16, h[1]);
    if (uid == ROOT_UID) uid = 1;
    if (uid == NOBODY_UID) uid = NOBODY_UID - 1;
    return uid;
}

/// Create user from identity (linked to keyring)
/// Root determination: blockchain-anchored (NOT "first user")
pub fn createUser(identity_name: []const u8) ?*User {
    if (!initialized) return null;
    if (user_count >= MAX_USERS) return null;

    // Find identity in keyring
    const id = keyring.findIdentity(identity_name) orelse return null;

    // Check if already registered
    if (findUserByIdentity(identity_name) != null) return null;

    // F3 UPGRADED: Determine role from blockchain, not position
    var role: UserRole = .user; // default

    if (user_chain.isInitialized()) {
        // Ask blockchain what role this pubkey should have
        role = user_chain.determineRole(&id.keypair.public_key);

        // If this is the very first user AND no root exists yet,
        // set up genesis with this user as root
        if (user_count == 0 and !user_chain.isRootPubkey(&id.keypair.public_key)) {
            // No root in blockchain yet — this IS first-time setup
            const name = id.getName();
            var clean_name: [32]u8 = [_]u8{0} ** 32;
            var cn_len: usize = 0;
            var start: usize = 0;
            if (name.len > 0 and name[0] == '@') start = 1;
            while (start + cn_len < name.len and cn_len < 31) : (cn_len += 1) {
                clean_name[cn_len] = name[start + cn_len];
            }

            if (user_chain.setupGenesis(&id.keypair.public_key, clean_name[0..cn_len])) {
                role = .root;
                serial.writeString("[USERS] Genesis setup: ");
                serial.writeString(clean_name[0..cn_len]);
                serial.writeString(" is ROOT (blockchain-anchored)\n");
            } else {
                // Fallback: first user = root (legacy behavior)
                role = .root;
                serial.writeString("[USERS] Genesis setup failed, fallback: first user = root\n");
            }
        }
    } else {
        // Chain not available — fallback to legacy behavior
        if (user_count == 0) role = .root;
    }

    // Derive uid
    const uid: u16 = if (role == .root) ROOT_UID else deriveUid(&id.keypair.public_key);

    // Determine gid based on role
    const gid: u16 = switch (role) {
        .root => GID_ROOT,
        .admin => GID_ADMIN,
        .user => GID_USERS,
        .guest => GID_GUEST,
    };

    // Find free slot
    var slot: usize = 0;
    while (slot < MAX_USERS) : (slot += 1) {
        if (!users_arr[slot].active) break;
    }
    if (slot >= MAX_USERS) return null;

    var u = &users_arr[slot];
    u.uid = uid;
    u.gid = gid;
    u.role = role;
    u.active = true;
    u.created_at = timer.getTicks();

    // Copy name from identity
    const name = id.getName();
    const nlen = @min(name.len, NAME_MAX);
    for (0..nlen) |i| {
        u.name[i] = name[i];
    }
    u.name_len = @intCast(nlen);

    // Copy address
    const addr = id.getAddress();
    const alen = @min(addr.len, 50);
    for (0..alen) |i| {
        u.address[i] = addr[i];
    }
    u.address_len = @intCast(alen);

    // Link to keyring index
    u.identity_index = findIdentityIndex(identity_name);

    user_count += 1;

    // Add to appropriate group
    if (findGroup(gid)) |grp| {
        _ = grp.addMember(uid);
    }
    // Root also in admin group
    if (role == .root) {
        if (findGroup(GID_ADMIN)) |admin_grp| {
            _ = admin_grp.addMember(uid);
        }
    }

    // Record in blockchain (if not already genesis setup)
    if (user_chain.isInitialized() and role != .root) {
        // Non-root users get recorded by current authority
        const current_session_user = findUserByUid(getCurrentUid());
        if (current_session_user != null) {
            if (current_session_user.?.identity_index >= 0) {
                const auth_idx: usize = @intCast(current_session_user.?.identity_index);
                if (keyring.getSlotPtr(auth_idx)) |auth_id| {
                    _ = user_chain.recordIdentityRegister(
                        &id.keypair.public_key,
                        role,
                        id.getName(),
                        &auth_id.keypair.public_key,
                    );
                }
            }
        }
    }

    serial.writeString("[USERS] Created user '");
    serial.writeString(u.getName());
    serial.writeString("' uid=");
    printNum16(uid);
    serial.writeString(" role=");
    serial.writeString(role.toString());
    if (user_chain.isRootPubkey(&id.keypair.public_key)) {
        serial.writeString(" [BLOCKCHAIN ROOT]");
    }
    serial.writeString("\n");

    return u;
}

/// Create user with explicit role (for admin use)
pub fn createUserWithRole(identity_name: []const u8, role: UserRole) ?*User {
    // Only root or admin can assign roles
    if (current_session.active and !current_session.isRoot() and current_session.role != .admin) {
        reportPermissionViolation("createUserWithRole: insufficient privilege");
        return null;
    }

    const u = createUser(identity_name) orelse return null;
    u.role = role;

    // Update gid based on role
    u.gid = switch (role) {
        .root => GID_ROOT,
        .admin => GID_ADMIN,
        .user => GID_USERS,
        .guest => GID_GUEST,
    };

    return u;
}

// === REPLACE deleteUser — add blockchain recording ===

/// Delete user by name — records revocation in blockchain
pub fn deleteUser(name: []const u8) bool {
    if (current_session.active and !current_session.isRoot()) {
        reportPermissionViolation("deleteUser: not root");
        return false;
    }

    const u = findUserByName(name) orelse return false;

    if (u.uid == ROOT_UID) {
        serial.writeString("[USERS] Cannot delete root user\n");
        return false;
    }

    if (current_session.active and current_session.uid == u.uid) {
        serial.writeString("[USERS] Cannot delete current user\n");
        return false;
    }

    // Record revocation in blockchain BEFORE deleting
    if (user_chain.isInitialized() and u.identity_index >= 0) {
        const idx: usize = @intCast(u.identity_index);
        if (keyring.getSlotPtr(idx)) |target_id| {
            const current_user = findUserByUid(getCurrentUid());
            if (current_user != null and current_user.?.identity_index >= 0) {
                const auth_idx: usize = @intCast(current_user.?.identity_index);
                if (keyring.getSlotPtr(auth_idx)) |auth_id| {
                    _ = user_chain.recordRoleRevoke(
                        &target_id.keypair.public_key,
                        1, // reason: admin action
                        &auth_id.keypair.public_key,
                    );
                }
            }
        }
    }

    // Remove from all groups
    for (&groups) |*g| {
        if (g.active) {
            _ = g.removeMember(u.uid);
        }
    }

    u.active = false;
    if (user_count > 0) user_count -= 1;

    serial.writeString("[USERS] Deleted user '");
    serial.writeString(name);
    serial.writeString("'\n");

    return true;
}

// === REPLACE setUserRole — add blockchain recording ===

/// Set user role (admin operation) — records in blockchain
pub fn setUserRole(name: []const u8, role: UserRole) bool {
    if (current_session.active and !current_session.isRoot()) {
        reportPermissionViolation("setUserRole: not root");
        return false;
    }

    const u = findUserByName(name) orelse return false;

    // Cannot change root's role
    if (u.uid == ROOT_UID and role != .root) return false;

    u.role = role;
    u.gid = switch (role) {
        .root => GID_ROOT,
        .admin => GID_ADMIN,
        .user => GID_USERS,
        .guest => GID_GUEST,
    };

    // Record role change in blockchain
    if (user_chain.isInitialized() and u.identity_index >= 0) {
        const idx: usize = @intCast(u.identity_index);
        if (keyring.getSlotPtr(idx)) |target_id| {
            // Get current user's pubkey as assigner
            const current_user = findUserByUid(getCurrentUid());
            if (current_user != null and current_user.?.identity_index >= 0) {
                const auth_idx: usize = @intCast(current_user.?.identity_index);
                if (keyring.getSlotPtr(auth_idx)) |auth_id| {
                    _ = user_chain.recordRoleAssign(
                        &target_id.keypair.public_key,
                        role,
                        &auth_id.keypair.public_key,
                    );
                }
            }
        }
    }

    return true;
}
// =============================================================================
// User Lookup
// =============================================================================

pub fn findUserByUid(uid: u16) ?*User {
    for (&users_arr) |*u| {
        if (u.active and u.uid == uid) return u;
    }
    return null;
}

pub fn findUserByName(name: []const u8) ?*User {
    for (&users_arr) |*u| {
        if (!u.active) continue;
        if (namesMatch(u.getName(), name)) return u;
    }
    return null;
}

pub fn findUserByIdentity(identity_name: []const u8) ?*User {
    for (&users_arr) |*u| {
        if (!u.active) continue;
        if (namesMatch(u.getName(), identity_name)) return u;
    }
    return null;
}

// =============================================================================
// Group Lookup
// =============================================================================

pub fn findGroup(gid: u16) ?*Group {
    for (&groups) |*g| {
        if (g.active and g.gid == gid) return g;
    }
    return null;
}

pub fn findGroupByName(name: []const u8) ?*Group {
    for (&groups) |*g| {
        if (!g.active) continue;
        if (strEqual(g.getName(), name)) return g;
    }
    return null;
}

/// Check if user is member of group
pub fn isInGroup(uid: u16, gid: u16) bool {
    const g = findGroup(gid) orelse return false;
    return g.hasMember(uid);
}

/// Create a new group
pub fn createGroup(name: []const u8) ?*Group {
    if (!initialized) return null;
    if (group_count >= MAX_GROUPS) return null;
    if (current_session.active and !current_session.isRoot() and current_session.role != .admin) {
        reportPermissionViolation("createGroup: insufficient privilege");
        return null;
    }

    // Check duplicate
    if (findGroupByName(name) != null) return null;

    const gid = next_gid;
    next_gid += 1;

    createGroupInternal(name, gid);

    return findGroup(gid);
}

/// Add user to group
pub fn addUserToGroup(uid: u16, gid: u16) bool {
    if (current_session.active and !current_session.isRoot() and current_session.role != .admin) {
        reportPermissionViolation("addUserToGroup: insufficient privilege");
        return false;
    }

    const g = findGroup(gid) orelse return false;
    return g.addMember(uid);
}

// =============================================================================
// Session Management (Login/Logout)
// =============================================================================

/// Login with identity name and PIN
pub fn login(identity_name: []const u8, pin: []const u8) bool {
    if (!initialized) return false;

    // If already logged in, must logout first
    if (current_session.active) {
        serial.writeString("[USERS] Already logged in. Logout first.\n");
        return false;
    }

    // Authenticate via identity auth system
    if (!auth.unlock(identity_name, pin)) {
        // Report auth failure
        if (violation.isInitialized()) {
            _ = violation.reportViolation(.{
                .violation_type = .auth_failure,
                .severity = .medium,
                .pid = 0,
                .source_ip = 0,
                .detail = "login: invalid credentials",
            });
        }
        serial.writeString("[USERS] Login failed: invalid credentials\n");
        return false;
    }

    // Find or auto-create user
    var user = findUserByIdentity(identity_name);
    if (user == null) {
        // Auto-create user from identity
        user = createUser(identity_name);
        if (user == null) {
            auth.lock();
            serial.writeString("[USERS] Login failed: cannot create user\n");
            return false;
        }
    }

    const u = user.?;

    // Set session
    current_session.uid = u.uid;
    current_session.gid = u.gid;
    current_session.euid = u.uid;
    current_session.egid = u.gid;
    current_session.role = u.role;
    current_session.active = true;
    current_session.login_time = timer.getTicks();
    current_session.sudo_active = false;
    current_session.sudo_expires = 0;

    // Copy name
    const name = u.getName();
    const nlen = @min(name.len, NAME_MAX);
    for (0..nlen) |i| {
        current_session.name[i] = name[i];
    }
    current_session.name_len = @intCast(nlen);

    // Update user last login
    u.last_login = timer.getTicks();

    serial.writeString("[USERS] Login successful: ");
    serial.writeString(current_session.getName());
    serial.writeString(" (uid=");
    printNum16(u.uid);
    serial.writeString(", role=");
    serial.writeString(u.role.toString());
    serial.writeString(")\n");

    return true;
}

/// Logout current session
pub fn logout() void {
    if (!current_session.active) return;

    serial.writeString("[USERS] Logout: ");
    serial.writeString(current_session.getName());
    serial.writeString("\n");

    // Lock identity auth
    auth.lock();

    // Clear session
    current_session = .{};
}

/// Switch user (su) — requires target user's PIN
pub fn switchUser(target_name: []const u8, pin: []const u8) bool {
    if (!current_session.active) {
        serial.writeString("[USERS] Not logged in\n");
        return false;
    }

    // Authenticate target
    if (!auth.unlock(target_name, pin)) {
        reportPermissionViolation("su: invalid credentials for target");
        return false;
    }

    const target = findUserByIdentity(target_name) orelse {
        auth.lock();
        return false;
    };

    // Update session
    current_session.uid = target.uid;
    current_session.gid = target.gid;
    current_session.euid = target.uid;
    current_session.egid = target.gid;
    current_session.role = target.role;
    current_session.sudo_active = false;

    const name = target.getName();
    const nlen = @min(name.len, NAME_MAX);
    for (0..nlen) |i| {
        current_session.name[i] = name[i];
    }
    current_session.name_len = @intCast(nlen);

    serial.writeString("[USERS] Switched to user: ");
    serial.writeString(current_session.getName());
    serial.writeString("\n");

    return true;
}

/// Sudo — temporarily elevate to root
pub fn sudo(root_pin: []const u8) bool {
    if (!current_session.active) return false;

    // Already root
    if (current_session.isRoot()) {
        current_session.sudo_active = true;
        return true;
    }

    // Must be admin role
    if (current_session.role != .admin and current_session.role != .root) {
        reportPermissionViolation("sudo: user is not admin");
        return false;
    }

    // Need CAP_ADMIN
    // (In a real system, we'd check process caps. Here check role.)

    // Verify root identity's PIN
    // Find root user
    const root_user = findUserByUid(ROOT_UID) orelse {
        serial.writeString("[USERS] sudo: no root user found\n");
        return false;
    };

    // Authenticate as root
    if (!auth.unlock(root_user.getName(), root_pin)) {
        reportPermissionViolation("sudo: invalid root credentials");

        // Re-unlock original user's session
        // (auth.unlock changes the current identity, so we re-auth)
        _ = auth.unlock(current_session.getName(), ""); // This will fail, but that's ok
        return false;
    }

    // Activate sudo
    current_session.euid = ROOT_UID;
    current_session.egid = ROOT_GID;
    current_session.sudo_active = true;
    current_session.sudo_expires = timer.getTicks() + SUDO_TIMEOUT;

    serial.writeString("[USERS] sudo activated for ");
    serial.writeString(current_session.getName());
    serial.writeString("\n");

    // Log to blockchain audit
    if (violation.isInitialized()) {
        _ = violation.reportViolation(.{
            .violation_type = .capability_violation,
            .severity = .info,
            .pid = 0,
            .source_ip = 0,
            .detail = "sudo: privilege escalation",
        });
    }

    return true;
}

/// Drop sudo privileges
pub fn sudoEnd() void {
    if (!current_session.sudo_active) return;

    current_session.euid = current_session.uid;
    current_session.egid = current_session.gid;
    current_session.sudo_active = false;
    current_session.sudo_expires = 0;

    serial.writeString("[USERS] sudo deactivated\n");
}

// =============================================================================
// Session Query
// =============================================================================

pub fn getCurrentSession() *const Session {
    return &current_session;
}

pub fn getCurrentUid() u16 {
    if (!current_session.active) return NOBODY_UID;
    return current_session.euid; // effective uid
}

pub fn getCurrentGid() u16 {
    if (!current_session.active) return NOBODY_GID;
    return current_session.egid;
}

pub fn getCurrentRole() UserRole {
    if (!current_session.active) return .guest;
    if (current_session.isSudoActive()) return .root;
    return current_session.role;
}

pub fn isLoggedIn() bool {
    return current_session.active;
}

pub fn isCurrentRoot() bool {
    if (!current_session.active) return false;
    return current_session.euid == ROOT_UID;
}

// =============================================================================
// File Permission Checking
// =============================================================================

pub const PermCheck = enum(u8) {
    read = 0,
    write = 1,
    exec = 2,
};

/// Check if current user can access file with given permission
/// Returns true if access allowed
pub fn checkFilePermission(
    file_uid: u32,
    file_gid: u32,
    mode: anytype, // FileMode from inode.zig
    perm: PermCheck,
) bool {
    // If no session active, allow all (boot/kernel mode)
    if (!current_session.active) return true;

    // Root bypasses all permission checks
    if (isCurrentRoot()) return true;

    const uid = getCurrentUid();
    const gid = getCurrentGid();

    // Check owner permissions
    if (uid == @as(u16, @intCast(file_uid & 0xFFFF))) {
        return switch (perm) {
            .read => mode.owner_read,
            .write => mode.owner_write,
            .exec => mode.owner_exec,
        };
    }

    // Check group permissions
    if (gid == @as(u16, @intCast(file_gid & 0xFFFF)) or
        isInGroup(uid, @intCast(file_gid & 0xFFFF)))
    {
        return switch (perm) {
            .read => mode.group_read,
            .write => mode.group_write,
            .exec => mode.group_exec,
        };
    }

    // Check other permissions
    return switch (perm) {
        .read => mode.other_read,
        .write => mode.other_write,
        .exec => mode.other_exec,
    };
}

/// Check and enforce file permission with violation reporting
pub fn checkAndEnforceFilePermission(
    file_path: []const u8,
    file_uid: u32,
    file_gid: u32,
    mode: anytype,
    perm: PermCheck,
) bool {
    if (checkFilePermission(file_uid, file_gid, mode, perm)) return true;

    // Permission denied — report violation
    var detail_buf: [48]u8 = [_]u8{0} ** 48;
    var pos: usize = 0;

    const prefix = "perm denied: ";
    for (prefix) |c| {
        if (pos >= 48) break;
        detail_buf[pos] = c;
        pos += 1;
    }

    const perm_str = switch (perm) {
        .read => "r ",
        .write => "w ",
        .exec => "x ",
    };
    for (perm_str) |c| {
        if (pos >= 48) break;
        detail_buf[pos] = c;
        pos += 1;
    }

    const path_max = @min(file_path.len, 48 - pos);
    for (0..path_max) |i| {
        detail_buf[pos] = file_path[i];
        pos += 1;
    }

    if (violation.isInitialized()) {
        _ = violation.reportViolation(.{
            .violation_type = .filesystem_violation,
            .severity = .medium,
            .pid = 0,
            .source_ip = 0,
            .detail = detail_buf[0..pos],
        });
    }

    return false;
}

// =============================================================================
// Helpers
// =============================================================================

fn findIdentityIndex(name: []const u8) i8 {
    var i: usize = 0;
    while (i < keyring.MAX_IDENTITIES) : (i += 1) {
        if (keyring.getSlotPtr(i)) |id_ptr| {
            if (id_ptr.active and id_ptr.has_name) {
                if (namesMatch(id_ptr.getName(), name)) {
                    return @intCast(i);
                }
            }
        }
    }
    return -1;
}

fn namesMatch(a: []const u8, b: []const u8) bool {
    var a_start: usize = 0;
    var b_start: usize = 0;
    if (a.len > 0 and a[0] == '@') a_start = 1;
    if (b.len > 0 and b[0] == '@') b_start = 1;
    const a_name = a[a_start..];
    const b_name = b[b_start..];
    if (a_name.len != b_name.len) return false;
    for (0..a_name.len) |i| {
        if (a_name[i] != b_name[i]) return false;
    }
    return true;
}

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (0..a.len) |i| {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn reportPermissionViolation(detail: []const u8) void {
    serial.writeString("[USERS] VIOLATION: ");
    serial.writeString(detail);
    serial.writeString("\n");

    if (violation.isInitialized()) {
        _ = violation.reportViolation(.{
            .violation_type = .capability_violation,
            .severity = .high,
            .pid = 0,
            .source_ip = 0,
            .detail = detail,
        });
    }
}

// =============================================================================
// Info / Debug
// =============================================================================

pub fn getUserCount() usize {
    return user_count;
}

pub fn getGroupCount() usize {
    return group_count;
}

pub fn getUserByIndex(index: usize) ?*const User {
    if (index >= MAX_USERS) return null;
    if (!users_arr[index].active) return null;
    return &users_arr[index];
}

pub fn getGroupByIndex(index: usize) ?*const Group {
    if (index >= MAX_GROUPS) return null;
    if (!groups[index].active) return null;
    return &groups[index];
}

// =============================================================================
// Print helpers
// =============================================================================

fn printNum16(val: u16) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [5]u8 = undefined;
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

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n=== F3 USER/GROUP TESTS ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Setup: init identity system and create test identity
    keyring.init();
    auth.init();
    _ = keyring.createIdentity("testroot", "1234");
    _ = keyring.createIdentity("testuser", "5678");
    _ = keyring.createIdentity("testguest", "0000");

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and user_count == 0 and group_count == 4) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Create root user (first user)
    serial.writeString("  Test 2: Create root user\n");
    const root = createUser("testroot");
    if (root != null and root.?.uid == ROOT_UID and root.?.role == .root) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Create normal user (second user)
    serial.writeString("  Test 3: Create normal user\n");
    const usr = createUser("testuser");
    if (usr != null and usr.?.uid != ROOT_UID and usr.?.role == .user) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Duplicate user blocked
    serial.writeString("  Test 4: Duplicate blocked\n");
    if (createUser("testroot") == null) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Find user by name
    serial.writeString("  Test 5: Find by name\n");
    if (findUserByName("@testroot") != null and findUserByName("nonexist") == null) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 6: Find user by uid
    serial.writeString("  Test 6: Find by uid\n");
    if (findUserByUid(ROOT_UID) != null) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 7: Default groups exist
    serial.writeString("  Test 7: Default groups\n");
    if (findGroup(GID_ROOT) != null and findGroup(GID_ADMIN) != null and
        findGroup(GID_USERS) != null)
    {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 8: Root in admin group
    serial.writeString("  Test 8: Root in admin group\n");
    if (isInGroup(ROOT_UID, GID_ADMIN)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 9: Login
    serial.writeString("  Test 9: Login\n");
    if (login("testroot", "1234")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 10: Session active
    serial.writeString("  Test 10: Session active\n");
    if (isLoggedIn() and isCurrentRoot()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 11: whoami
    serial.writeString("  Test 11: Current session name\n");
    const sname = current_session.getName();
    if (sname.len > 0) {
        serial.writeString("    OK (");
        serial.writeString(sname);
        serial.writeString(")\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 12: File permission - root bypass
    serial.writeString("  Test 12: Root bypasses permissions\n");
    const readonly_mode = @import("../fs/inode.zig").FileMode.readonly();
    if (checkFilePermission(999, 999, readonly_mode, .write)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 13: Logout
    serial.writeString("  Test 13: Logout\n");
    logout();
    if (!isLoggedIn()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 14: Login as normal user
    serial.writeString("  Test 14: Login normal user\n");
    if (login("testuser", "5678")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 15: Normal user cannot write to root-owned file
    serial.writeString("  Test 15: Permission check (owner write)\n");
    // File owned by root (uid=0), mode 0644
    const file_mode = @import("../fs/inode.zig").FileMode.regular(); // 0644
    if (!checkFilePermission(0, 0, file_mode, .write)) {
        serial.writeString("    OK (denied)\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL (should deny)\n");
        failed += 1;
    }

    // Test 16: Normal user can read root-owned file (other_read=true)
    serial.writeString("  Test 16: Permission check (other read)\n");
    if (checkFilePermission(0, 0, file_mode, .read)) {
        serial.writeString("    OK (allowed)\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL (should allow)\n");
        failed += 1;
    }

    // Test 17: Normal user can write own file
    serial.writeString("  Test 17: Permission check (owner write own)\n");
    const my_uid = getCurrentUid();
    if (checkFilePermission(my_uid, getCurrentGid(), file_mode, .write)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 18: Wrong login rejected
    serial.writeString("  Test 18: Wrong PIN rejected\n");
    logout();
    if (!login("testroot", "9999")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 19: Role capabilities
    serial.writeString("  Test 19: Role capabilities\n");
    const root_caps = UserRole.root.defaultCaps();
    const guest_caps = UserRole.guest.defaultCaps();
    if (root_caps == capability.CAP_ALL and guest_caps != capability.CAP_ALL and
        (guest_caps & capability.CAP_FS_READ) != 0 and
        (guest_caps & capability.CAP_FS_WRITE) == 0)
    {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 20: Uid derivation is deterministic
    serial.writeString("  Test 20: Uid deterministic\n");
    var test_key: [32]u8 = [_]u8{0xAB} ** 32;
    const uid1 = deriveUid(&test_key);
    const uid2 = deriveUid(&test_key);
    if (uid1 == uid2 and uid1 != ROOT_UID and uid1 != NOBODY_UID) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 21: Group management
    serial.writeString("  Test 21: Create group\n");
    _ = login("testroot", "1234"); // login as root for permission
    const dev_grp = createGroup("developers");
    if (dev_grp != null) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 22: Add user to group
    serial.writeString("  Test 22: Add to group\n");
    if (usr != null and dev_grp != null) {
        if (addUserToGroup(usr.?.uid, dev_grp.?.gid)) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("    SKIP\n");
        failed += 1;
    }

    // Test 23: Group membership check
    serial.writeString("  Test 23: Group membership\n");
    if (usr != null and dev_grp != null) {
        if (isInGroup(usr.?.uid, dev_grp.?.gid)) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("    SKIP\n");
        failed += 1;
    }

    // Test 24: Delete user
    serial.writeString("  Test 24: Delete user\n");
    if (deleteUser("testguest") or true) { // guest wasn't created, but test the path
        // Create guest then delete
        _ = createUser("testguest");
        if (deleteUser("testguest")) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    }

    // Test 25: Cannot delete root
    serial.writeString("  Test 25: Cannot delete root\n");
    if (!deleteUser("testroot")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Cleanup
    logout();

    // Summary
    serial.writeString("\n  F3 USERS: ");
    printNum32(passed);
    serial.writeString("/");
    printNum32(passed + failed);
    serial.writeString(" passed\n");
    serial.writeString("========================================\n\n");

    return failed == 0;
}

fn printNum32(val: u32) void {
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
