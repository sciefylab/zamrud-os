//! Zamrud OS - F3 User/Group Shell Commands
//! Top-level: login, logout, whoami, su, sudo
//! Sub-command: user <cmd> [args]

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const users = @import("../../security/users.zig");
const identity_mod = @import("../../identity/identity.zig");
const keyring = @import("../../identity/keyring.zig");
const vfs = @import("../../fs/vfs.zig");
const capability = @import("../../security/capability.zig");

// =============================================================================
// Top-Level Commands (called directly from commands.zig)
// =============================================================================

/// login <name> <pin>
pub fn cmdLogin(args: []const u8) void {
    if (!users.isInitialized()) {
        shell.printErrorLine("User system not initialized");
        return;
    }

    if (args.len == 0) {
        shell.println("  Usage: login <identity_name> <pin>");
        return;
    }

    const parsed = helpers.parseArgs(args);
    if (parsed.cmd.len == 0) {
        shell.println("  Usage: login <identity_name> <pin>");
        return;
    }

    const name = parsed.cmd;
    const pin_parsed = helpers.parseArgs(parsed.rest);
    const pin = pin_parsed.cmd;

    if (pin.len == 0) {
        shell.println("  Usage: login <name> <pin>");
        return;
    }

    if (users.login(name, pin)) {
        const session = users.getCurrentSession();
        shell.newLine();
        shell.printSuccess("  Login successful!");
        shell.newLine();
        shell.print("  User:  ");
        shell.println(session.getName());
        shell.print("  Role:  ");
        shell.println(session.role.toString());
        shell.print("  UID:   ");
        helpers.printDec(session.euid);
        shell.newLine();
        shell.newLine();
    } else {
        shell.printErrorLine("Login failed: invalid credentials");
    }
}

/// logout
pub fn cmdLogout(_: []const u8) void {
    if (!users.isLoggedIn()) {
        shell.printWarning("  Not logged in");
        shell.newLine();
        return;
    }

    const name = users.getCurrentSession().getName();
    shell.print("  Goodbye, ");
    shell.print(name);
    shell.println("!");
    users.logout();
}

/// whoami
pub fn cmdWhoami(_: []const u8) void {
    if (!users.isLoggedIn()) {
        shell.println("  nobody (not logged in)");
        return;
    }

    const session = users.getCurrentSession();
    shell.newLine();
    shell.print("  User:     ");
    shell.println(session.getName());
    shell.print("  UID:      ");
    helpers.printDec(session.euid);
    shell.newLine();
    shell.print("  GID:      ");
    helpers.printDec(session.egid);
    shell.newLine();
    shell.print("  Role:     ");
    shell.println(session.role.toString());
    shell.print("  Sudo:     ");
    shell.println(if (session.isSudoActive()) "active" else "inactive");
    shell.newLine();
}

/// id [name]
pub fn cmdId(args: []const u8) void {
    if (!users.isInitialized()) {
        shell.printErrorLine("User system not initialized");
        return;
    }

    if (args.len == 0) {
        if (!users.isLoggedIn()) {
            shell.println("  uid=65534(nobody) gid=65534(nobody)");
            return;
        }
        const session = users.getCurrentSession();
        shell.print("  uid=");
        helpers.printDec(session.euid);
        shell.print("(");
        shell.print(session.getName());
        shell.print(") gid=");
        helpers.printDec(session.egid);
        if (users.findGroup(session.egid)) |g| {
            shell.print("(");
            shell.print(g.getName());
            shell.print(")");
        }
        shell.print(" role=");
        shell.println(session.role.toString());
        return;
    }

    const parsed = helpers.parseArgs(args);
    const u = users.findUserByName(parsed.cmd) orelse {
        shell.printError("  User not found: ");
        shell.println(parsed.cmd);
        return;
    };

    shell.print("  uid=");
    helpers.printDec(u.uid);
    shell.print("(");
    shell.print(u.getName());
    shell.print(") gid=");
    helpers.printDec(u.gid);
    if (users.findGroup(u.gid)) |g| {
        shell.print("(");
        shell.print(g.getName());
        shell.print(")");
    }
    shell.print(" role=");
    shell.println(u.role.toString());
}

/// su <name> <pin>
pub fn cmdSu(args: []const u8) void {
    if (!users.isInitialized()) {
        shell.printErrorLine("User system not initialized");
        return;
    }

    if (args.len == 0) {
        shell.println("  Usage: su <username> <pin>");
        return;
    }

    const parsed = helpers.parseArgs(args);
    const name = parsed.cmd;
    const pin_parsed = helpers.parseArgs(parsed.rest);
    const pin = pin_parsed.cmd;

    if (pin.len == 0) {
        shell.println("  Usage: su <username> <pin>");
        return;
    }

    if (users.switchUser(name, pin)) {
        shell.printSuccess("  Switched to: ");
        shell.println(users.getCurrentSession().getName());
    } else {
        shell.printErrorLine("Switch user failed");
    }
}

/// sudo <root_pin>
pub fn cmdSudo(args: []const u8) void {
    if (!users.isInitialized()) {
        shell.printErrorLine("User system not initialized");
        return;
    }

    if (args.len == 0) {
        // Check if sudo already active
        if (users.isLoggedIn() and users.getCurrentSession().isSudoActive()) {
            shell.println("  Sudo is active. Use 'sudoend' to deactivate.");
            return;
        }
        shell.println("  Usage: sudo <root_pin>");
        return;
    }

    const parsed = helpers.parseArgs(args);

    if (users.sudo(parsed.cmd)) {
        shell.printSuccessLine("  Sudo activated");
    } else {
        shell.printErrorLine("Sudo failed: insufficient privileges or wrong PIN");
    }
}

/// sudoend
pub fn cmdSudoEnd(_: []const u8) void {
    users.sudoEnd();
    shell.println("  Sudo deactivated");
}

// =============================================================================
// Sub-command dispatcher: user <cmd> [args]
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "list")) {
        cmdListUsers();
    } else if (helpers.strEql(parsed.cmd, "add")) {
        cmdUseradd(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "del")) {
        cmdUserdel(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "groups")) {
        cmdGroups(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "role")) {
        cmdSetRole(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "chmod")) {
        cmdChmod(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "chown")) {
        cmdChown(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "test")) {
        cmdTest();
    } else {
        shell.printError("user: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'user help'");
    }
}

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  USER - User/Group Management (F3)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Top-level commands:");
    shell.println("  login <name> <pin>   Login with identity");
    shell.println("  logout               Logout current session");
    shell.println("  whoami               Show current user info");
    shell.println("  id [name]            Show user/group IDs");
    shell.println("  su <name> <pin>      Switch user");
    shell.println("  sudo <root_pin>      Elevate to root");
    shell.println("  sudoend              Drop sudo privileges");
    shell.newLine();

    shell.println("Sub-commands (user <cmd>):");
    shell.println("  user list            List all users");
    shell.println("  user add <name>      Create user from identity");
    shell.println("  user del <name>      Delete user (root only)");
    shell.println("  user groups [name]   Show group memberships");
    shell.println("  user role <n> <role> Set user role (root only)");
    shell.println("  user chmod <mode> <f> Change file permissions");
    shell.println("  user chown <uid> <f>  Change file owner");
    shell.println("  user test            Run F3 tests");
    shell.newLine();

    shell.println("Roles: root, admin, user, guest");
    shell.println("Related: identity, caps");
    shell.newLine();
}

// =============================================================================
// user list
// =============================================================================

fn cmdListUsers() void {
    if (!users.isInitialized()) {
        shell.printErrorLine("User system not initialized");
        return;
    }

    shell.newLine();
    shell.println("  UID   NAME                 ROLE     GID");
    shell.println("  ───── ──────────────────── ──────── ─────");

    var found: usize = 0;
    var i: usize = 0;
    while (i < users.MAX_USERS) : (i += 1) {
        if (users.getUserByIndex(i)) |u| {
            shell.print("  ");
            helpers.printU16Padded(u.uid, 5);
            shell.print(" ");
            printPaddedStr(u.getName(), 20);
            shell.print(" ");
            printPaddedStr(u.role.toString(), 8);
            shell.print(" ");
            helpers.printDec(u.gid);
            shell.newLine();
            found += 1;
        }
    }

    if (found == 0) {
        shell.println("  (no users)");
    }
    shell.newLine();
}

// =============================================================================
// user add <name>
// =============================================================================

fn cmdUseradd(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: user add <identity_name>");
        return;
    }

    const parsed = helpers.parseArgs(args);

    // Check identity exists
    if (keyring.findIdentity(parsed.cmd) == null) {
        shell.printError("  Identity not found: ");
        shell.println(parsed.cmd);
        shell.println("  Create identity first: identity create <name> <pin>");
        return;
    }

    if (users.createUser(parsed.cmd)) |u| {
        shell.printSuccess("  User created: ");
        shell.print(u.getName());
        shell.print(" (uid=");
        helpers.printDec(u.uid);
        shell.print(", role=");
        shell.print(u.role.toString());
        shell.println(")");
    } else {
        shell.printErrorLine("Failed to create user (already exists or limit reached)");
    }
}

// =============================================================================
// user del <name>
// =============================================================================

fn cmdUserdel(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: user del <name>");
        return;
    }

    const parsed = helpers.parseArgs(args);

    if (users.deleteUser(parsed.cmd)) {
        shell.printSuccess("  User deleted: ");
        shell.println(parsed.cmd);
    } else {
        shell.printErrorLine("Failed to delete user (not found, is root, or not authorized)");
    }
}

// =============================================================================
// user groups [name]
// =============================================================================

fn cmdGroups(args: []const u8) void {
    if (!users.isInitialized()) {
        shell.printErrorLine("User system not initialized");
        return;
    }

    if (args.len == 0) {
        // Show all groups
        shell.newLine();
        shell.println("  GID   NAME                 MEMBERS");
        shell.println("  ───── ──────────────────── ───────");

        var i: usize = 0;
        while (i < users.MAX_GROUPS) : (i += 1) {
            if (users.getGroupByIndex(i)) |g| {
                shell.print("  ");
                helpers.printU16Padded(g.gid, 5);
                shell.print(" ");
                printPaddedStr(g.getName(), 20);
                shell.print(" ");
                helpers.printDec(@as(u16, g.member_count));
                shell.newLine();
            }
        }
        shell.newLine();
        return;
    }

    // Show groups for specific user
    const parsed = helpers.parseArgs(args);
    const u = users.findUserByName(parsed.cmd) orelse {
        shell.printError("  User not found: ");
        shell.println(parsed.cmd);
        return;
    };

    shell.print("  Groups for ");
    shell.print(u.getName());
    shell.println(":");

    var i: usize = 0;
    while (i < users.MAX_GROUPS) : (i += 1) {
        if (users.getGroupByIndex(i)) |g| {
            if (g.hasMember(u.uid)) {
                shell.print("    ");
                helpers.printDec(g.gid);
                shell.print(" (");
                shell.print(g.getName());
                shell.println(")");
            }
        }
    }
}

// =============================================================================
// user role <name> <role>
// =============================================================================

fn cmdSetRole(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: user role <name> <root|admin|user|guest>");
        return;
    }

    const parsed = helpers.parseArgs(args);
    const name = parsed.cmd;
    const role_parsed = helpers.parseArgs(parsed.rest);
    const role_str = role_parsed.cmd;

    if (role_str.len == 0) {
        shell.println("  Usage: user role <name> <root|admin|user|guest>");
        return;
    }

    const role: users.UserRole = if (helpers.strEql(role_str, "root"))
        .root
    else if (helpers.strEql(role_str, "admin"))
        .admin
    else if (helpers.strEql(role_str, "user"))
        .user
    else if (helpers.strEql(role_str, "guest"))
        .guest
    else {
        shell.printErrorLine("Invalid role. Use: root, admin, user, guest");
        return;
    };

    if (users.setUserRole(name, role)) {
        shell.printSuccess("  Role updated: ");
        shell.print(name);
        shell.print(" → ");
        shell.println(role.toString());
    } else {
        shell.printErrorLine("Failed to set role (not found or not authorized)");
    }
}

// =============================================================================
// user chmod <mode> <file>
// =============================================================================

fn cmdChmod(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: user chmod <mode_octal> <file>");
        shell.println("  Example: user chmod 755 myfile");
        return;
    }

    const parsed = helpers.parseArgs(args);
    const mode_str = parsed.cmd;
    const file_parsed = helpers.parseArgs(parsed.rest);
    const file_path = file_parsed.cmd;

    if (file_path.len == 0) {
        shell.println("  Usage: user chmod <mode> <file>");
        return;
    }

    const mode_val = parseOctal(mode_str) orelse {
        shell.printErrorLine("Invalid mode (use octal: 755, 644, etc.)");
        return;
    };

    const inode = vfs.resolvePath(file_path) orelse {
        shell.printError("  File not found: ");
        shell.println(file_path);
        return;
    };

    // Permission check: must be owner or root
    if (users.isLoggedIn() and !users.isCurrentRoot()) {
        const uid = users.getCurrentUid();
        if (inode.uid != uid) {
            shell.printErrorLine("Permission denied: not owner");
            return;
        }
    }

    const inode_mod = @import("../../fs/inode.zig");
    inode.mode = inode_mod.FileMode.fromOctal(mode_val);

    shell.printSuccess("  Mode changed: ");
    shell.print(file_path);
    shell.print(" → ");
    shell.print(mode_str);
    shell.newLine();
}

// =============================================================================
// user chown <uid> <file>
// =============================================================================

fn cmdChown(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: user chown <uid> <file>");
        return;
    }

    if (users.isLoggedIn() and !users.isCurrentRoot()) {
        shell.printErrorLine("Permission denied: only root can chown");
        return;
    }

    const parsed = helpers.parseArgs(args);
    const uid_str = parsed.cmd;
    const file_parsed = helpers.parseArgs(parsed.rest);
    const file_path = file_parsed.cmd;

    if (file_path.len == 0) {
        shell.println("  Usage: user chown <uid> <file>");
        return;
    }

    const uid = helpers.parseU32(uid_str) orelse {
        shell.printErrorLine("Invalid uid");
        return;
    };

    const inode = vfs.resolvePath(file_path) orelse {
        shell.printError("  File not found: ");
        shell.println(file_path);
        return;
    };

    inode.uid = uid;

    shell.printSuccess("  Owner changed: ");
    shell.print(file_path);
    shell.print(" → uid=");
    helpers.printDec(uid);
    shell.newLine();
}

// =============================================================================
// user test — F3 test suite
// =============================================================================

fn cmdTest() void {
    helpers.printTestHeader("F3 USER/GROUP PERMISSIONS");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Setup: init identity system and create test identities
    keyring.init();
    const auth = @import("../../identity/auth.zig");
    auth.init();
    _ = keyring.createIdentity("testroot", "1234");
    _ = keyring.createIdentity("testuser", "5678");
    _ = keyring.createIdentity("testguest", "0000");

    // Test 1: Init
    users.init();
    passed += helpers.doTest("Initialize", users.isInitialized(), &failed);

    // Test 2: Default groups created (root, admin, users, guest = 4)
    passed += helpers.doTest("Default groups = 4", users.getGroupCount() == 4, &failed);

    // Test 3: Create root user (first user)
    const root = users.createUser("testroot");
    passed += helpers.doTest("Create root user", root != null, &failed);

    // Test 4: Root has uid=0
    if (root) |r| {
        passed += helpers.doTest("Root uid=0", r.uid == users.ROOT_UID, &failed);
    } else {
        passed += helpers.doTest("Root uid=0", false, &failed);
    }

    // Test 5: Root role
    if (root) |r| {
        passed += helpers.doTest("Root role=root", r.role == .root, &failed);
    } else {
        passed += helpers.doTest("Root role=root", false, &failed);
    }

    // Test 6: Create normal user
    const usr = users.createUser("testuser");
    passed += helpers.doTest("Create normal user", usr != null, &failed);

    // Test 7: Normal user != root
    if (usr) |u| {
        passed += helpers.doTest("User uid != 0", u.uid != users.ROOT_UID, &failed);
    } else {
        passed += helpers.doTest("User uid != 0", false, &failed);
    }

    // Test 8: Normal user role
    if (usr) |u| {
        passed += helpers.doTest("User role=user", u.role == .user, &failed);
    } else {
        passed += helpers.doTest("User role=user", false, &failed);
    }

    // Test 9: Duplicate blocked
    passed += helpers.doTest("Duplicate blocked", users.createUser("testroot") == null, &failed);

    // Test 10: Find by name
    passed += helpers.doTest("Find by name", users.findUserByName("@testroot") != null, &failed);

    // Test 11: Find nonexist
    passed += helpers.doTest("Find nonexist null", users.findUserByName("nonexist") == null, &failed);

    // Test 12: Find by uid
    passed += helpers.doTest("Find by uid=0", users.findUserByUid(users.ROOT_UID) != null, &failed);

    // Test 13: Default groups exist
    passed += helpers.doTest("Group root exists", users.findGroup(users.GID_ROOT) != null, &failed);

    // Test 14: Root in admin group
    passed += helpers.doTest("Root in admin group", users.isInGroup(users.ROOT_UID, users.GID_ADMIN), &failed);

    // Test 15: Login
    passed += helpers.doTest("Login root", users.login("testroot", "1234"), &failed);

    // Test 16: Session active
    passed += helpers.doTest("Session active", users.isLoggedIn(), &failed);

    // Test 17: Is root
    passed += helpers.doTest("Is root", users.isCurrentRoot(), &failed);

    // Test 18: Root bypasses file permission
    const inode_mod = @import("../../fs/inode.zig");
    const ro_mode = inode_mod.FileMode.readonly();
    passed += helpers.doTest("Root bypass perm", users.checkFilePermission(999, 999, ro_mode, .write), &failed);

    // Test 19: Logout
    users.logout();
    passed += helpers.doTest("Logout", !users.isLoggedIn(), &failed);

    // Test 20: Login normal user
    passed += helpers.doTest("Login normal user", users.login("testuser", "5678"), &failed);

    // Test 21: Normal user NOT root
    passed += helpers.doTest("Not root", !users.isCurrentRoot(), &failed);

    // Test 22: Cannot write root-owned file
    const file_mode = inode_mod.FileMode.regular(); // 0644
    passed += helpers.doTest("Perm denied write", !users.checkFilePermission(0, 0, file_mode, .write), &failed);

    // Test 23: Can read root-owned file (other_read=true in 0644)
    passed += helpers.doTest("Perm allow read", users.checkFilePermission(0, 0, file_mode, .read), &failed);

    // Test 24: Can write own file
    const my_uid = users.getCurrentUid();
    passed += helpers.doTest("Perm own file write", users.checkFilePermission(my_uid, users.getCurrentGid(), file_mode, .write), &failed);

    // Test 25: Role capabilities
    const root_caps = users.UserRole.root.defaultCaps();
    const guest_caps = users.UserRole.guest.defaultCaps();
    passed += helpers.doTest("Role caps correct", root_caps == capability.CAP_ALL and
        (guest_caps & capability.CAP_FS_READ) != 0 and
        (guest_caps & capability.CAP_FS_WRITE) == 0, &failed);

    // Cleanup
    users.logout();

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Internal helpers
// =============================================================================

fn parseOctal(s: []const u8) ?u16 {
    if (s.len == 0 or s.len > 4) return null;
    var result: u16 = 0;
    for (s) |c| {
        if (c < '0' or c > '7') return null;
        result = result * 8 + @as(u16, c - '0');
    }
    return result;
}

fn printPaddedStr(s: []const u8, width: usize) void {
    shell.print(s);
    if (s.len < width) {
        var i: usize = 0;
        while (i < width - s.len) : (i += 1) {
            shell.printChar(' ');
        }
    }
}
