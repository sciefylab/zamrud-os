//! Zamrud OS - Filesystem Commands
//! ls, cd, pwd, mkdir, touch, rm, rmdir, cat, write
//! T4.1: Colored ls output

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const ui = @import("../ui.zig");
const vfs = @import("../../fs/vfs.zig");
const fat32 = @import("../../fs/fat32.zig");

var read_buf: [64]u8 = [_]u8{0} ** 64;

// =============================================================================
// T4.1: Colored ls
// =============================================================================

pub fn cmdLs(args: []const u8) void {
    const dir_path = if (args.len > 0) helpers.trim(args) else vfs.getcwd();
    const theme = ui.getTheme();

    // Special case: "ls /disk"
    if (isDiskPath(dir_path)) {
        listDiskFiles();
        return;
    }

    const inode = vfs.resolvePath(dir_path);
    if (inode == null) {
        shell.printError("ls: cannot access '");
        shell.print(dir_path);
        shell.printErrorLine("': No such file or directory");
        return;
    }

    if (inode.?.file_type != .Directory) {
        shell.print("  ");
        shell.println(dir_path);
        return;
    }

    var index: usize = 0;
    var count: usize = 0;
    var dir_count: usize = 0;
    var file_count: usize = 0;

    while (true) {
        const entry = vfs.readdir(dir_path, index);
        if (entry == null) break;

        shell.print("  ");

        if (terminal.isInitialized()) {
            if (entry.?.file_type == .Directory) {
                terminal.setFgColor(theme.text_info);
                shell.print("[DIR]  ");
                terminal.setFgColor(theme.prompt_path);
                terminal.setBold(true);
                shell.print(entry.?.getName());
                terminal.setBold(false);
                shell.printChar('/');
                dir_count += 1;
            } else if (entry.?.file_type == .CharDevice or entry.?.file_type == .BlockDevice) {
                terminal.setFgColor(theme.text_warning);
                shell.print("[DEV]  ");
                terminal.setFgColor(theme.text_warning);
                shell.print(entry.?.getName());
            } else {
                terminal.setFgColor(theme.text_dim);
                shell.print("[FILE] ");
                terminal.setFgColor(theme.text_normal);
                shell.print(entry.?.getName());
                file_count += 1;
            }
            terminal.setFgColor(theme.text_normal);
        } else {
            if (entry.?.file_type == .Directory) {
                shell.print("[DIR]  ");
                dir_count += 1;
            } else if (entry.?.file_type == .CharDevice) {
                shell.print("[DEV]  ");
            } else {
                shell.print("[FILE] ");
                file_count += 1;
            }
            shell.print(entry.?.getName());
        }

        shell.newLine();
        index += 1;
        count += 1;
    }

    if (count == 0) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.println("  (empty)");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    } else {
        // Summary line
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.print("  ");
        helpers.printUsize(count);
        shell.print(" total (");
        helpers.printUsize(dir_count);
        shell.print(" dirs, ");
        helpers.printUsize(file_count);
        shell.println(" files)");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    }
}

// =============================================================================
// T5.1: cd with ~ support
// =============================================================================

pub fn cmdCd(args: []const u8) void {
    // cd tanpa args = go home
    if (args.len == 0) {
        const shell_mod = @import("../shell.zig");
        const home = shell_mod.getHomeDir();
        if (home.len > 0) {
            if (!vfs.chdir(home)) {
                shell.printErrorLine("cd: cannot change to home");
            }
        }
        return;
    }

    // cd ~ atau cd ~/path
    if (args[0] == '~') {
        const shell_mod = @import("../shell.zig");
        const home = shell_mod.getHomeDir();
        if (home.len == 0) {
            shell.printErrorLine("cd: HOME not set");
            return;
        }

        if (args.len == 1) {
            if (!vfs.chdir(home)) {
                shell.printErrorLine("cd: cannot change to home");
            }
            return;
        }

        if (args.len > 1 and args[1] == '/') {
            var full_path: [256]u8 = [_]u8{0} ** 256;
            var pos: usize = 0;

            for (home) |c| {
                if (pos < 255) {
                    full_path[pos] = c;
                    pos += 1;
                }
            }

            for (args[1..]) |c| {
                if (pos < 255) {
                    full_path[pos] = c;
                    pos += 1;
                }
            }

            if (!vfs.chdir(full_path[0..pos])) {
                shell.printError("cd: cannot change to '");
                shell.print(full_path[0..pos]);
                shell.printErrorLine("': No such directory");
            }
            return;
        }
    }

    // Normal cd
    const target = args;
    if (!vfs.chdir(target)) {
        shell.printError("cd: cannot change to '");
        shell.print(target);
        shell.printErrorLine("': No such directory");
    }
}

// =============================================================================
// Other filesystem commands
// =============================================================================

pub fn cmdPwd(_: []const u8) void {
    shell.print("  ");
    shell.println(vfs.getcwd());
}

pub fn cmdMkdir(args: []const u8) void {
    const name = helpers.trim(args);
    if (name.len == 0) {
        shell.printErrorLine("mkdir: missing operand");
        return;
    }

    if (vfs.createDir(name) != null) {
        shell.printSuccess("Created directory: ");
        shell.println(name);
    } else {
        shell.printError("mkdir: cannot create '");
        shell.print(name);
        shell.printErrorLine("'");
    }
}

pub fn cmdTouch(args: []const u8) void {
    const name = helpers.trim(args);
    if (name.len == 0) {
        shell.printErrorLine("touch: missing operand");
        return;
    }

    if (vfs.exists(name)) {
        shell.printWarning("File already exists: ");
        shell.println(name);
        return;
    }

    if (vfs.createFile(name) != null) {
        shell.printSuccess("Created file: ");
        shell.println(name);
    } else {
        shell.printError("touch: cannot create '");
        shell.print(name);
        shell.printErrorLine("'");
    }
}

pub fn cmdRm(args: []const u8) void {
    const name = helpers.trim(args);
    if (name.len == 0) {
        shell.printErrorLine("rm: missing operand");
        return;
    }

    if (isDiskFilePath(name)) {
        const fname = extractDiskFilename(name);
        if (fname.len > 0 and fat32.deleteFile(fname)) {
            shell.printSuccess("Removed from disk: ");
            shell.println(fname);
        } else {
            shell.printError("rm: cannot remove '");
            shell.print(name);
            shell.printErrorLine("'");
        }
        return;
    }

    if (vfs.removeFile(name)) {
        shell.printSuccess("Removed: ");
        shell.println(name);
    } else {
        shell.printError("rm: cannot remove '");
        shell.print(name);
        shell.printErrorLine("'");
    }
}

pub fn cmdRmdir(args: []const u8) void {
    const name = helpers.trim(args);
    if (name.len == 0) {
        shell.printErrorLine("rmdir: missing operand");
        return;
    }

    if (vfs.removeDir(name)) {
        shell.printSuccess("Removed directory: ");
        shell.println(name);
    } else {
        shell.printError("rmdir: cannot remove '");
        shell.print(name);
        shell.printErrorLine("' (not empty or not found)");
    }
}

pub fn cmdCat(args: []const u8) void {
    const name = helpers.trim(args);
    if (name.len == 0) {
        shell.printErrorLine("cat: missing operand");
        return;
    }

    if (isDiskFilePath(name)) {
        const fname = extractDiskFilename(name);
        catDiskFile(fname);
        return;
    }

    var flags = vfs.OpenFlags.O_RDONLY;
    flags.read = true;
    const file = vfs.open(name, flags);
    if (file == null) {
        shell.printError("cat: cannot open '");
        shell.print(name);
        shell.printErrorLine("'");
        return;
    }

    var total_read: usize = 0;
    const max_bytes: usize = 4096;

    shell.print("  ");

    while (total_read < max_bytes) {
        @memset(&read_buf, 0);

        const bytes_read = vfs.read(file.?, read_buf[0..64]);
        if (bytes_read <= 0) break;

        const read_len: usize = @intCast(bytes_read);
        for (read_buf[0..read_len]) |c| {
            shell.printChar(c);
        }
        total_read += read_len;
    }

    vfs.close(file.?);

    if (total_read > 0) {
        shell.newLine();
    }

    if (total_read >= max_bytes) {
        shell.printWarningLine("(output truncated)");
    }
}

pub fn cmdWrite(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("write: usage: write <filename> <text>");
        return;
    }

    var space_pos: ?usize = null;
    for (trimmed, 0..) |c, i| {
        if (c == ' ') {
            space_pos = i;
            break;
        }
    }

    if (space_pos == null) {
        shell.printErrorLine("write: usage: write <filename> <text>");
        return;
    }

    const filename = trimmed[0..space_pos.?];
    var content_start = space_pos.? + 1;
    while (content_start < trimmed.len and trimmed[content_start] == ' ') {
        content_start += 1;
    }
    const content = trimmed[content_start..];

    if (isDiskFilePath(filename)) {
        const fname = extractDiskFilename(filename);
        if (fname.len > 0) {
            writeDiskFile(fname, content);
        } else {
            shell.printErrorLine("write: invalid disk path");
        }
        return;
    }

    if (!vfs.exists(filename)) {
        if (vfs.createFile(filename) == null) {
            shell.printErrorLine("write: cannot create file");
            return;
        }
    }

    var flags = vfs.OpenFlags.O_WRONLY;
    flags.write = true;
    flags.truncate = true;
    const file = vfs.open(filename, flags);
    if (file == null) {
        shell.printErrorLine("write: cannot open file");
        return;
    }

    const written = vfs.write(file.?, content);
    _ = vfs.write(file.?, "\n");
    vfs.close(file.?);

    if (written > 0) {
        shell.printSuccess("Written ");
        helpers.printUsize(@intCast(written));
        shell.print(" bytes to ");
        shell.println(filename);
    } else {
        shell.printErrorLine("write: failed to write");
    }
}

// =============================================================================
// FAT32 Direct Access Helpers
// =============================================================================

fn isDiskPath(p: []const u8) bool {
    if (p.len == 5 and eql5(p, "/disk")) return true;
    if (p.len == 6 and eql5(p, "/disk") and p[5] == '/') return true;
    if (p.len == 4 and eql4(p, "disk")) return true;
    return false;
}

fn isDiskFilePath(p: []const u8) bool {
    if (p.len > 6 and eql5(p, "/disk") and p[5] == '/') return true;
    return false;
}

fn extractDiskFilename(p: []const u8) []const u8 {
    if (p.len > 6 and eql5(p, "/disk") and p[5] == '/') {
        return p[6..];
    }
    return p;
}

fn eql4(s: []const u8, target: *const [4]u8) bool {
    if (s.len < 4) return false;
    return s[0] == target[0] and s[1] == target[1] and s[2] == target[2] and s[3] == target[3];
}

fn eql5(s: []const u8, target: *const [5]u8) bool {
    if (s.len < 5) return false;
    return s[0] == target[0] and s[1] == target[1] and s[2] == target[2] and s[3] == target[3] and s[4] == target[4];
}

fn listDiskFiles() void {
    const theme = ui.getTheme();

    if (!fat32.isMounted()) {
        shell.printErrorLine("  Disk not mounted");
        return;
    }

    var entries: [32]fat32.FileInfo = undefined;
    const count = fat32.listRoot(&entries);

    if (count == 0) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.println("  (empty disk)");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
        return;
    }

    shell.newLine();
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
    shell.println("  Name            Size       Type");
    shell.println("  ────────────────────────────────────");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    for (entries[0..count]) |entry| {
        shell.print("  ");

        const name = entry.getName();

        if (entry.is_dir) {
            if (terminal.isInitialized()) terminal.setFgColor(theme.prompt_path);
            shell.print(name);
            shell.printChar('/');
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

            var pad_name: usize = if (15 > name.len + 1) 15 - name.len - 1 else 1;
            while (pad_name > 0) : (pad_name -= 1) shell.printChar(' ');

            if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
            shell.print("-          ");
            terminal.setFgColor(theme.text_info);
            shell.print("[DIR]");
        } else {
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
            shell.print(name);

            var pad_name: usize = if (16 > name.len) 16 - name.len else 1;
            while (pad_name > 0) : (pad_name -= 1) shell.printChar(' ');

            helpers.printU32(entry.size);
            shell.print(" B");
            const pad_size: usize = if (entry.size < 10) 8 else if (entry.size < 100) 7 else if (entry.size < 1000) 6 else if (entry.size < 10000) 5 else 4;
            var ps = pad_size;
            while (ps > 0) : (ps -= 1) shell.printChar(' ');

            if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
            shell.print("[FILE]");
        }
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
        shell.newLine();
    }

    shell.newLine();
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
    shell.print("  ");
    helpers.printUsize(count);
    shell.println(" file(s)");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
}

fn catDiskFile(name: []const u8) void {
    if (!fat32.isMounted()) {
        shell.printErrorLine("  Disk not mounted");
        return;
    }

    const file = fat32.findInRoot(name) orelse {
        shell.printError("cat: file not found on disk: ");
        shell.println(name);
        return;
    };

    if (file.is_dir) {
        shell.printErrorLine("cat: is a directory");
        return;
    }

    var buf: [4096]u8 = [_]u8{0} ** 4096;
    const max_read = @min(@as(usize, file.size), 4096);
    const bytes = fat32.readFile(file.cluster, buf[0..max_read]);

    if (bytes == 0) {
        shell.println("  (empty file)");
        return;
    }

    shell.print("  ");
    for (buf[0..bytes]) |c| {
        if (c == '\n') {
            shell.newLine();
            shell.print("  ");
        } else if (c >= 0x20 and c < 0x7F) {
            shell.printChar(c);
        }
    }
    shell.newLine();
}

fn writeDiskFile(name: []const u8, content: []const u8) void {
    if (!fat32.isMounted()) {
        shell.printErrorLine("  Disk not mounted");
        return;
    }

    if (fat32.findInRoot(name) != null) {
        _ = fat32.deleteFile(name);
    }

    if (fat32.createFile(name, content)) {
        shell.printSuccess("Written to disk: ");
        shell.print(name);
        shell.print(" (");
        helpers.printUsize(content.len);
        shell.println(" bytes)");
    } else {
        shell.printError("write: failed to write to disk: ");
        shell.println(name);
    }
}
