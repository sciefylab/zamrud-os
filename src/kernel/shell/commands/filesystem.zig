//! Zamrud OS - Filesystem Commands
//! ls, cd, pwd, mkdir, touch, rm, rmdir, cat, write
//! B2.3: mv (rename), cp (copy), truncate commands
//! T4.1: Colored ls output
//! B2.2: Fixed relative path handling in /disk

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

    // Special case: "ls /disk" or cwd is /disk
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

    if (isDiskFilePath(name)) {
        const fname = extractDiskFilename(name);
        if (fat32.createDirectory(fname)) {
            shell.printSuccess("Created directory on disk: ");
            shell.println(fname);
        } else {
            shell.printError("mkdir: cannot create '");
            shell.print(name);
            shell.printErrorLine("'");
        }
        return;
    }

    const cwd = vfs.getcwd();
    if (isDiskPath(cwd)) {
        if (fat32.createDirectory(name)) {
            shell.printSuccess("Created directory on disk: ");
            shell.println(name);
        } else {
            shell.printError("mkdir: cannot create '");
            shell.print(name);
            shell.printErrorLine("'");
        }
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

    if (isDiskFilePath(name)) {
        const fname = extractDiskFilename(name);
        if (fat32.findInRoot(fname) != null) {
            shell.printWarning("File already exists: ");
            shell.println(fname);
            return;
        }
        if (fat32.createFile(fname, "")) {
            shell.printSuccess("Created file on disk: ");
            shell.println(fname);
        } else {
            shell.printError("touch: cannot create '");
            shell.print(name);
            shell.printErrorLine("'");
        }
        return;
    }

    const cwd = vfs.getcwd();
    if (isDiskPath(cwd)) {
        if (fat32.findInRoot(name) != null) {
            shell.printWarning("File already exists: ");
            shell.println(name);
            return;
        }
        if (fat32.createFile(name, "")) {
            shell.printSuccess("Created file on disk: ");
            shell.println(name);
        } else {
            shell.printError("touch: cannot create '");
            shell.print(name);
            shell.printErrorLine("'");
        }
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

    const cwd = vfs.getcwd();
    if (isDiskPath(cwd)) {
        if (fat32.deleteFile(name)) {
            shell.printSuccess("Removed from disk: ");
            shell.println(name);
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

    if (isDiskFilePath(name)) {
        const fname = extractDiskFilename(name);
        if (fname.len > 0 and fat32.deleteDirectory(fname)) {
            shell.printSuccess("Removed directory from disk: ");
            shell.println(fname);
        } else {
            shell.printError("rmdir: cannot remove '");
            shell.print(name);
            shell.printErrorLine("' (not empty or not found)");
        }
        return;
    }

    const cwd = vfs.getcwd();
    if (isDiskPath(cwd)) {
        if (fat32.deleteDirectory(name)) {
            shell.printSuccess("Removed directory from disk: ");
            shell.println(name);
        } else {
            shell.printError("rmdir: cannot remove '");
            shell.print(name);
            shell.printErrorLine("' (not empty or not found)");
        }
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

    const cwd = vfs.getcwd();
    if (isDiskPath(cwd)) {
        catDiskFile(name);
        return;
    }

    var flags = vfs.OpenFlags{};
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

    const cwd = vfs.getcwd();
    if (isDiskPath(cwd)) {
        writeDiskFile(filename, content);
        return;
    }

    if (!vfs.exists(filename)) {
        if (vfs.createFile(filename) == null) {
            shell.printErrorLine("write: cannot create file");
            return;
        }
    }

    var flags = vfs.OpenFlags{};
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
// B2.3: mv (rename) command
// =============================================================================

pub fn cmdMv(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("mv: usage: mv <source> <destination>");
        return;
    }

    // Parse two arguments
    var space_pos: ?usize = null;
    for (trimmed, 0..) |c, i| {
        if (c == ' ') {
            space_pos = i;
            break;
        }
    }

    if (space_pos == null) {
        shell.printErrorLine("mv: usage: mv <source> <destination>");
        return;
    }

    const src = trimmed[0..space_pos.?];
    var dst_start = space_pos.? + 1;
    while (dst_start < trimmed.len and trimmed[dst_start] == ' ') {
        dst_start += 1;
    }
    if (dst_start >= trimmed.len) {
        shell.printErrorLine("mv: missing destination");
        return;
    }
    const dst = trimmed[dst_start..];

    // Try disk path first
    const src_disk = isDiskFilePath(src);
    const dst_disk = isDiskFilePath(dst);
    const cwd = vfs.getcwd();
    const cwd_disk = isDiskPath(cwd);

    if (src_disk and dst_disk) {
        // Both absolute /disk paths
        const src_name = extractDiskFilename(src);
        const dst_name = extractDiskFilename(dst);
        if (fat32.renameFile(src_name, dst_name)) {
            shell.printSuccess("Renamed: ");
            shell.print(src_name);
            shell.print(" -> ");
            shell.println(dst_name);
        } else {
            shell.printError("mv: cannot rename '");
            shell.print(src);
            shell.printErrorLine("'");
        }
        return;
    }

    if (cwd_disk and !src_disk and !dst_disk) {
        // Both relative in /disk
        if (fat32.renameFile(src, dst)) {
            shell.printSuccess("Renamed: ");
            shell.print(src);
            shell.print(" -> ");
            shell.println(dst);
        } else {
            shell.printError("mv: cannot rename '");
            shell.print(src);
            shell.printErrorLine("'");
        }
        return;
    }

    // VFS rename
    if (vfs.rename(src, dst)) {
        shell.printSuccess("Renamed: ");
        shell.print(src);
        shell.print(" -> ");
        shell.println(dst);
    } else {
        shell.printError("mv: cannot rename '");
        shell.print(src);
        shell.print("' to '");
        shell.print(dst);
        shell.printErrorLine("'");
    }
}

// =============================================================================
// B2.3: cp (copy) command
// =============================================================================

pub fn cmdCp(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("cp: usage: cp <source> <destination>");
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
        shell.printErrorLine("cp: usage: cp <source> <destination>");
        return;
    }

    const src = trimmed[0..space_pos.?];
    var dst_start = space_pos.? + 1;
    while (dst_start < trimmed.len and trimmed[dst_start] == ' ') {
        dst_start += 1;
    }
    if (dst_start >= trimmed.len) {
        shell.printErrorLine("cp: missing destination");
        return;
    }
    const dst = trimmed[dst_start..];

    // Disk paths
    const src_disk = isDiskFilePath(src);
    const dst_disk = isDiskFilePath(dst);
    const cwd = vfs.getcwd();
    const cwd_disk = isDiskPath(cwd);

    if (src_disk and dst_disk) {
        const src_name = extractDiskFilename(src);
        const dst_name = extractDiskFilename(dst);
        if (fat32.copyFile(src_name, dst_name)) {
            shell.printSuccess("Copied: ");
            shell.print(src_name);
            shell.print(" -> ");
            shell.println(dst_name);
        } else {
            shell.printError("cp: cannot copy '");
            shell.print(src);
            shell.printErrorLine("'");
        }
        return;
    }

    if (cwd_disk and !src_disk and !dst_disk) {
        if (fat32.copyFile(src, dst)) {
            shell.printSuccess("Copied: ");
            shell.print(src);
            shell.print(" -> ");
            shell.println(dst);
        } else {
            shell.printError("cp: cannot copy '");
            shell.print(src);
            shell.printErrorLine("'");
        }
        return;
    }

    // VFS copy: read source, write to destination
    // Read source file
    var flags_r = vfs.OpenFlags{};
    flags_r.read = true;
    const src_file = vfs.open(src, flags_r) orelse {
        shell.printError("cp: cannot open source '");
        shell.print(src);
        shell.printErrorLine("'");
        return;
    };

    // Create destination
    if (!vfs.exists(dst)) {
        if (vfs.createFile(dst) == null) {
            vfs.close(src_file);
            shell.printError("cp: cannot create '");
            shell.print(dst);
            shell.printErrorLine("'");
            return;
        }
    }

    var flags_w = vfs.OpenFlags{};
    flags_w.write = true;
    flags_w.truncate = true;
    const dst_file = vfs.open(dst, flags_w) orelse {
        vfs.close(src_file);
        shell.printError("cp: cannot open destination '");
        shell.print(dst);
        shell.printErrorLine("'");
        return;
    };

    var copy_buf: [512]u8 = undefined;
    var total: usize = 0;

    while (true) {
        const n = vfs.read(src_file, &copy_buf);
        if (n <= 0) break;
        const written = vfs.write(dst_file, copy_buf[0..@intCast(n)]);
        if (written <= 0) break;
        total += @intCast(written);
    }

    vfs.close(src_file);
    vfs.close(dst_file);

    shell.printSuccess("Copied ");
    helpers.printUsize(total);
    shell.print(" bytes: ");
    shell.print(src);
    shell.print(" -> ");
    shell.println(dst);
}

// =============================================================================
// B2.3: truncate command
// =============================================================================

pub fn cmdTruncate(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("truncate: usage: truncate <filename> <size>");
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
        // Truncate to 0 if no size given
        const fname = trimmed;
        truncateFile(fname, 0);
        return;
    }

    const fname = trimmed[0..space_pos.?];
    var size_start = space_pos.? + 1;
    while (size_start < trimmed.len and trimmed[size_start] == ' ') {
        size_start += 1;
    }
    const size_str = trimmed[size_start..];

    // Parse size
    var size: u64 = 0;
    for (size_str) |c| {
        if (c >= '0' and c <= '9') {
            size = size * 10 + (c - '0');
        } else {
            shell.printErrorLine("truncate: invalid size");
            return;
        }
    }

    truncateFile(fname, size);
}

fn truncateFile(fname: []const u8, size: u64) void {
    // Disk paths
    if (isDiskFilePath(fname)) {
        const disk_name = extractDiskFilename(fname);
        if (fat32.truncateFile(disk_name, @intCast(@min(size, 0xFFFFFFFF)))) {
            shell.printSuccess("Truncated ");
            shell.print(disk_name);
            shell.print(" to ");
            helpers.printUsize(@intCast(size));
            shell.println(" bytes");
        } else {
            shell.printError("truncate: cannot truncate '");
            shell.print(fname);
            shell.printErrorLine("'");
        }
        return;
    }

    const cwd = vfs.getcwd();
    if (isDiskPath(cwd)) {
        if (fat32.truncateFile(fname, @intCast(@min(size, 0xFFFFFFFF)))) {
            shell.printSuccess("Truncated ");
            shell.print(fname);
            shell.print(" to ");
            helpers.printUsize(@intCast(size));
            shell.println(" bytes");
        } else {
            shell.printError("truncate: cannot truncate '");
            shell.print(fname);
            shell.printErrorLine("'");
        }
        return;
    }

    // VFS truncate
    if (vfs.truncate(fname, size)) {
        shell.printSuccess("Truncated ");
        shell.print(fname);
        shell.print(" to ");
        helpers.printUsize(@intCast(size));
        shell.println(" bytes");
    } else {
        shell.printError("truncate: cannot truncate '");
        shell.print(fname);
        shell.printErrorLine("'");
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
    shell.println("  Name             Size      Type");
    shell.println("  ------------------------------------");
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
            shell.print("-         ");
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_info);
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

    // Delete if exists, then create new
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
