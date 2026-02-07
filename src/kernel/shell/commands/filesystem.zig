//! Zamrud OS - Filesystem Commands
//! ls, cd, pwd, mkdir, touch, rm, rmdir, cat, write

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const vfs = @import("../../fs/vfs.zig");

var read_buf: [64]u8 = [_]u8{0} ** 64;

pub fn cmdLs(args: []const u8) void {
    const dir_path = if (args.len > 0) helpers.trim(args) else vfs.getcwd();

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

    while (true) {
        const entry = vfs.readdir(dir_path, index);
        if (entry == null) break;

        if (terminal.isInitialized()) {
            if (entry.?.file_type == .Directory) {
                terminal.setFgColor(terminal.Colors.DIR_COLOR);
                shell.print("  [DIR]  ");
            } else if (entry.?.file_type == .CharDevice) {
                terminal.setFgColor(terminal.Colors.WARNING);
                shell.print("  [DEV]  ");
            } else {
                terminal.setFgColor(terminal.Colors.FILE_COLOR);
                shell.print("  [FILE] ");
            }
            terminal.setFgColor(terminal.Colors.FG_DEFAULT);
        } else {
            if (entry.?.file_type == .Directory) {
                shell.print("  [DIR]  ");
            } else if (entry.?.file_type == .CharDevice) {
                shell.print("  [DEV]  ");
            } else {
                shell.print("  [FILE] ");
            }
        }

        shell.println(entry.?.getName());
        index += 1;
        count += 1;
    }

    if (count == 0) {
        shell.println("  (empty)");
    }
}

pub fn cmdCd(args: []const u8) void {
    const target = if (args.len > 0) helpers.trim(args) else "/";

    if (!vfs.chdir(target)) {
        shell.printError("cd: cannot change to '");
        shell.print(target);
        shell.printErrorLine("': No such directory");
    }
}

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
