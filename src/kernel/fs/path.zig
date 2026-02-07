//! Zamrud OS - Path Utilities

pub const MAX_PATH: usize = 256;
pub const MAX_FILENAME: usize = 128;
pub const PATH_SEPARATOR: u8 = '/';

/// Mendapatkan basename dari path (nama file/dir terakhir)
pub fn basename(file_path: []const u8) []const u8 {
    if (file_path.len == 0) return "";
    if (file_path.len == 1 and file_path[0] == '/') return "/";

    var end = file_path.len;
    while (end > 0 and file_path[end - 1] == '/') {
        end -= 1;
    }

    if (end == 0) return "/";

    var start = end;
    while (start > 0 and file_path[start - 1] != '/') {
        start -= 1;
    }

    return file_path[start..end];
}

/// Mendapatkan parent directory dari path
pub fn dirname(file_path: []const u8) []const u8 {
    if (file_path.len == 0) return ".";
    if (file_path.len == 1 and file_path[0] == '/') return "/";

    var end = file_path.len;
    while (end > 0 and file_path[end - 1] == '/') {
        end -= 1;
    }

    if (end == 0) return "/";

    while (end > 0 and file_path[end - 1] != '/') {
        end -= 1;
    }

    while (end > 1 and file_path[end - 1] == '/') {
        end -= 1;
    }

    if (end == 0) return ".";

    return file_path[0..end];
}

/// Cek apakah path absolute
pub fn isAbsolute(file_path: []const u8) bool {
    return file_path.len > 0 and file_path[0] == '/';
}

/// Cek apakah path adalah root
pub fn isRoot(file_path: []const u8) bool {
    if (file_path.len == 0) return false;

    var i: usize = 0;
    while (i < file_path.len) : (i += 1) {
        if (file_path[i] != '/') return false;
    }
    return true;
}

/// Normalize path - SIMPLIFIED VERSION
pub fn normalize(file_path: []const u8, output: []u8) usize {
    if (output.len == 0) return 0;
    if (file_path.len == 0) {
        output[0] = '.';
        return 1;
    }

    // Special case: root path
    if (isRoot(file_path)) {
        output[0] = '/';
        return 1;
    }

    // Simple case: no special characters
    var has_dot = false;
    var has_slash = false;
    var idx: usize = 0;
    while (idx < file_path.len) : (idx += 1) {
        if (file_path[idx] == '.') has_dot = true;
        if (file_path[idx] == '/') has_slash = true;
    }

    // If no dots and no slashes, just copy
    if (!has_dot and !has_slash) {
        const copy_len = @min(file_path.len, output.len);
        var i: usize = 0;
        while (i < copy_len) : (i += 1) {
            output[i] = file_path[i];
        }
        return copy_len;
    }

    var out_idx: usize = 0;
    var i: usize = 0;

    const is_absolute = file_path[0] == '/';
    if (is_absolute) {
        output[out_idx] = '/';
        out_idx += 1;
        i = 1;
    }

    while (i < file_path.len) {
        // Skip slashes
        while (i < file_path.len and file_path[i] == '/') {
            i += 1;
        }

        if (i >= file_path.len) break;

        // Find component end
        var end = i;
        while (end < file_path.len and file_path[end] != '/') {
            end += 1;
        }

        const comp_len = end - i;

        // Check for "."
        if (comp_len == 1 and file_path[i] == '.') {
            i = end;
            continue;
        }

        // Check for ".."
        if (comp_len == 2 and file_path[i] == '.' and file_path[i + 1] == '.') {
            if (is_absolute) {
                if (out_idx > 1) {
                    out_idx -= 1;
                    while (out_idx > 1 and output[out_idx - 1] != '/') {
                        out_idx -= 1;
                    }
                }
            } else {
                if (out_idx > 0) {
                    if (out_idx >= 2 and output[out_idx - 1] == '.' and output[out_idx - 2] == '.') {
                        // Already ends with .., add another
                        if (out_idx < output.len) {
                            output[out_idx] = '/';
                            out_idx += 1;
                        }
                        if (out_idx + 1 < output.len) {
                            output[out_idx] = '.';
                            output[out_idx + 1] = '.';
                            out_idx += 2;
                        }
                    } else {
                        // Go up
                        while (out_idx > 0 and output[out_idx - 1] != '/') {
                            out_idx -= 1;
                        }
                        if (out_idx > 0) {
                            out_idx -= 1;
                        }
                    }
                } else {
                    // Output is empty, add ..
                    if (out_idx + 1 < output.len) {
                        output[out_idx] = '.';
                        output[out_idx + 1] = '.';
                        out_idx += 2;
                    }
                }
            }
            i = end;
            continue;
        }

        // Normal component - add separator if needed
        if (out_idx > 0 and output[out_idx - 1] != '/') {
            if (out_idx < output.len) {
                output[out_idx] = '/';
                out_idx += 1;
            }
        }

        // Copy component
        var j: usize = 0;
        while (j < comp_len and out_idx < output.len) : (j += 1) {
            output[out_idx] = file_path[i + j];
            out_idx += 1;
        }

        i = end;
    }

    if (out_idx == 0) {
        if (is_absolute) {
            output[0] = '/';
            return 1;
        } else {
            output[0] = '.';
            return 1;
        }
    }

    // Remove trailing slash
    if (out_idx > 1 and output[out_idx - 1] == '/') {
        out_idx -= 1;
    }

    return out_idx;
}

/// Join dua path
pub fn join(base: []const u8, relative: []const u8, output: []u8) usize {
    if (output.len == 0) return 0;

    var out_idx: usize = 0;

    if (relative.len > 0 and relative[0] == '/') {
        var i: usize = 0;
        while (i < relative.len and out_idx < output.len) : (i += 1) {
            output[out_idx] = relative[i];
            out_idx += 1;
        }
        return out_idx;
    }

    var i: usize = 0;
    while (i < base.len and out_idx < output.len) : (i += 1) {
        output[out_idx] = base[i];
        out_idx += 1;
    }

    if (out_idx > 0 and output[out_idx - 1] != '/' and relative.len > 0) {
        if (out_idx < output.len) {
            output[out_idx] = '/';
            out_idx += 1;
        }
    }

    i = 0;
    while (i < relative.len and out_idx < output.len) : (i += 1) {
        output[out_idx] = relative[i];
        out_idx += 1;
    }

    return out_idx;
}

/// Compare strings
fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}
