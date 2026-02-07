const limine = @import("../../core/limine.zig");

const FONT_WIDTH: u64 = 8;
const FONT_HEIGHT: u64 = 16;

pub const Color = enum(u8) {
    black,
    blue,
    green,
    cyan,
    red,
    magenta,
    brown,
    light_gray,
    dark_gray,
    light_blue,
    light_green,
    light_cyan,
    light_red,
    light_magenta,
    yellow,
    white,

    pub fn toRgb(self: Color) u32 {
        const colors = [_]u32{
            0x000000, 0x0000AA, 0x00AA00, 0x00AAAA,
            0xAA0000, 0xAA00AA, 0xAA5500, 0xAAAAAA,
            0x555555, 0x5555FF, 0x55FF55, 0x55FFFF,
            0xFF5555, 0xFF55FF, 0xFFFF55, 0xFFFFFF,
        };
        return colors[@intFromEnum(self)];
    }
};

var fb: ?*limine.Framebuffer = null;

var cx: usize = 0;
var cy: usize = 0;

var fg: u32 = 0xFFFFFF;
var bg: u32 = 0x000000;

var cols: usize = 0;
var rows: usize = 0;

const font = @embedFile("font.bin");

pub fn init(f: *limine.Framebuffer) void {
    fb = f;

    cols = @as(usize, @intCast(f.width / FONT_WIDTH));
    rows = @as(usize, @intCast(f.height / FONT_HEIGHT));

    clear();
}

pub fn setColor(f_col: Color, b_col: Color) void {
    fg = f_col.toRgb();
    bg = b_col.toRgb();
}

pub fn clear() void {
    const f = fb orelse return;

    const width: usize = @as(usize, @intCast(f.width));
    const height: usize = @as(usize, @intCast(f.height));

    const pixels: [*]u32 = @ptrCast(@alignCast(f.address));

    const count = width * height;
    for (0..count) |i| pixels[i] = bg;

    cx = 0;
    cy = 0;
}

pub fn print(str: []const u8) void {
    for (str) |c| putChar(c);
}

pub fn printInt(val: u64) void {
    if (val == 0) {
        putChar('0');
        return;
    }

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v: u64 = val;

    while (v > 0) : (i += 1) {
        buf[i] = @as(u8, @intCast((v % 10) + '0'));
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        putChar(buf[i]);
    }
}

fn putChar(c: u8) void {
    if (fb == null) return;

    switch (c) {
        '\n' => {
            cx = 0;
            cy += 1;
            if (cy >= rows) scroll();
        },
        '\r' => {
            cx = 0;
        },
        else => {
            if (c >= 32 and c < 127) {
                drawChar(c, cx, cy);
            } else {
                drawChar('?', cx, cy);
            }

            cx += 1;
            if (cx >= cols) {
                cx = 0;
                cy += 1;
                if (cy >= rows) scroll();
            }
        },
    }
}

fn drawChar(c: u8, col: usize, row: usize) void {
    const f = fb orelse return;

    const width: usize = @as(usize, @intCast(f.width));
    const height: usize = @as(usize, @intCast(f.height));
    const pitch_pixels: usize = @as(usize, @intCast(f.pitch / 4));

    const pixels: [*]u32 = @ptrCast(@alignCast(f.address));

    const idx: usize = if (c >= 32 and c < 127) @as(usize, @intCast(c - 32)) else 0;
    const off: usize = idx * @as(usize, @intCast(FONT_HEIGHT));

    if (off + @as(usize, @intCast(FONT_HEIGHT)) > font.len) return;

    const start_x: usize = col * @as(usize, @intCast(FONT_WIDTH));
    const start_y: usize = row * @as(usize, @intCast(FONT_HEIGHT));

    const fw: usize = @as(usize, @intCast(FONT_WIDTH));
    const fh: usize = @as(usize, @intCast(FONT_HEIGHT));

    for (0..fh) |y| {
        const r: u8 = font[off + y];
        for (0..fw) |x| {
            const px = start_x + x;
            const py = start_y + y;

            if (px < width and py < height) {
                const bit: u3 = @as(u3, @intCast(7 - x));
                const on: bool = (((r >> bit) & 1) == 1);
                pixels[py * pitch_pixels + px] = if (on) fg else bg;
            }
        }
    }
}

fn scroll() void {
    const f = fb orelse return;

    const width: usize = @as(usize, @intCast(f.width));
    const height: usize = @as(usize, @intCast(f.height));
    const pitch_pixels: usize = @as(usize, @intCast(f.pitch / 4));

    const line_px: usize = @as(usize, @intCast(FONT_HEIGHT));
    if (height <= line_px) return;

    const pixels: [*]u32 = @ptrCast(@alignCast(f.address));

    const copy_height: usize = height - line_px;

    // move up by FONT_HEIGHT pixels
    for (0..copy_height) |y| {
        const src_y = y + line_px;
        for (0..width) |x| {
            pixels[y * pitch_pixels + x] = pixels[src_y * pitch_pixels + x];
        }
    }

    // clear last area
    for (copy_height..height) |y| {
        for (0..width) |x| {
            pixels[y * pitch_pixels + x] = bg;
        }
    }

    cy = rows - 1;
}

// check point 8 scheduller
