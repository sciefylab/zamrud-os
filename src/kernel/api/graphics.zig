//! Zamrud OS - Graphics API
//! Shared definitions untuk kernel <-> UI engine
//!
//! Copy file ini ke: zamrud-ui/api/graphics.zig

// =============================================================================
// Framebuffer Info
// =============================================================================

/// Framebuffer information structure
pub const FramebufferInfo = extern struct {
    /// Virtual address (setelah di-map)
    address: u64,

    /// Width in pixels
    width: u32,

    /// Height in pixels
    height: u32,

    /// Bytes per scanline (may have padding)
    pitch: u32,

    /// Bits per pixel (8, 16, 24, 32)
    bpp: u16,

    /// Pixel format
    format: PixelFormat,

    /// Reserved
    _pad: u8 = 0,

    /// Total buffer size in bytes
    size: u64,

    /// Display DPI (untuk scaling)
    dpi_x: u16,
    dpi_y: u16,

    /// Refresh rate in Hz
    refresh_rate: u16,

    /// Display flags
    flags: DisplayFlags,

    /// Reserved for future
    _reserved: [16]u8 = [_]u8{0} ** 16,
};

/// Pixel format enumeration
pub const PixelFormat = enum(u8) {
    Unknown = 0,
    BGRA8888 = 1, // Most common (Limine default)
    RGBA8888 = 2,
    ARGB8888 = 3,
    RGB888 = 4, // 24-bit, no alpha
    BGR888 = 5,
    RGB565 = 6, // 16-bit
    BGR565 = 7,
};

/// Display flags
pub const DisplayFlags = packed struct {
    /// Double buffering available
    double_buffer: bool = false,

    /// VSync available
    vsync: bool = false,

    /// Hardware cursor available
    hw_cursor: bool = false,

    /// Touch screen
    touch_screen: bool = false,

    /// External display
    external: bool = false,

    /// HDR capable
    hdr: bool = false,

    /// Reserved
    _pad: u2 = 0,
};

// =============================================================================
// Cursor Info (Hardware Cursor)
// =============================================================================

pub const CursorInfo = extern struct {
    /// Cursor visible
    visible: bool,

    /// Cursor type (dari input.zig)
    cursor_type: u8,

    /// Reserved
    _pad: [2]u8 = [_]u8{0} ** 2,

    /// Current X position
    x: i32,

    /// Current Y position
    y: i32,

    /// Hotspot X (click point offset)
    hotspot_x: i16,

    /// Hotspot Y
    hotspot_y: i16,

    /// Custom cursor width (if custom)
    width: u16,

    /// Custom cursor height
    height: u16,

    /// Custom cursor image address (ARGB)
    image_addr: u64,
};

// =============================================================================
// Display Mode
// =============================================================================

pub const DisplayMode = extern struct {
    width: u32,
    height: u32,
    bpp: u16,
    refresh_rate: u16,
    format: PixelFormat,
    _reserved: [7]u8 = [_]u8{0} ** 7,
};

// =============================================================================
// Dirty Rectangle (untuk partial flush)
// =============================================================================

pub const Rect = extern struct {
    x: i32,
    y: i32,
    width: u32,
    height: u32,

    pub fn init(x: i32, y: i32, w: u32, h: u32) Rect {
        return .{ .x = x, .y = y, .width = w, .height = h };
    }

    pub fn isEmpty(self: Rect) bool {
        return self.width == 0 or self.height == 0;
    }

    /// Full screen (semua 0 = flush seluruh layar)
    pub fn fullScreen() Rect {
        return .{ .x = 0, .y = 0, .width = 0, .height = 0 };
    }

    /// Intersect two rectangles
    pub fn intersect(self: Rect, other: Rect) Rect {
        const x1 = @max(self.x, other.x);
        const y1 = @max(self.y, other.y);
        const x2 = @min(self.x + @as(i32, @intCast(self.width)), other.x + @as(i32, @intCast(other.width)));
        const y2 = @min(self.y + @as(i32, @intCast(self.height)), other.y + @as(i32, @intCast(other.height)));

        if (x2 <= x1 or y2 <= y1) {
            return .{ .x = 0, .y = 0, .width = 0, .height = 0 };
        }

        return .{
            .x = x1,
            .y = y1,
            .width = @intCast(x2 - x1),
            .height = @intCast(y2 - y1),
        };
    }
};

// =============================================================================
// Screen Orientation (Mobile)
// =============================================================================

pub const Orientation = enum(u8) {
    Portrait = 0,
    Landscape = 1,
    PortraitFlipped = 2,
    LandscapeFlipped = 3,
};

// =============================================================================
// Color Helper
// =============================================================================

pub const Color = packed struct {
    b: u8,
    g: u8,
    r: u8,
    a: u8,

    pub fn rgba(r: u8, g: u8, b: u8, a: u8) Color {
        return .{ .r = r, .g = g, .b = b, .a = a };
    }

    pub fn rgb(r: u8, g: u8, b: u8) Color {
        return rgba(r, g, b, 255);
    }

    pub fn fromU32(val: u32) Color {
        return @bitCast(val);
    }

    pub fn toU32(self: Color) u32 {
        return @bitCast(self);
    }

    // Basic colors
    pub const BLACK = rgb(0, 0, 0);
    pub const WHITE = rgb(255, 255, 255);
    pub const RED = rgb(255, 0, 0);
    pub const GREEN = rgb(0, 255, 0);
    pub const BLUE = rgb(0, 0, 255);
    pub const YELLOW = rgb(255, 255, 0);
    pub const CYAN = rgb(0, 255, 255);
    pub const MAGENTA = rgb(255, 0, 255);
    pub const TRANSPARENT = rgba(0, 0, 0, 0);

    // Zamrud theme
    pub const ZAMRUD_PRIMARY = rgb(0, 168, 107); // Emerald
    pub const ZAMRUD_SECONDARY = rgb(0, 128, 128); // Teal
    pub const ZAMRUD_ACCENT = rgb(255, 215, 0); // Gold
    pub const ZAMRUD_BG = rgb(15, 25, 35);
    pub const ZAMRUD_SURFACE = rgb(25, 40, 55);
    pub const ZAMRUD_TEXT = rgb(240, 240, 240);
};
