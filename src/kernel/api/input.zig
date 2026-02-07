//! Zamrud OS - Input API
//! Shared definitions untuk kernel <-> UI engine
//! Mendukung: Keyboard, Mouse, Touch (Mobile/Tablet)
//!
//! Copy file ini ke: zamrud-ui/api/input.zig

// =============================================================================
// Input Event Structure (Universal)
// =============================================================================

/// Universal input event - mendukung semua jenis input
pub const InputEvent = extern struct {
    /// Timestamp dalam milliseconds sejak boot
    timestamp: u64,

    /// Tipe event
    event_type: EventType,

    /// Device ID (untuk multi-touch, multi-mouse)
    device_id: u8,

    /// Reserved for alignment
    _pad: [2]u8 = [_]u8{0} ** 2,

    /// Event data (union berdasarkan event_type)
    data: EventData,
};

/// Event type enumeration
pub const EventType = enum(u8) {
    None = 0,

    // Keyboard events (1-9)
    KeyDown = 1,
    KeyUp = 2,
    KeyRepeat = 3,

    // Mouse events (10-19)
    MouseMove = 10,
    MouseButtonDown = 11,
    MouseButtonUp = 12,
    MouseScroll = 13,
    MouseEnter = 14, // Mouse masuk window
    MouseLeave = 15, // Mouse keluar window

    // Touch events (20-29)
    TouchStart = 20,
    TouchMove = 21,
    TouchEnd = 22,
    TouchCancel = 23,

    // Gesture events (30-39) - untuk UI engine
    GestureTap = 30,
    GestureDoubleTap = 31,
    GestureLongPress = 32,
    GestureSwipe = 33,
    GesturePinch = 34,
    GestureRotate = 35,

    // System events (40-49)
    FocusIn = 40,
    FocusOut = 41,
    Resize = 42,
};

/// Event data union
pub const EventData = extern union {
    key: KeyEventData,
    mouse: MouseEventData,
    touch: TouchEventData,
    gesture: GestureEventData,
    raw: [32]u8,
};

// =============================================================================
// Keyboard Event Data
// =============================================================================

pub const KeyEventData = extern struct {
    /// Scancode (hardware code)
    scancode: u16,

    /// Virtual key code (OS-independent)
    keycode: KeyCode,

    /// Modifier keys state
    modifiers: KeyModifiers,

    /// Unicode character (jika applicable, 0 jika tidak)
    unicode: u32,

    /// Reserved
    _reserved: [16]u8 = [_]u8{0} ** 16,
};

/// Keyboard modifier flags
pub const KeyModifiers = packed struct {
    shift: bool = false,
    ctrl: bool = false,
    alt: bool = false,
    super: bool = false, // Windows/Command key
    caps_lock: bool = false,
    num_lock: bool = false,
    scroll_lock: bool = false,
    _pad: u1 = 0,
};

/// Virtual key codes (cross-platform)
pub const KeyCode = enum(u16) {
    Unknown = 0,

    // Letters
    A = 4,
    B = 5,
    C = 6,
    D = 7,
    E = 8,
    F = 9,
    G = 10,
    H = 11,
    I = 12,
    J = 13,
    K = 14,
    L = 15,
    M = 16,
    N = 17,
    O = 18,
    P = 19,
    Q = 20,
    R = 21,
    S = 22,
    T = 23,
    U = 24,
    V = 25,
    W = 26,
    X = 27,
    Y = 28,
    Z = 29,

    // Numbers
    Num1 = 30,
    Num2 = 31,
    Num3 = 32,
    Num4 = 33,
    Num5 = 34,
    Num6 = 35,
    Num7 = 36,
    Num8 = 37,
    Num9 = 38,
    Num0 = 39,

    // Function keys
    F1 = 58,
    F2 = 59,
    F3 = 60,
    F4 = 61,
    F5 = 62,
    F6 = 63,
    F7 = 64,
    F8 = 65,
    F9 = 66,
    F10 = 67,
    F11 = 68,
    F12 = 69,

    // Special keys
    Enter = 40,
    Escape = 41,
    Backspace = 42,
    Tab = 43,
    Space = 44,
    Minus = 45,
    Equal = 46,
    LeftBracket = 47,
    RightBracket = 48,
    Backslash = 49,
    Semicolon = 51,
    Quote = 52,
    Grave = 53,
    Comma = 54,
    Period = 55,
    Slash = 56,
    CapsLock = 57,

    // Navigation
    Insert = 73,
    Home = 74,
    PageUp = 75,
    Delete = 76,
    End = 77,
    PageDown = 78,
    Right = 79,
    Left = 80,
    Down = 81,
    Up = 82,

    // Modifiers
    LeftCtrl = 224,
    LeftShift = 225,
    LeftAlt = 226,
    LeftSuper = 227,
    RightCtrl = 228,
    RightShift = 229,
    RightAlt = 230,
    RightSuper = 231,

    // Numpad
    NumLock = 83,
    NumDivide = 84,
    NumMultiply = 85,
    NumMinus = 86,
    NumPlus = 87,
    NumEnter = 88,
    Numpad1 = 89,
    Numpad2 = 90,
    Numpad3 = 91,
    Numpad4 = 92,
    Numpad5 = 93,
    Numpad6 = 94,
    Numpad7 = 95,
    Numpad8 = 96,
    Numpad9 = 97,
    Numpad0 = 98,
    NumpadDot = 99,

    _,
};

// =============================================================================
// Mouse Event Data
// =============================================================================

pub const MouseEventData = extern struct {
    /// Posisi X (absolute, dalam pixels)
    x: i32,

    /// Posisi Y (absolute, dalam pixels)
    y: i32,

    /// Delta X (relative movement)
    delta_x: i16,

    /// Delta Y (relative movement)
    delta_y: i16,

    /// Button yang di-click/release
    button: MouseButton,

    /// State semua button saat ini
    buttons: MouseButtonState,

    /// Scroll amount (vertical)
    scroll_y: i16,

    /// Scroll amount (horizontal)
    scroll_x: i16,

    /// Reserved
    _reserved: [12]u8 = [_]u8{0} ** 12,
};

/// Mouse button enum
pub const MouseButton = enum(u8) {
    None = 0,
    Left = 1,
    Right = 2,
    Middle = 3,
    Back = 4, // Side button
    Forward = 5, // Side button
    _,
};

/// Mouse button state (bitfield)
pub const MouseButtonState = packed struct {
    left: bool = false,
    right: bool = false,
    middle: bool = false,
    back: bool = false,
    forward: bool = false,
    _pad: u3 = 0,
};

// =============================================================================
// Touch Event Data (Mobile/Tablet Support)
// =============================================================================

pub const TouchEventData = extern struct {
    /// Touch point ID (untuk multi-touch tracking)
    touch_id: u8,

    /// Total jumlah touch points aktif
    touch_count: u8,

    /// Reserved
    _pad: [2]u8 = [_]u8{0} ** 2,

    /// Posisi X (dalam pixels)
    x: i32,

    /// Posisi Y (dalam pixels)
    y: i32,

    /// Pressure (0.0 - 1.0, normalized) - stored as u16 (0-65535)
    pressure: u16,

    /// Touch radius X (untuk finger size)
    radius_x: u16,

    /// Touch radius Y
    radius_y: u16,

    /// Rotation angle (untuk stylus)
    rotation: i16,

    /// Touch phase
    phase: TouchPhase,

    /// Reserved
    _reserved: [7]u8 = [_]u8{0} ** 7,
};

/// Touch phase
pub const TouchPhase = enum(u8) {
    Began = 0, // Finger touched
    Moved = 1, // Finger moved
    Stationary = 2, // Finger not moving
    Ended = 3, // Finger lifted
    Cancelled = 4, // Touch cancelled (e.g., palm rejection)
};

// =============================================================================
// Gesture Event Data
// =============================================================================

pub const GestureEventData = extern struct {
    /// Gesture type
    gesture_type: GestureType,

    /// Gesture state
    state: GestureState,

    /// Number of fingers/touches
    touch_count: u8,

    /// Reserved
    _pad: u8 = 0,

    /// Center X position
    center_x: i32,

    /// Center Y position
    center_y: i32,

    /// Gesture-specific values
    value1: f32, // Scale for pinch, velocity for swipe
    value2: f32, // Rotation angle, direction for swipe

    /// Reserved
    _reserved: [8]u8 = [_]u8{0} ** 8,
};

/// Gesture types
pub const GestureType = enum(u8) {
    None = 0,
    Tap = 1,
    DoubleTap = 2,
    LongPress = 3,
    Pan = 4,
    Swipe = 5,
    Pinch = 6,
    Rotate = 7,
};

/// Gesture state
pub const GestureState = enum(u8) {
    Possible = 0,
    Began = 1,
    Changed = 2,
    Ended = 3,
    Cancelled = 4,
    Failed = 5,
};

// =============================================================================
// Cursor Types (untuk UI engine set cursor)
// =============================================================================

pub const CursorType = enum(u8) {
    Default = 0,
    None = 1, // Hidden
    Arrow = 2,
    IBeam = 3, // Text cursor
    Crosshair = 4,
    Hand = 5, // Pointer/link
    ResizeNS = 6, // North-South resize
    ResizeEW = 7, // East-West resize
    ResizeNESW = 8, // Diagonal resize
    ResizeNWSE = 9, // Diagonal resize
    Move = 10, // Move/drag
    NotAllowed = 11, // Forbidden
    Wait = 12, // Loading
    Progress = 13, // Background loading
    Help = 14, // Help cursor
    Custom = 255, // Custom cursor image
};

// =============================================================================
// Input Mode Configuration
// =============================================================================

pub const InputMode = packed struct {
    /// Raw keyboard mode (no translation)
    raw_keyboard: bool = false,

    /// Enable key repeat
    key_repeat: bool = true,

    /// Enable mouse capture (relative mode)
    mouse_captured: bool = false,

    /// Show system cursor
    cursor_visible: bool = true,

    /// Enable touch input
    touch_enabled: bool = true,

    /// Enable gesture recognition
    gestures_enabled: bool = true,

    /// Enable multi-touch
    multitouch_enabled: bool = true,

    /// Reserved
    _pad: u1 = 0,
};

// =============================================================================
// Touch Capabilities (untuk query device)
// =============================================================================

pub const TouchCapabilities = extern struct {
    /// Device supports touch
    has_touch: bool,

    /// Maximum simultaneous touch points
    max_touch_points: u8,

    /// Supports pressure sensitivity
    has_pressure: bool,

    /// Supports touch radius/size
    has_radius: bool,

    /// Supports stylus
    has_stylus: bool,

    /// Reserved
    _reserved: [11]u8 = [_]u8{0} ** 11,
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if touch is supported
pub fn isTouchSupported(caps: TouchCapabilities) bool {
    return caps.has_touch and caps.max_touch_points > 0;
}

/// Convert pressure from u16 to float (0.0-1.0)
pub fn pressureToFloat(pressure: u16) f32 {
    return @as(f32, @floatFromInt(pressure)) / 65535.0;
}

/// Convert float pressure (0.0-1.0) to u16
pub fn floatToPressure(pressure: f32) u16 {
    const clamped = @max(0.0, @min(1.0, pressure));
    return @intFromFloat(clamped * 65535.0);
}

/// Create empty event
pub fn emptyEvent() InputEvent {
    return InputEvent{
        .timestamp = 0,
        .event_type = .None,
        .device_id = 0,
        .data = .{ .raw = [_]u8{0} ** 32 },
    };
}
