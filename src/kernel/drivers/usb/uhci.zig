//! Zamrud OS - UHCI (Universal Host Controller Interface) Driver
//! B2.11: USB 1.x support with full control transfer implementation
//!
//! UHCI Architecture:
//!   Frame List (1024 entries, 4KB aligned)
//!     └── Queue Heads (QH)
//!           └── Transfer Descriptors (TD)

const serial = @import("../../drivers/serial/serial.zig");
const pmm = @import("../../mm/pmm.zig");
const timer = @import("../../drivers/timer/timer.zig");
const cpu = @import("../../core/cpu.zig");
const usb = @import("usb.zig");

// =============================================================================
// UHCI Register Offsets (I/O ports)
// =============================================================================

const UHCI_USBCMD: u16 = 0x00;
const UHCI_USBSTS: u16 = 0x02;
const UHCI_USBINTR: u16 = 0x04;
const UHCI_FRNUM: u16 = 0x06;
const UHCI_FRBASEADD: u16 = 0x08;
const UHCI_SOFMOD: u16 = 0x0C;
const UHCI_PORTSC1: u16 = 0x10;
const UHCI_PORTSC2: u16 = 0x12;

// USBCMD bits
const USBCMD_RS: u16 = 1 << 0;
const USBCMD_HCRESET: u16 = 1 << 1;
const USBCMD_GRESET: u16 = 1 << 2;
const USBCMD_EGSM: u16 = 1 << 3;
const USBCMD_FGR: u16 = 1 << 4;
const USBCMD_SWDBG: u16 = 1 << 5;
const USBCMD_CF: u16 = 1 << 6;
const USBCMD_MAXP: u16 = 1 << 7;

// USBSTS bits
const USBSTS_USBINT: u16 = 1 << 0;
const USBSTS_ERROR: u16 = 1 << 1;
const USBSTS_RD: u16 = 1 << 2;
const USBSTS_HSE: u16 = 1 << 3;
const USBSTS_HCPE: u16 = 1 << 4;
const USBSTS_HCH: u16 = 1 << 5;

// PORTSC bits
const PORTSC_CCS: u16 = 1 << 0;
const PORTSC_CSC: u16 = 1 << 1;
const PORTSC_PE: u16 = 1 << 2;
const PORTSC_PEC: u16 = 1 << 3;
const PORTSC_DPLUS: u16 = 1 << 4;
const PORTSC_DMINUS: u16 = 1 << 5;
const PORTSC_RD: u16 = 1 << 6;
const PORTSC_LSDA: u16 = 1 << 8;
const PORTSC_PR: u16 = 1 << 9;
const PORTSC_SUSP: u16 = 1 << 12;

// =============================================================================
// UHCI Data Structures (must be physically contiguous, aligned)
// =============================================================================

/// Transfer Descriptor (TD) - 32 bytes, 16-byte aligned
pub const TransferDescriptor = extern struct {
    link_ptr: u32 align(1),
    control_status: u32 align(1),
    token: u32 align(1),
    buffer_ptr: u32 align(1),
    // Software fields (not used by hardware)
    sw_next: u32 align(1),
    sw_buffer_virt: u32 align(1),
    sw_reserved: [2]u32 align(1),

    pub const LINK_TERMINATE: u32 = 1 << 0;
    pub const LINK_QH: u32 = 1 << 1;
    pub const LINK_DEPTH: u32 = 1 << 2;

    // Control/Status bits
    pub const STATUS_ACTIVE: u32 = 1 << 23;
    pub const STATUS_STALLED: u32 = 1 << 22;
    pub const STATUS_DATA_BUFFER_ERR: u32 = 1 << 21;
    pub const STATUS_BABBLE: u32 = 1 << 20;
    pub const STATUS_NAK: u32 = 1 << 19;
    pub const STATUS_CRC_TIMEOUT: u32 = 1 << 18;
    pub const STATUS_BITSTUFF: u32 = 1 << 17;
    pub const STATUS_LOW_SPEED: u32 = 1 << 26;
    pub const STATUS_IOS: u32 = 1 << 25;
    pub const STATUS_IOC: u32 = 1 << 24;
    pub const STATUS_SPD: u32 = 1 << 29;

    pub const STATUS_ERROR_MASK: u32 = STATUS_STALLED | STATUS_DATA_BUFFER_ERR |
        STATUS_BABBLE | STATUS_CRC_TIMEOUT | STATUS_BITSTUFF;

    // PID values
    pub const PID_SETUP: u8 = 0x2D;
    pub const PID_IN: u8 = 0x69;
    pub const PID_OUT: u8 = 0xE1;

    pub fn init(self: *TransferDescriptor) void {
        self.link_ptr = LINK_TERMINATE;
        self.control_status = 0;
        self.token = 0;
        self.buffer_ptr = 0;
        self.sw_next = 0;
        self.sw_buffer_virt = 0;
        self.sw_reserved = [_]u32{0} ** 2;
    }

    pub fn setup(self: *TransferDescriptor, pid: u8, addr: u7, ep: u4, toggle: u1, max_len: u11, low_speed: bool, ioc: bool, buffer_phys: u32) void {
        // Control/Status: Active, 3 retries
        var cs: u32 = STATUS_ACTIVE | (3 << 27); // C_ERR = 3

        // MaxLen field is (actual_length - 1), stored in bits 21:11 of control_status
        // For 0 bytes, use 0x7FF (special case)
        const maxlen_field: u32 = if (max_len == 0) 0x7FF else @as(u32, max_len - 1);

        if (low_speed) cs |= STATUS_LOW_SPEED;
        if (ioc) cs |= STATUS_IOC;

        self.control_status = cs;

        // Token: PID, device address, endpoint, data toggle, max length
        var tok: u32 = @as(u32, pid);
        tok |= @as(u32, addr) << 8;
        tok |= @as(u32, ep) << 15;
        tok |= @as(u32, toggle) << 19;
        tok |= (maxlen_field << 21) & 0xFFE00000;

        self.token = tok;
        self.buffer_ptr = buffer_phys;
    }

    pub fn isComplete(self: *const TransferDescriptor) bool {
        return (self.control_status & STATUS_ACTIVE) == 0;
    }

    pub fn hasError(self: *const TransferDescriptor) bool {
        return (self.control_status & STATUS_ERROR_MASK) != 0;
    }

    pub fn isStalled(self: *const TransferDescriptor) bool {
        return (self.control_status & STATUS_STALLED) != 0;
    }

    pub fn getActualLength(self: *const TransferDescriptor) u11 {
        // ActLen is in bits 10:0, returns (actual + 1), 0x7FF means 0 bytes
        const actlen = self.control_status & 0x7FF;
        if (actlen == 0x7FF) return 0;
        return @truncate(actlen + 1);
    }
};

/// Queue Head (QH) - 16 bytes, 16-byte aligned
pub const QueueHead = extern struct {
    head_link_ptr: u32 align(1),
    element_link_ptr: u32 align(1),
    sw_prev: u32 align(1),
    sw_next: u32 align(1),

    pub const LINK_TERMINATE: u32 = 1 << 0;
    pub const LINK_QH: u32 = 1 << 1;

    pub fn init(self: *QueueHead) void {
        self.head_link_ptr = LINK_TERMINATE;
        self.element_link_ptr = LINK_TERMINATE;
        self.sw_prev = 0;
        self.sw_next = 0;
    }

    pub fn linkTd(self: *QueueHead, td_phys: u32) void {
        self.element_link_ptr = td_phys & 0xFFFFFFF0;
    }

    pub fn linkNextQh(self: *QueueHead, qh_phys: u32) void {
        self.head_link_ptr = (qh_phys & 0xFFFFFFF0) | LINK_QH;
    }
};

// =============================================================================
// UHCI Controller State
// =============================================================================

const MAX_UHCI_CONTROLLERS: usize = 4;
const MAX_TDS_PER_TRANSFER: usize = 16;
const TD_POOL_SIZE: usize = 64;
const QH_POOL_SIZE: usize = 16;
const DATA_BUFFER_SIZE: usize = 4096;

const UhciController = struct {
    io_base: u16 = 0,
    irq: u8 = 0,

    // Frame list
    frame_list_phys: u64 = 0,
    frame_list_virt: u64 = 0,

    // TD pool
    td_pool_phys: u64 = 0,
    td_pool_virt: u64 = 0,
    td_used: [TD_POOL_SIZE]bool = [_]bool{false} ** TD_POOL_SIZE,

    // QH pool
    qh_pool_phys: u64 = 0,
    qh_pool_virt: u64 = 0,
    qh_used: [QH_POOL_SIZE]bool = [_]bool{false} ** QH_POOL_SIZE,

    // Data buffer for control transfers
    data_buffer_phys: u64 = 0,
    data_buffer_virt: u64 = 0,

    // Async QH (head of schedule)
    async_qh_phys: u64 = 0,

    // Stats
    transfers_completed: u32 = 0,
    transfers_failed: u32 = 0,
    port_status: [2]u16 = [_]u16{0} ** 2,

    initialized: bool = false,
    running: bool = false,
};

var uhci_controllers: [MAX_UHCI_CONTROLLERS]UhciController = [_]UhciController{.{}} ** MAX_UHCI_CONTROLLERS;
var uhci_count: usize = 0;
var hhdm_offset: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init(ctrl: *usb.UsbController) bool {
    if (uhci_count >= MAX_UHCI_CONTROLLERS) return false;
    if (ctrl.controller_type != .uhci) return false;

    hhdm_offset = pmm.getHhdmOffset();

    const uhci_ctrl = &uhci_controllers[uhci_count];
    uhci_ctrl.io_base = @truncate(ctrl.base_addr);
    uhci_ctrl.irq = ctrl.irq;

    serial.writeString("[UHCI] Initializing controller at I/O 0x");
    printHex16(uhci_ctrl.io_base);
    serial.writeString("\n");

    // Step 1: Global Reset
    outw(uhci_ctrl.io_base + UHCI_USBCMD, USBCMD_GRESET);
    timer.sleep(50);
    outw(uhci_ctrl.io_base + UHCI_USBCMD, 0);
    timer.sleep(10);

    // Step 2: Host Controller Reset
    outw(uhci_ctrl.io_base + UHCI_USBCMD, USBCMD_HCRESET);

    var timeout: u32 = 100;
    while (timeout > 0) : (timeout -= 1) {
        if ((inw(uhci_ctrl.io_base + UHCI_USBCMD) & USBCMD_HCRESET) == 0) break;
        timer.sleep(1);
    }

    if (timeout == 0) {
        serial.writeString("[UHCI] Reset timeout\n");
        return false;
    }

    // Step 3: Clear status
    outw(uhci_ctrl.io_base + UHCI_USBSTS, 0xFFFF);

    // Step 4: Allocate Frame List (4KB)
    uhci_ctrl.frame_list_phys = pmm.allocPage() orelse {
        serial.writeString("[UHCI] Failed to allocate frame list\n");
        return false;
    };
    uhci_ctrl.frame_list_virt = hhdm_offset + uhci_ctrl.frame_list_phys;

    // Step 5: Allocate TD pool (2 pages = 8KB, fits 256 TDs)
    uhci_ctrl.td_pool_phys = pmm.allocPages(2) orelse {
        pmm.freePage(uhci_ctrl.frame_list_phys);
        return false;
    };
    uhci_ctrl.td_pool_virt = hhdm_offset + uhci_ctrl.td_pool_phys;

    // Step 6: Allocate QH pool (1 page)
    uhci_ctrl.qh_pool_phys = pmm.allocPage() orelse {
        pmm.freePage(uhci_ctrl.frame_list_phys);
        pmm.freePages(uhci_ctrl.td_pool_phys, 2);
        return false;
    };
    uhci_ctrl.qh_pool_virt = hhdm_offset + uhci_ctrl.qh_pool_phys;

    // Step 7: Allocate data buffer (1 page)
    uhci_ctrl.data_buffer_phys = pmm.allocPage() orelse {
        pmm.freePage(uhci_ctrl.frame_list_phys);
        pmm.freePages(uhci_ctrl.td_pool_phys, 2);
        pmm.freePage(uhci_ctrl.qh_pool_phys);
        return false;
    };
    uhci_ctrl.data_buffer_virt = hhdm_offset + uhci_ctrl.data_buffer_phys;

    // Clear all pools
    @memset(@as([*]u8, @ptrFromInt(uhci_ctrl.td_pool_virt))[0..8192], 0);
    @memset(@as([*]u8, @ptrFromInt(uhci_ctrl.qh_pool_virt))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(uhci_ctrl.data_buffer_virt))[0..4096], 0);

    // Step 8: Setup async QH (first QH in pool)
    uhci_ctrl.qh_used[0] = true;
    const async_qh = getQh(uhci_ctrl, 0);
    async_qh.init();
    async_qh.head_link_ptr = QueueHead.LINK_TERMINATE;
    async_qh.element_link_ptr = QueueHead.LINK_TERMINATE;
    uhci_ctrl.async_qh_phys = getQhPhys(uhci_ctrl, 0);

    // Step 9: Initialize frame list - point all frames to async QH
    const frame_list: [*]volatile u32 = @ptrFromInt(uhci_ctrl.frame_list_virt);
    for (0..1024) |i| {
        frame_list[i] = @as(u32, @truncate(uhci_ctrl.async_qh_phys)) | QueueHead.LINK_QH;
    }

    // Step 10: Set Frame List Base Address
    outl(uhci_ctrl.io_base + UHCI_FRBASEADD, @truncate(uhci_ctrl.frame_list_phys));

    // Step 11: Set frame number to 0
    outw(uhci_ctrl.io_base + UHCI_FRNUM, 0);

    // Step 12: Set SOF timing
    outb(uhci_ctrl.io_base + UHCI_SOFMOD, 64);

    // Step 13: Disable interrupts (polling mode)
    outw(uhci_ctrl.io_base + UHCI_USBINTR, 0);

    // Step 14: Start controller
    outw(uhci_ctrl.io_base + UHCI_USBCMD, USBCMD_RS | USBCMD_CF | USBCMD_MAXP);

    // Verify running
    timer.sleep(10);
    const status = inw(uhci_ctrl.io_base + UHCI_USBSTS);
    if ((status & USBSTS_HCH) != 0) {
        serial.writeString("[UHCI] Controller still halted\n");
        return false;
    }

    uhci_ctrl.initialized = true;
    uhci_ctrl.running = true;
    uhci_count += 1;

    serial.writeString("[UHCI] Controller initialized and running\n");

    // Probe ports
    probePort(uhci_ctrl, 0);
    probePort(uhci_ctrl, 1);

    return true;
}

// =============================================================================
// Pool Management
// =============================================================================

fn allocTd(uhci_ctrl: *UhciController) ?usize {
    for (0..TD_POOL_SIZE) |i| {
        if (!uhci_ctrl.td_used[i]) {
            uhci_ctrl.td_used[i] = true;
            const td = getTd(uhci_ctrl, i);
            td.init();
            return i;
        }
    }
    return null;
}

fn freeTd(uhci_ctrl: *UhciController, index: usize) void {
    if (index < TD_POOL_SIZE) {
        uhci_ctrl.td_used[index] = false;
    }
}

fn getTd(uhci_ctrl: *UhciController, index: usize) *TransferDescriptor {
    const addr = uhci_ctrl.td_pool_virt + index * @sizeOf(TransferDescriptor);
    return @ptrFromInt(addr);
}

fn getTdPhys(uhci_ctrl: *UhciController, index: usize) u32 {
    return @truncate(uhci_ctrl.td_pool_phys + index * @sizeOf(TransferDescriptor));
}

fn allocQh(uhci_ctrl: *UhciController) ?usize {
    // Skip index 0 (async QH)
    for (1..QH_POOL_SIZE) |i| {
        if (!uhci_ctrl.qh_used[i]) {
            uhci_ctrl.qh_used[i] = true;
            const qh = getQh(uhci_ctrl, i);
            qh.init();
            return i;
        }
    }
    return null;
}

fn freeQh(uhci_ctrl: *UhciController, index: usize) void {
    if (index > 0 and index < QH_POOL_SIZE) {
        uhci_ctrl.qh_used[index] = false;
    }
}

fn getQh(uhci_ctrl: *UhciController, index: usize) *QueueHead {
    const addr = uhci_ctrl.qh_pool_virt + index * @sizeOf(QueueHead);
    return @ptrFromInt(addr);
}

fn getQhPhys(uhci_ctrl: *UhciController, index: usize) u32 {
    return @truncate(uhci_ctrl.qh_pool_phys + index * @sizeOf(QueueHead));
}

// =============================================================================
// Port Management
// =============================================================================

fn probePort(uhci_ctrl: *UhciController, port: u8) void {
    const port_reg: u16 = if (port == 0) UHCI_PORTSC1 else UHCI_PORTSC2;
    var portsc = inw(uhci_ctrl.io_base + port_reg);

    // Save port status
    uhci_ctrl.port_status[port] = portsc;

    serial.writeString("[UHCI] Port ");
    serial.writeChar('1' + port);
    serial.writeString(": status=0x");
    printHex16(portsc);
    serial.writeString(" ");

    if ((portsc & PORTSC_CCS) == 0) {
        serial.writeString("No device\n");
        return;
    }

    // Device connected
    const low_speed = (portsc & PORTSC_LSDA) != 0;
    serial.writeString(if (low_speed) "Low-speed" else "Full-speed");
    serial.writeString(" device connected\n");

    // Reset port
    portsc = inw(uhci_ctrl.io_base + port_reg);
    portsc |= PORTSC_PR;
    outw(uhci_ctrl.io_base + port_reg, portsc);
    timer.sleep(50);

    portsc = inw(uhci_ctrl.io_base + port_reg);
    portsc &= ~PORTSC_PR;
    outw(uhci_ctrl.io_base + port_reg, portsc);
    timer.sleep(10);

    // Clear status change bits (write-1-to-clear)
    portsc = inw(uhci_ctrl.io_base + port_reg);
    portsc |= PORTSC_CSC | PORTSC_PEC;
    outw(uhci_ctrl.io_base + port_reg, portsc);

    // Enable port
    portsc = inw(uhci_ctrl.io_base + port_reg);
    portsc |= PORTSC_PE;
    outw(uhci_ctrl.io_base + port_reg, portsc);
    timer.sleep(10);

    portsc = inw(uhci_ctrl.io_base + port_reg);
    uhci_ctrl.port_status[port] = portsc;

    if ((portsc & PORTSC_PE) != 0) {
        serial.writeString("[UHCI] Port ");
        serial.writeChar('1' + port);
        serial.writeString(" enabled\n");

        // Enumerate device
        if (enumerateDevice(uhci_ctrl, port, low_speed)) {
            serial.writeString("[UHCI] Device enumerated successfully\n");
        } else {
            serial.writeString("[UHCI] Device enumeration failed\n");
        }
    } else {
        serial.writeString("[UHCI] Port enable failed\n");
    }
}

// =============================================================================
// Control Transfer Implementation
// =============================================================================

pub const TransferError = error{
    NoController,
    NotInitialized,
    NoTdAvailable,
    NoQhAvailable,
    Timeout,
    Stalled,
    DataBufferError,
    Babble,
    CrcTimeout,
    BitStuff,
    UnknownError,
};

/// Execute a control transfer
pub fn controlTransfer(
    uhci_ctrl: *UhciController,
    addr: u7,
    ep: u4,
    low_speed: bool,
    setup_packet: *const usb.SetupPacket,
    data: ?[]u8,
    direction_in: bool,
) TransferError!u16 {
    if (!uhci_ctrl.initialized) return TransferError.NotInitialized;

    usb.incrementTransfers();

    // Allocate QH for this transfer
    const qh_idx = allocQh(uhci_ctrl) orelse return TransferError.NoQhAvailable;
    defer freeQh(uhci_ctrl, qh_idx);

    const qh = getQh(uhci_ctrl, qh_idx);
    const qh_phys = getQhPhys(uhci_ctrl, qh_idx);

    // We need at least: 1 Setup TD, 0+ Data TDs, 1 Status TD
    var td_indices: [MAX_TDS_PER_TRANSFER]usize = undefined;
    var td_count: usize = 0;

    // Copy setup packet to data buffer
    const setup_buf_phys: u32 = @truncate(uhci_ctrl.data_buffer_phys);
    const setup_buf: [*]u8 = @ptrFromInt(uhci_ctrl.data_buffer_virt);
    const setup_bytes = @as([*]const u8, @ptrCast(setup_packet));
    @memcpy(setup_buf[0..8], setup_bytes[0..8]);

    // --- Setup TD ---
    const setup_td_idx = allocTd(uhci_ctrl) orelse return TransferError.NoTdAvailable;
    td_indices[td_count] = setup_td_idx;
    td_count += 1;

    const setup_td = getTd(uhci_ctrl, setup_td_idx);
    setup_td.setup(
        TransferDescriptor.PID_SETUP,
        addr,
        ep,
        0, // toggle = 0 for SETUP
        8, // SETUP packet is always 8 bytes
        low_speed,
        false, // no IOC yet
        setup_buf_phys,
    );

    // --- Data TDs ---
    var data_toggle: u1 = 1; // First data packet uses DATA1
    var data_offset: usize = 0;
    const data_len = if (data) |d| d.len else 0;
    const max_packet: usize = if (low_speed) 8 else 64;

    // Data buffer starts after setup packet (offset 64)
    const data_buf_phys: u32 = @truncate(uhci_ctrl.data_buffer_phys + 64);
    const data_buf: [*]u8 = @ptrFromInt(uhci_ctrl.data_buffer_virt + 64);

    // For OUT transfers, copy data to buffer
    if (!direction_in and data != null) {
        @memcpy(data_buf[0..data_len], data.?);
    }

    while (data_offset < data_len) {
        const chunk_size = @min(max_packet, data_len - data_offset);

        const data_td_idx = allocTd(uhci_ctrl) orelse {
            // Free already allocated TDs
            for (td_indices[0..td_count]) |idx| freeTd(uhci_ctrl, idx);
            return TransferError.NoTdAvailable;
        };
        td_indices[td_count] = data_td_idx;
        td_count += 1;

        const data_td = getTd(uhci_ctrl, data_td_idx);
        data_td.setup(
            if (direction_in) TransferDescriptor.PID_IN else TransferDescriptor.PID_OUT,
            addr,
            ep,
            data_toggle,
            @truncate(chunk_size),
            low_speed,
            false,
            data_buf_phys + @as(u32, @truncate(data_offset)),
        );

        data_toggle ^= 1;
        data_offset += chunk_size;
    }

    // --- Status TD ---
    const status_td_idx = allocTd(uhci_ctrl) orelse {
        for (td_indices[0..td_count]) |idx| freeTd(uhci_ctrl, idx);
        return TransferError.NoTdAvailable;
    };
    td_indices[td_count] = status_td_idx;
    td_count += 1;

    const status_td = getTd(uhci_ctrl, status_td_idx);
    // Status stage: opposite direction of data, DATA1, zero length
    status_td.setup(
        if (direction_in or data_len == 0) TransferDescriptor.PID_OUT else TransferDescriptor.PID_IN,
        addr,
        ep,
        1, // DATA1 for status
        0, // zero length
        low_speed,
        true, // IOC on status TD
        0, // no buffer
    );

    // --- Link TDs together ---
    for (0..td_count - 1) |i| {
        const td = getTd(uhci_ctrl, td_indices[i]);
        td.link_ptr = getTdPhys(uhci_ctrl, td_indices[i + 1]) | TransferDescriptor.LINK_DEPTH;
    }
    // Last TD terminates
    getTd(uhci_ctrl, td_indices[td_count - 1]).link_ptr = TransferDescriptor.LINK_TERMINATE;

    // --- Link QH to first TD ---
    qh.linkTd(getTdPhys(uhci_ctrl, td_indices[0]));

    // --- Insert QH into schedule ---
    const async_qh = getQh(uhci_ctrl, 0);
    qh.head_link_ptr = async_qh.head_link_ptr;
    async_qh.head_link_ptr = qh_phys | QueueHead.LINK_QH;

    // Memory barrier
    asm volatile ("mfence" ::: .{ .memory = true });

    // --- Wait for completion ---
    var timeout_ms: u32 = 1000; // 1 second timeout
    while (timeout_ms > 0) : (timeout_ms -= 1) {
        // Check if all TDs completed
        var all_done = true;
        for (td_indices[0..td_count]) |idx| {
            const td = getTd(uhci_ctrl, idx);
            if (!td.isComplete()) {
                all_done = false;
                break;
            }
        }

        if (all_done) break;
        timer.sleep(1);
    }

    // --- Remove QH from schedule ---
    async_qh.head_link_ptr = qh.head_link_ptr;
    asm volatile ("mfence" ::: .{ .memory = true });

    // Check for errors
    var total_transferred: u16 = 0;
    var had_error = false;
    var error_type: TransferError = TransferError.UnknownError;

    for (td_indices[0..td_count]) |idx| {
        const td = getTd(uhci_ctrl, idx);

        if (!td.isComplete()) {
            had_error = true;
            error_type = TransferError.Timeout;
            break;
        }

        if (td.hasError()) {
            had_error = true;
            if (td.isStalled()) {
                error_type = TransferError.Stalled;
            } else if ((td.control_status & TransferDescriptor.STATUS_DATA_BUFFER_ERR) != 0) {
                error_type = TransferError.DataBufferError;
            } else if ((td.control_status & TransferDescriptor.STATUS_BABBLE) != 0) {
                error_type = TransferError.Babble;
            } else if ((td.control_status & TransferDescriptor.STATUS_CRC_TIMEOUT) != 0) {
                error_type = TransferError.CrcTimeout;
            } else {
                error_type = TransferError.BitStuff;
            }
            break;
        }

        // Count transferred bytes (skip setup TD, count data TDs)
        if (idx != td_indices[0] and idx != td_indices[td_count - 1]) {
            total_transferred += td.getActualLength();
        }
    }

    // Free TDs
    for (td_indices[0..td_count]) |idx| {
        freeTd(uhci_ctrl, idx);
    }

    if (had_error) {
        uhci_ctrl.transfers_failed += 1;
        return error_type;
    }

    uhci_ctrl.transfers_completed += 1;

    // For IN transfers, copy data back
    if (direction_in and data != null and total_transferred > 0) {
        const copy_len = @min(data.?.len, total_transferred);
        @memcpy(data.?[0..copy_len], data_buf[0..copy_len]);
    }

    return total_transferred;
}

// =============================================================================
// Device Enumeration
// =============================================================================

fn enumerateDevice(uhci_ctrl: *UhciController, port: u8, low_speed: bool) bool {
    // Allocate USB device
    const dev = usb.allocateDevice() orelse {
        serial.writeString("[UHCI] Failed to allocate device\n");
        return false;
    };

    dev.controller_type = .uhci;
    dev.controller_index = @truncate(uhci_count - 1);
    dev.port = port;
    dev.speed = if (low_speed) usb.USB_SPEED_LOW else usb.USB_SPEED_FULL;
    dev.state = .default;
    dev.max_packet_size0 = if (low_speed) 8 else 8; // Start with 8, will be updated

    // Step 1: Get first 8 bytes of device descriptor (address 0)
    var desc_buf: [18]u8 = undefined;
    const get_desc_setup = usb.SetupPacket{
        .bmRequestType = usb.USB_REQ_DEVICE_TO_HOST | usb.USB_REQ_TYPE_STANDARD | usb.USB_REQ_RECIPIENT_DEVICE,
        .bRequest = usb.USB_REQ_GET_DESCRIPTOR,
        .wValue = (@as(u16, usb.USB_DESC_DEVICE) << 8) | 0,
        .wIndex = 0,
        .wLength = 8,
    };

    const result1 = controlTransfer(uhci_ctrl, 0, 0, low_speed, &get_desc_setup, desc_buf[0..8], true) catch |err| {
        serial.writeString("[UHCI] GET_DESCRIPTOR(8) failed: ");
        printError(err);
        usb.freeDevice(dev);
        return false;
    };

    if (result1 < 8) {
        serial.writeString("[UHCI] Short descriptor read\n");
        usb.freeDevice(dev);
        return false;
    }

    // Update max packet size from descriptor
    dev.max_packet_size0 = desc_buf[7];
    serial.writeString("[UHCI] MaxPacketSize0: ");
    printU8(dev.max_packet_size0);
    serial.writeString("\n");

    // Small delay before SET_ADDRESS
    timer.sleep(10);

    // Step 2: Set device address
    const new_addr: u7 = @truncate(dev.address & 0x7F);
    const set_addr_setup = usb.SetupPacket{
        .bmRequestType = usb.USB_REQ_HOST_TO_DEVICE | usb.USB_REQ_TYPE_STANDARD | usb.USB_REQ_RECIPIENT_DEVICE,
        .bRequest = usb.USB_REQ_SET_ADDRESS,
        .wValue = new_addr,
        .wIndex = 0,
        .wLength = 0,
    };

    _ = controlTransfer(uhci_ctrl, 0, 0, low_speed, &set_addr_setup, null, false) catch |err| {
        serial.writeString("[UHCI] SET_ADDRESS failed: ");
        printError(err);
        usb.freeDevice(dev);
        return false;
    };

    // Wait for device to process address
    timer.sleep(20);

    dev.state = .addressed;
    serial.writeString("[UHCI] Device address set to ");
    printU8(new_addr);
    serial.writeString("\n");

    // Step 3: Get full device descriptor
    const get_full_desc_setup = usb.SetupPacket{
        .bmRequestType = usb.USB_REQ_DEVICE_TO_HOST | usb.USB_REQ_TYPE_STANDARD | usb.USB_REQ_RECIPIENT_DEVICE,
        .bRequest = usb.USB_REQ_GET_DESCRIPTOR,
        .wValue = (@as(u16, usb.USB_DESC_DEVICE) << 8) | 0,
        .wIndex = 0,
        .wLength = 18,
    };

    const result3 = controlTransfer(uhci_ctrl, new_addr, 0, low_speed, &get_full_desc_setup, desc_buf[0..18], true) catch |err| {
        serial.writeString("[UHCI] GET_DESCRIPTOR(18) failed: ");
        printError(err);
        // Device is still valid, just can't read full descriptor
        return true;
    };

    if (result3 >= 18) {
        // Parse device descriptor
        dev.vendor_id = @as(u16, desc_buf[8]) | (@as(u16, desc_buf[9]) << 8);
        dev.product_id = @as(u16, desc_buf[10]) | (@as(u16, desc_buf[11]) << 8);
        dev.device_class = desc_buf[4];
        dev.device_subclass = desc_buf[5];
        dev.device_protocol = desc_buf[6];

        serial.writeString("[UHCI] VID:PID = ");
        printHex16(dev.vendor_id);
        serial.writeString(":");
        printHex16(dev.product_id);
        serial.writeString(", Class: ");
        printU8(dev.device_class);
        serial.writeString("\n");
    }

    // Step 4: Get configuration descriptor (just header first)
    var config_buf: [64]u8 = undefined;
    const get_config_setup = usb.SetupPacket{
        .bmRequestType = usb.USB_REQ_DEVICE_TO_HOST | usb.USB_REQ_TYPE_STANDARD | usb.USB_REQ_RECIPIENT_DEVICE,
        .bRequest = usb.USB_REQ_GET_DESCRIPTOR,
        .wValue = (@as(u16, usb.USB_DESC_CONFIGURATION) << 8) | 0,
        .wIndex = 0,
        .wLength = 64,
    };

    const result4 = controlTransfer(uhci_ctrl, new_addr, 0, low_speed, &get_config_setup, config_buf[0..64], true) catch {
        // Configuration read failed, but device is still usable
        return true;
    };

    if (result4 >= 9) {
        const total_len = @as(u16, config_buf[2]) | (@as(u16, config_buf[3]) << 8);
        const num_interfaces = config_buf[4];
        serial.writeString("[UHCI] Config: ");
        printU16(total_len);
        serial.writeString(" bytes, ");
        printU8(num_interfaces);
        serial.writeString(" interface(s)\n");

        // Parse interfaces
        parseConfiguration(dev, config_buf[0..@min(64, result4)]);
    }

    // Step 5: Set configuration (config value 1)
    const set_config_setup = usb.SetupPacket{
        .bmRequestType = usb.USB_REQ_HOST_TO_DEVICE | usb.USB_REQ_TYPE_STANDARD | usb.USB_REQ_RECIPIENT_DEVICE,
        .bRequest = usb.USB_REQ_SET_CONFIGURATION,
        .wValue = 1,
        .wIndex = 0,
        .wLength = 0,
    };

    _ = controlTransfer(uhci_ctrl, new_addr, 0, low_speed, &set_config_setup, null, false) catch {
        // Set config failed
        return true;
    };

    dev.state = .configured;
    dev.current_config = 1;
    serial.writeString("[UHCI] Device configured\n");

    return true;
}

fn parseConfiguration(dev: *usb.UsbDevice, data: []const u8) void {
    var offset: usize = 0;

    while (offset + 2 <= data.len) {
        const length = data[offset];
        const desc_type = data[offset + 1];

        if (length < 2 or offset + length > data.len) break;

        switch (desc_type) {
            usb.USB_DESC_INTERFACE => {
                if (length >= 9 and dev.num_interfaces < usb.MAX_INTERFACES) {
                    const iface = &dev.interfaces[dev.num_interfaces];
                    iface.number = data[offset + 2];
                    iface.alt_setting = data[offset + 3];
                    iface.num_endpoints = data[offset + 4];
                    iface.class = data[offset + 5];
                    iface.subclass = data[offset + 6];
                    iface.protocol = data[offset + 7];
                    iface.active = true;
                    dev.num_interfaces += 1;

                    serial.writeString("[UHCI]   Interface ");
                    printU8(iface.number);
                    serial.writeString(": class=");
                    printU8(iface.class);
                    serial.writeString(" sub=");
                    printU8(iface.subclass);
                    serial.writeString(" proto=");
                    printU8(iface.protocol);
                    serial.writeString("\n");
                }
            },
            usb.USB_DESC_ENDPOINT => {
                if (length >= 7 and dev.num_interfaces > 0) {
                    const iface = &dev.interfaces[dev.num_interfaces - 1];
                    const ep_count = blk: {
                        var cnt: u8 = 0;
                        for (iface.endpoints) |ep| {
                            if (ep.active) cnt += 1;
                        }
                        break :blk cnt;
                    };
                    if (ep_count < usb.MAX_ENDPOINTS) {
                        const ep = &iface.endpoints[ep_count];
                        ep.address = data[offset + 2];
                        ep.attributes = data[offset + 3];
                        ep.max_packet_size = @as(u16, data[offset + 4]) | (@as(u16, data[offset + 5]) << 8);
                        ep.interval = data[offset + 6];
                        ep.active = true;
                    }
                }
            },
            else => {},
        }

        offset += length;
    }
}

// =============================================================================
// Public Interface
// =============================================================================

pub fn isInitialized() bool {
    return uhci_count > 0 and uhci_controllers[0].initialized;
}

pub fn getControllerCount() usize {
    return uhci_count;
}

pub fn getController(index: usize) ?*UhciController {
    if (index >= uhci_count) return null;
    return &uhci_controllers[index];
}

pub fn getPortStatus(ctrl_index: usize, port: u8) u16 {
    if (ctrl_index >= uhci_count) return 0;
    if (port > 1) return 0;
    return uhci_controllers[ctrl_index].port_status[port];
}

pub fn getTransfersCompleted(ctrl_index: usize) u32 {
    if (ctrl_index >= uhci_count) return 0;
    return uhci_controllers[ctrl_index].transfers_completed;
}

pub fn getTransfersFailed(ctrl_index: usize) u32 {
    if (ctrl_index >= uhci_count) return 0;
    return uhci_controllers[ctrl_index].transfers_failed;
}

/// Execute control transfer on first UHCI controller
pub fn doControlTransfer(
    addr: u7,
    ep: u4,
    low_speed: bool,
    setup: *const usb.SetupPacket,
    data: ?[]u8,
    direction_in: bool,
) TransferError!u16 {
    if (uhci_count == 0) return TransferError.NoController;
    return controlTransfer(&uhci_controllers[0], addr, ep, low_speed, setup, data, direction_in);
}

// =============================================================================
// IRQ Handler
// =============================================================================

pub fn handleInterrupt() void {
    for (uhci_controllers[0..uhci_count]) |*uhci_ctrl| {
        if (!uhci_ctrl.initialized) continue;

        const status = inw(uhci_ctrl.io_base + UHCI_USBSTS);
        if (status == 0) continue;

        // Clear status bits
        outw(uhci_ctrl.io_base + UHCI_USBSTS, status);

        if ((status & USBSTS_ERROR) != 0) {
            serial.writeString("[UHCI] USB error\n");
        }
        if ((status & USBSTS_HSE) != 0) {
            serial.writeString("[UHCI] Host system error!\n");
        }
    }
}

// =============================================================================
// I/O Helpers
// =============================================================================

inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

inline fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

inline fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "N{dx}" (port),
    );
}

inline fn outw(port: u16, value: u16) void {
    asm volatile ("outw %[value], %[port]"
        :
        : [value] "{ax}" (value),
          [port] "N{dx}" (port),
    );
}

inline fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "N{dx}" (port),
    );
}

// =============================================================================
// Print Helpers
// =============================================================================

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

fn printU16(val: u16) void {
    if (val >= 10000) serial.writeChar('0' + @as(u8, @truncate(val / 10000)));
    if (val >= 1000) serial.writeChar('0' + @as(u8, @truncate((val / 1000) % 10)));
    if (val >= 100) serial.writeChar('0' + @as(u8, @truncate((val / 100) % 10)));
    if (val >= 10) serial.writeChar('0' + @as(u8, @truncate((val / 10) % 10)));
    serial.writeChar('0' + @as(u8, @truncate(val % 10)));
}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 12) & 0xF]);
    serial.writeChar(hex[(val >> 8) & 0xF]);
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printError(err: TransferError) void {
    const msg = switch (err) {
        TransferError.NoController => "No controller",
        TransferError.NotInitialized => "Not initialized",
        TransferError.NoTdAvailable => "No TD available",
        TransferError.NoQhAvailable => "No QH available",
        TransferError.Timeout => "Timeout",
        TransferError.Stalled => "Stalled",
        TransferError.DataBufferError => "Data buffer error",
        TransferError.Babble => "Babble",
        TransferError.CrcTimeout => "CRC/Timeout",
        TransferError.BitStuff => "Bitstuff error",
        TransferError.UnknownError => "Unknown error",
    };
    serial.writeString(msg);
    serial.writeString("\n");
}
