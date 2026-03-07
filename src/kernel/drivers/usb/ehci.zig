//! Zamrud OS - EHCI (Enhanced Host Controller Interface) Driver
//! B2.11: USB 2.0 support (High speed, 480 Mbps)
//! v11: Periodic schedule for interrupt transfers (B2.11b)

const serial = @import("../../drivers/serial/serial.zig");
const pmm = @import("../../mm/pmm.zig");
const timer = @import("../../drivers/timer/timer.zig");
const usb = @import("usb.zig");

// =============================================================================
// EHCI Register Offsets
// =============================================================================
const EHCI_CAPLENGTH: u32 = 0x00;
const EHCI_HCIVERSION: u32 = 0x02;
const EHCI_HCSPARAMS: u32 = 0x04;
const EHCI_HCCPARAMS: u32 = 0x08;
const HCSPARAMS_N_PORTS_MASK: u32 = 0x0000000F;
const HCCPARAMS_64BIT: u32 = 1 << 0;
const HCCPARAMS_EECP_MASK: u32 = 0x0000FF00;

const EHCI_USBCMD: u32 = 0x00;
const EHCI_USBSTS: u32 = 0x04;
const EHCI_USBINTR: u32 = 0x08;
const EHCI_FRINDEX: u32 = 0x0C;
const EHCI_CTRLDSSEGMENT: u32 = 0x10;
const EHCI_PERIODICLISTBASE: u32 = 0x14;
const EHCI_ASYNCLISTADDR: u32 = 0x18;
const EHCI_CONFIGFLAG: u32 = 0x40;
const EHCI_PORTSC_BASE: u32 = 0x44;

const USBCMD_RS: u32 = 1 << 0;
const USBCMD_HCRESET: u32 = 1 << 1;
const USBCMD_PSE: u32 = 1 << 4;
const USBCMD_ASE: u32 = 1 << 5;
const USBCMD_IAAD: u32 = 1 << 6;
const USBCMD_ITC_1: u32 = 0x01 << 16;

const USBSTS_USBINT: u32 = 1 << 0;
const USBSTS_USBERRINT: u32 = 1 << 1;
const USBSTS_HSE: u32 = 1 << 4;
const USBSTS_IAA: u32 = 1 << 5;
const USBSTS_HCH: u32 = 1 << 12;
const USBSTS_ASS: u32 = 1 << 15;
const USBSTS_PSS: u32 = 1 << 14;

const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_CSC: u32 = 1 << 1;
const PORTSC_PE: u32 = 1 << 2;
const PORTSC_PEC: u32 = 1 << 3;
const PORTSC_OCC: u32 = 1 << 5;
const PORTSC_PR: u32 = 1 << 8;
const PORTSC_LS_MASK: u32 = 0x00000C00;
const PORTSC_LS_K: u32 = 0x00000800;
const PORTSC_PO: u32 = 1 << 13;
const CONFIGFLAG_CF: u32 = 1 << 0;

const QTD_ACTIVE: u32 = 1 << 7;
const QTD_HALTED: u32 = 1 << 6;
const QTD_DBE: u32 = 1 << 5;
const QTD_BABBLE: u32 = 1 << 4;
const QTD_XACT: u32 = 1 << 3;
const QTD_PID_OUT: u32 = 0 << 8;
const QTD_PID_IN: u32 = 1 << 8;
const QTD_PID_SETUP: u32 = 2 << 8;
const QTD_IOC: u32 = 1 << 15;
const QTD_DT: u32 = 1 << 31;
const QTD_TERMINATE: u32 = 1;
const QTD_ERROR_MASK: u32 = QTD_HALTED | QTD_DBE | QTD_BABBLE | QTD_XACT;

const QH_TERMINATE: u32 = 1;
const QH_TYPE_QH: u32 = 1 << 1;
const QH_HEAD: u32 = 1 << 15;
const QH_DTC: u32 = 1 << 14;
const QH_EPS_HIGH: u32 = 2 << 12;

// =============================================================================
// State
// =============================================================================
const MAX_EHCI_CONTROLLERS: usize = 4;
const MAX_PORTS_PER_EHCI: usize = 16;

// Periodic schedule constants
const MAX_PERIODIC_EPS: usize = 8; // Max interrupt endpoints
const PERIODIC_QH_OFFSET: usize = 0x800; // Offset in xfer_page for periodic QHs
const PERIODIC_QTD_OFFSET: usize = 0xC00; // Offset for periodic qTDs
const PERIODIC_DATA_OFFSET: usize = 0x800; // Offset in data_page for periodic data

const PeriodicEndpoint = struct {
    active: bool = false,
    usb_device: ?*usb.UsbDevice = null,
    endpoint: u8 = 0,
    max_packet: u16 = 8,
    interval_ms: u8 = 8, // Poll interval in ms
    data_toggle: u1 = 0,
    report_size: u8 = 8,
    // DMA offsets within xfer_page/data_page
    qh_offset: usize = 0,
    qtd_offset: usize = 0,
    data_offset: usize = 0,
    // Double buffer for safe reading
    last_report: [16]u8 = [_]u8{0} ** 16,
    new_data_ready: bool = false,
    poll_count: u64 = 0,
    success_count: u64 = 0,
    error_count: u32 = 0,
};

const EhciController = struct {
    cap_base: u64 = 0,
    op_base: u64 = 0,
    irq: u8 = 0,
    num_ports: u8 = 0,
    has_64bit: bool = false,
    hci_version: u16 = 0,
    frame_list_phys: u64 = 0,
    frame_list_virt: u64 = 0,
    xfer_page_phys: u64 = 0,
    xfer_page_virt: u64 = 0,
    data_page_phys: u64 = 0,
    data_page_virt: u64 = 0,
    port_status: [MAX_PORTS_PER_EHCI]u32 = [_]u32{0} ** MAX_PORTS_PER_EHCI,
    initialized: bool = false,
    // Periodic schedule state
    periodic_endpoints: [MAX_PERIODIC_EPS]PeriodicEndpoint = [_]PeriodicEndpoint{.{}} ** MAX_PERIODIC_EPS,
    periodic_count: usize = 0,
    periodic_active: bool = false,
};

var ehci_controllers: [MAX_EHCI_CONTROLLERS]EhciController = [_]EhciController{.{}} ** MAX_EHCI_CONTROLLERS;
var ehci_count: usize = 0;
var hhdm_offset: u64 = 0;

// =============================================================================
// MMIO helpers
// =============================================================================
inline fn wr32(addr: u64, val: u32) void {
    @as(*volatile u32, @ptrFromInt(addr)).* = val;
}
inline fn rd32(addr: u64) u32 {
    return @as(*volatile u32, @ptrFromInt(addr)).*;
}
inline fn mmioRead8(addr: u64) u8 {
    return @as(*volatile u8, @ptrFromInt(addr)).*;
}
inline fn mmioRead16(addr: u64) u16 {
    return @as(*volatile u16, @ptrFromInt(addr)).*;
}
inline fn mmioRead32(addr: u64) u32 {
    return @as(*volatile u32, @ptrFromInt(addr)).*;
}
inline fn mmioWrite32(addr: u64, value: u32) void {
    @as(*volatile u32, @ptrFromInt(addr)).* = value;
}
inline fn fence() void {
    asm volatile ("mfence" ::: .{ .memory = true });
}

// =============================================================================
// Initialization
// =============================================================================
pub fn init(ctrl: *usb.UsbController) bool {
    if (ehci_count >= MAX_EHCI_CONTROLLERS) return false;
    if (ctrl.controller_type != .ehci) return false;

    hhdm_offset = pmm.getHhdmOffset();
    const ehci = &ehci_controllers[ehci_count];
    ehci.cap_base = hhdm_offset + ctrl.base_addr;
    ehci.irq = ctrl.irq;

    serial.writeString("[EHCI] Init MMIO 0x");
    printHex64(ctrl.base_addr);
    serial.writeString("\n");

    const cap_length = mmioRead8(ehci.cap_base + EHCI_CAPLENGTH);
    const hci_version = mmioRead16(ehci.cap_base + EHCI_HCIVERSION);
    const hcs_params = mmioRead32(ehci.cap_base + EHCI_HCSPARAMS);
    const hcc_params = mmioRead32(ehci.cap_base + EHCI_HCCPARAMS);

    ehci.op_base = ehci.cap_base + cap_length;
    ehci.num_ports = @truncate(hcs_params & HCSPARAMS_N_PORTS_MASK);
    ehci.has_64bit = (hcc_params & HCCPARAMS_64BIT) != 0;
    ehci.hci_version = hci_version;

    serial.writeString("[EHCI] v0x");
    printHex16(hci_version);
    serial.writeString(" Ports:");
    printU8(ehci.num_ports);
    serial.writeString("\n");

    ctrl.num_ports = ehci.num_ports;

    const eecp: u32 = (hcc_params & HCCPARAMS_EECP_MASK) >> 8;
    if (eecp >= 0x40) takeBiosOwnership(ctrl, @truncate(eecp));

    // Stop controller
    var cmd = mmioRead32(ehci.op_base + EHCI_USBCMD);
    cmd &= ~(USBCMD_RS | USBCMD_ASE | USBCMD_PSE);
    mmioWrite32(ehci.op_base + EHCI_USBCMD, cmd);
    _ = waitBit(ehci, EHCI_USBSTS, USBSTS_HCH, true, 100);

    // Reset
    mmioWrite32(ehci.op_base + EHCI_USBCMD, USBCMD_HCRESET);
    if (!waitBit(ehci, EHCI_USBCMD, USBCMD_HCRESET, false, 100)) {
        serial.writeString("[EHCI] Reset timeout\n");
        return false;
    }
    timer.sleep(10);

    // Allocate DMA pages
    ehci.frame_list_phys = pmm.allocPage() orelse return false;
    ehci.frame_list_virt = hhdm_offset + ehci.frame_list_phys;
    ehci.xfer_page_phys = pmm.allocPage() orelse {
        pmm.freePage(ehci.frame_list_phys);
        return false;
    };
    ehci.xfer_page_virt = hhdm_offset + ehci.xfer_page_phys;
    ehci.data_page_phys = pmm.allocPage() orelse {
        pmm.freePage(ehci.frame_list_phys);
        pmm.freePage(ehci.xfer_page_phys);
        return false;
    };
    ehci.data_page_virt = hhdm_offset + ehci.data_page_phys;

    serial.writeString("[EHCI] DMA: xfer=0x");
    printHex32(@truncate(ehci.xfer_page_phys));
    serial.writeString(" data=0x");
    printHex32(@truncate(ehci.data_page_phys));
    serial.writeString("\n");

    @memset(@as([*]u8, @ptrFromInt(ehci.frame_list_virt))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(ehci.xfer_page_virt))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(ehci.data_page_virt))[0..4096], 0);

    // Periodic frame list: all terminated initially
    const fl: [*]volatile u32 = @ptrFromInt(ehci.frame_list_virt);
    for (0..1024) |i| fl[i] = QH_TERMINATE;

    if (ehci.has_64bit) mmioWrite32(ehci.op_base + EHCI_CTRLDSSEGMENT, 0);
    mmioWrite32(ehci.op_base + EHCI_PERIODICLISTBASE, @truncate(ehci.frame_list_phys));
    mmioWrite32(ehci.op_base + EHCI_ASYNCLISTADDR, 0);
    mmioWrite32(ehci.op_base + EHCI_USBSTS, 0x3F);
    mmioWrite32(ehci.op_base + EHCI_USBINTR, USBSTS_USBINT | USBSTS_USBERRINT | USBSTS_IAA);
    mmioWrite32(ehci.op_base + EHCI_CONFIGFLAG, CONFIGFLAG_CF);
    timer.sleep(50);

    // Start: RS + PSE + ITC=1
    mmioWrite32(ehci.op_base + EHCI_USBCMD, USBCMD_RS | USBCMD_PSE | USBCMD_ITC_1);
    timer.sleep(20);

    if ((mmioRead32(ehci.op_base + EHCI_USBSTS) & USBSTS_HCH) != 0) {
        serial.writeString("[EHCI] Start failed\n");
        return false;
    }

    serial.writeString("[EHCI] Running\n");
    ehci.initialized = true;
    ehci_count += 1;

    for (0..ehci.num_ports) |port| probePort(ehci, @truncate(port));
    return true;
}

fn waitBit(ehci: *EhciController, reg: u32, bit: u32, want_set: bool, max_ms: u32) bool {
    var t = max_ms;
    while (t > 0) : (t -= 1) {
        if (((mmioRead32(ehci.op_base + reg) & bit) != 0) == want_set) return true;
        timer.sleep(1);
    }
    return false;
}

fn takeBiosOwnership(ctrl: *usb.UsbController, eecp: u8) void {
    const reg = pciRead(ctrl.pci_bus, ctrl.pci_device, ctrl.pci_function, eecp);
    if ((reg & (1 << 16)) != 0) {
        pciWrite(ctrl.pci_bus, ctrl.pci_device, ctrl.pci_function, eecp, reg | (1 << 24));
        var t: u32 = 100;
        while (t > 0) : (t -= 1) {
            if ((pciRead(ctrl.pci_bus, ctrl.pci_device, ctrl.pci_function, eecp) & (1 << 16)) == 0) break;
            timer.sleep(10);
        }
    }
}

fn resetPort(ehci: *EhciController, port: u8) bool {
    const pa = ehci.op_base + EHCI_PORTSC_BASE + @as(u32, port) * 4;
    var ps = mmioRead32(pa);
    mmioWrite32(pa, (ps | PORTSC_PR) & ~PORTSC_PE);
    timer.sleep(55);
    ps = mmioRead32(pa);
    mmioWrite32(pa, ps & ~PORTSC_PR);
    timer.sleep(10);
    var t: u32 = 20;
    while (t > 0) : (t -= 1) {
        ps = mmioRead32(pa);
        if ((ps & PORTSC_PE) != 0) {
            mmioWrite32(pa, ps | PORTSC_CSC | PORTSC_PEC | PORTSC_OCC);
            timer.sleep(10);
            return true;
        }
        timer.sleep(5);
    }
    return false;
}

fn probePort(ehci: *EhciController, port: u8) void {
    const pa = ehci.op_base + EHCI_PORTSC_BASE + @as(u32, port) * 4;
    var ps = mmioRead32(pa);
    if (port < MAX_PORTS_PER_EHCI) ehci.port_status[port] = ps;
    if ((ps & PORTSC_CCS) == 0) {
        serial.writeString("[EHCI] P");
        printU8(port + 1);
        serial.writeString(": empty\n");
        return;
    }
    if ((ps & PORTSC_LS_MASK) == PORTSC_LS_K) {
        serial.writeString("[EHCI] P");
        printU8(port + 1);
        serial.writeString(": LS->companion\n");
        mmioWrite32(pa, ps | PORTSC_PO);
        return;
    }
    serial.writeString("[EHCI] P");
    printU8(port + 1);
    serial.writeString(": reset\n");
    if (!resetPort(ehci, port)) {
        serial.writeString("[EHCI] P");
        printU8(port + 1);
        serial.writeString(": enable fail\n");
        ps = mmioRead32(pa);
        mmioWrite32(pa, ps | PORTSC_PO);
        return;
    }
    ps = mmioRead32(pa);
    if (port < MAX_PORTS_PER_EHCI) ehci.port_status[port] = ps;
    serial.writeString("[EHCI] P");
    printU8(port + 1);
    serial.writeString(": HS OK\n");
    _ = enumerateDevice(ehci, port);
}

// =============================================================================
// Control Transfer v10 - Pre-populated overlay
// =============================================================================

fn controlXfer(ehci: *EhciController, addr: u7, max_pkt: u16, setup: *const usb.SetupPacket, data: ?[]u8, dir_in: bool) bool {
    const xfer_p = ehci.xfer_page_phys;
    const xfer_v = ehci.xfer_page_virt;
    const data_p = ehci.data_page_phys;
    const data_v = ehci.data_page_virt;

    const qh_phys: u32 = @truncate(xfer_p);
    const qh_virt: u64 = xfer_v;
    const qtd_s_p: u32 = @truncate(xfer_p + 0x040);
    const qtd_s_v: u64 = xfer_v + 0x040;
    const qtd_d_p: u32 = @truncate(xfer_p + 0x080);
    const qtd_d_v: u64 = xfer_v + 0x080;
    const qtd_st_p: u32 = @truncate(xfer_p + 0x0C0);
    const qtd_st_v: u64 = xfer_v + 0x0C0;
    const setup_buf: u32 = @truncate(data_p);
    const data_buf: u32 = @truncate(data_p + 0x200);

    const data_len: u16 = if (data) |d| @truncate(d.len) else 0;
    const mps: u32 = if (max_pkt >= 8) @as(u32, max_pkt) else 64;
    const has_data = data_len > 0;

    // 1) Ensure ASE off
    var cmd = mmioRead32(ehci.op_base + EHCI_USBCMD);
    if ((cmd & USBCMD_ASE) != 0) {
        cmd &= ~USBCMD_ASE;
        mmioWrite32(ehci.op_base + EHCI_USBCMD, cmd);
        var w: u32 = 200;
        while (w > 0) : (w -= 1) {
            if ((mmioRead32(ehci.op_base + EHCI_USBSTS) & USBSTS_ASS) == 0) break;
            timer.sleep(1);
        }
    }
    timer.sleep(1);

    // 2) Clear DMA (control transfer area only: 0x000-0x0FF)
    @memset(@as([*]u8, @ptrFromInt(xfer_v))[0..0x100], 0);
    @memset(@as([*]u8, @ptrFromInt(data_v))[0..0x400], 0);

    const sp = @as([*]const u8, @ptrCast(setup));
    @memcpy(@as([*]u8, @ptrFromInt(data_v))[0..8], sp[0..8]);

    if (!dir_in and data != null and data_len > 0) {
        @memcpy(@as([*]u8, @ptrFromInt(data_v + 0x200))[0..data_len], data.?[0..data_len]);
    }
    fence();

    // 3) Build qTD chain
    const s_next = if (has_data) qtd_d_p else qtd_st_p;
    const s_token: u32 = QTD_ACTIVE | QTD_PID_SETUP | (3 << 10) | (8 << 16);
    wr32(qtd_s_v + 0x00, s_next);
    wr32(qtd_s_v + 0x04, QTD_TERMINATE);
    wr32(qtd_s_v + 0x08, s_token);
    wr32(qtd_s_v + 0x0C, setup_buf);
    wr32(qtd_s_v + 0x10, 0);
    wr32(qtd_s_v + 0x14, 0);
    wr32(qtd_s_v + 0x18, 0);
    wr32(qtd_s_v + 0x1C, 0);

    if (has_data) {
        const d_pid = if (dir_in) QTD_PID_IN else QTD_PID_OUT;
        const d_token: u32 = QTD_ACTIVE | d_pid | QTD_DT | (3 << 10) | (@as(u32, data_len) << 16);
        wr32(qtd_d_v + 0x00, qtd_st_p);
        wr32(qtd_d_v + 0x04, QTD_TERMINATE);
        wr32(qtd_d_v + 0x08, d_token);
        wr32(qtd_d_v + 0x0C, data_buf);
        wr32(qtd_d_v + 0x10, 0);
        wr32(qtd_d_v + 0x14, 0);
        wr32(qtd_d_v + 0x18, 0);
        wr32(qtd_d_v + 0x1C, 0);
    }

    const st_pid = if (dir_in or !has_data) QTD_PID_OUT else QTD_PID_IN;
    const st_token: u32 = QTD_ACTIVE | st_pid | QTD_DT | QTD_IOC | (3 << 10);
    wr32(qtd_st_v + 0x00, QTD_TERMINATE);
    wr32(qtd_st_v + 0x04, QTD_TERMINATE);
    wr32(qtd_st_v + 0x08, st_token);
    wr32(qtd_st_v + 0x0C, 0);
    wr32(qtd_st_v + 0x10, 0);
    wr32(qtd_st_v + 0x14, 0);
    wr32(qtd_st_v + 0x18, 0);
    wr32(qtd_st_v + 0x1C, 0);

    fence();

    // 4) Build QH with overlay pre-populated
    wr32(qh_virt + 0x00, qh_phys | QH_TYPE_QH);
    var ec: u32 = @as(u32, addr);
    ec |= QH_EPS_HIGH | QH_DTC | QH_HEAD;
    ec |= (mps << 16);
    ec |= (15 << 28);
    wr32(qh_virt + 0x04, ec);
    wr32(qh_virt + 0x08, (1 << 30));
    wr32(qh_virt + 0x0C, qtd_s_p);
    wr32(qh_virt + 0x10, s_next);
    wr32(qh_virt + 0x14, QTD_TERMINATE);
    wr32(qh_virt + 0x18, s_token);
    wr32(qh_virt + 0x1C, setup_buf);
    wr32(qh_virt + 0x20, 0);
    wr32(qh_virt + 0x24, 0);
    wr32(qh_virt + 0x28, 0);
    wr32(qh_virt + 0x2C, 0);

    fence();

    // 5) Enable async schedule
    mmioWrite32(ehci.op_base + EHCI_ASYNCLISTADDR, qh_phys);
    fence();
    mmioWrite32(ehci.op_base + EHCI_USBSTS, 0x3F);
    fence();
    cmd = mmioRead32(ehci.op_base + EHCI_USBCMD);
    cmd |= USBCMD_ASE;
    mmioWrite32(ehci.op_base + EHCI_USBCMD, cmd);
    fence();

    {
        var t: u32 = 100;
        while (t > 0) : (t -= 1) {
            if ((mmioRead32(ehci.op_base + EHCI_USBSTS) & USBSTS_ASS) != 0) break;
            timer.sleep(1);
        }
    }

    // 6) Poll for completion
    var timeout: u32 = 1000;
    var completed = false;
    while (timeout > 0) : (timeout -= 1) {
        fence();
        const ov = rd32(qh_virt + 0x18);

        if ((ov & QTD_IOC) != 0 and (ov & QTD_ACTIVE) == 0 and (ov & QTD_ERROR_MASK) == 0) {
            completed = true;
            break;
        }
        if ((ov & QTD_HALTED) != 0) break;
        const sts = mmioRead32(ehci.op_base + EHCI_USBSTS);
        if ((sts & USBSTS_USBERRINT) != 0) {
            mmioWrite32(ehci.op_base + EHCI_USBSTS, USBSTS_USBERRINT);
            break;
        }
        if ((sts & USBSTS_HSE) != 0) {
            mmioWrite32(ehci.op_base + EHCI_USBSTS, USBSTS_HSE);
            break;
        }
        if ((sts & USBSTS_USBINT) != 0) {
            mmioWrite32(ehci.op_base + EHCI_USBSTS, USBSTS_USBINT);
        }
        const st_tok = rd32(qtd_st_v + 0x08);
        if ((st_tok & QTD_ACTIVE) == 0 and (st_tok & QTD_ERROR_MASK) == 0 and (st_tok & QTD_IOC) != 0) {
            completed = true;
            break;
        }
        timer.sleep(2);
    }

    // 7) Disable ASE
    cmd = mmioRead32(ehci.op_base + EHCI_USBCMD);
    cmd &= ~USBCMD_ASE;
    mmioWrite32(ehci.op_base + EHCI_USBCMD, cmd);
    {
        var t: u32 = 200;
        while (t > 0) : (t -= 1) {
            if ((mmioRead32(ehci.op_base + EHCI_USBSTS) & USBSTS_ASS) == 0) break;
            timer.sleep(1);
        }
    }

    // 8) Fallback check
    if (!completed) {
        fence();
        const stk = rd32(qtd_s_v + 0x08);
        const sttk = rd32(qtd_st_v + 0x08);
        if ((stk & QTD_ACTIVE) == 0 and (stk & QTD_ERROR_MASK) == 0 and
            (sttk & QTD_ACTIVE) == 0 and (sttk & QTD_ERROR_MASK) == 0)
        {
            if (has_data) {
                const dtk = rd32(qtd_d_v + 0x08);
                if ((dtk & QTD_ACTIVE) == 0 and (dtk & QTD_ERROR_MASK) == 0) completed = true;
            } else {
                completed = true;
            }
        }
    }

    // Only log errors, not success (to avoid spam during HID polling)
    if (!completed) {
        serial.writeString("[EHCI] XFAIL a=");
        printU8(addr);
        serial.writeString(" OV=");
        printHex32(rd32(qh_virt + 0x18));
        serial.writeString(" S=");
        printHex32(rd32(qtd_s_v + 0x08));
        serial.writeString(" ST=");
        printHex32(rd32(qtd_st_v + 0x08));
        if (has_data) {
            serial.writeString(" D=");
            printHex32(rd32(qtd_d_v + 0x08));
        }
        serial.writeString("\n");
    }

    if (completed and dir_in and data != null and data_len > 0) {
        @memcpy(data.?[0..data_len], @as([*]u8, @ptrFromInt(data_v + 0x200))[0..data_len]);
    }

    return completed;
}

// =============================================================================
// Enumeration v10a
// =============================================================================
fn enumerateDevice(ehci: *EhciController, port: u8) bool {
    const dev = usb.allocateDevice() orelse return false;
    dev.controller_type = .ehci;
    dev.controller_index = @truncate(ehci_count - 1);
    dev.port = port;
    dev.speed = usb.USB_SPEED_HIGH;
    dev.state = .default;
    dev.max_packet_size0 = 64;

    // QEMU FIX: Force address 0 - don't reassign
    dev.address = 0;

    // Step 1: GET_DESCRIPTOR(8) at address 0
    var desc: [18]u8 = [_]u8{0} ** 18;
    if (!controlXfer(ehci, 0, 64, &usb.SetupPacket{
        .bmRequestType = 0x80,
        .bRequest = 0x06,
        .wValue = 0x0100,
        .wIndex = 0,
        .wLength = 8,
    }, desc[0..8], true)) {
        serial.writeString("[EHCI] DESC8 fail\n");
        usb.freeDevice(dev);
        return false;
    }

    dev.max_packet_size0 = if (desc[7] >= 8) desc[7] else 64;
    serial.writeString("[EHCI] MaxPkt=");
    printU8(dev.max_packet_size0);
    serial.writeString("\n");

    // Step 2: GET full descriptor at address 0
    desc = [_]u8{0} ** 18;
    if (controlXfer(ehci, 0, 64, &usb.SetupPacket{
        .bmRequestType = 0x80,
        .bRequest = 0x06,
        .wValue = 0x0100,
        .wIndex = 0,
        .wLength = 18,
    }, desc[0..18], true)) {
        dev.vendor_id = @as(u16, desc[8]) | (@as(u16, desc[9]) << 8);
        dev.product_id = @as(u16, desc[10]) | (@as(u16, desc[11]) << 8);
        dev.device_class = desc[4];
        dev.device_subclass = desc[5];
        dev.device_protocol = desc[6];
        serial.writeString("[EHCI] VID:PID=");
        printHex16(dev.vendor_id);
        serial.writeString(":");
        printHex16(dev.product_id);
        serial.writeString(" class=");
        printU8(dev.device_class);
        serial.writeString("\n");
    }

    // Step 3: GET_CONFIG at address 0
    var cfg: [64]u8 = [_]u8{0} ** 64;
    if (controlXfer(ehci, 0, 64, &usb.SetupPacket{
        .bmRequestType = 0x80,
        .bRequest = 0x06,
        .wValue = 0x0200,
        .wIndex = 0,
        .wLength = 64,
    }, cfg[0..64], true)) {
        if (cfg[0] >= 9) parseConfig(dev, &cfg);
    }

    // Step 4: SET_CONFIGURATION at address 0
    if (controlXfer(ehci, 0, 64, &usb.SetupPacket{
        .bmRequestType = 0x00,
        .bRequest = 0x09,
        .wValue = 1,
        .wIndex = 0,
        .wLength = 0,
    }, null, false)) {
        dev.current_config = 1;
        serial.writeString("[EHCI] Config=1\n");
    }

    // Step 5: SET_PROTOCOL(boot) for HID boot devices
    for (dev.interfaces[0..dev.num_interfaces]) |iface| {
        if (iface.active and iface.class == usb.USB_CLASS_HID and
            iface.subclass == usb.USB_HID_SUBCLASS_BOOT)
        {
            _ = controlXfer(ehci, 0, 64, &usb.SetupPacket{
                .bmRequestType = 0x21,
                .bRequest = 0x0B,
                .wValue = 0,
                .wIndex = iface.number,
                .wLength = 0,
            }, null, false);
            serial.writeString("[EHCI] SET_PROTOCOL(boot)\n");

            _ = controlXfer(ehci, 0, 64, &usb.SetupPacket{
                .bmRequestType = 0x21,
                .bRequest = 0x0A,
                .wValue = 0,
                .wIndex = iface.number,
                .wLength = 0,
            }, null, false);
            serial.writeString("[EHCI] SET_IDLE(0)\n");
        }
    }

    // QEMU MODE: Skip SET_ADDRESS entirely - device stays at address 0
    // Real hardware would need SET_ADDRESS for multi-device support
    dev.state = .configured;
    serial.writeString("[EHCI] Configured (addr=0 QEMU-mode)\n");

    return true;
}

fn parseConfig(dev: *usb.UsbDevice, data: []const u8) void {
    var off: usize = 0;
    while (off + 2 <= data.len) {
        const len = data[off];
        const dtype = data[off + 1];
        if (len < 2 or off + len > data.len) break;
        if (dtype == usb.USB_DESC_INTERFACE and len >= 9 and dev.num_interfaces < usb.MAX_INTERFACES) {
            const iface = &dev.interfaces[dev.num_interfaces];
            iface.number = data[off + 2];
            iface.alt_setting = data[off + 3];
            iface.num_endpoints = data[off + 4];
            iface.class = data[off + 5];
            iface.subclass = data[off + 6];
            iface.protocol = data[off + 7];
            iface.active = true;
            dev.num_interfaces += 1;
            serial.writeString("[EHCI] IF");
            printU8(iface.number);
            serial.writeString(" c=");
            printU8(iface.class);
            serial.writeString(" s=");
            printU8(iface.subclass);
            serial.writeString(" p=");
            printU8(iface.protocol);
            serial.writeString("\n");
        }
        // Parse endpoint descriptors too
        if (dtype == usb.USB_DESC_ENDPOINT and len >= 7 and dev.num_interfaces > 0) {
            const iface = &dev.interfaces[dev.num_interfaces - 1];
            if (iface.num_endpoints > 0) {
                // Find next free endpoint slot
                for (&iface.endpoints) |*ep| {
                    if (!ep.active) {
                        ep.address = data[off + 2];
                        ep.attributes = data[off + 3];
                        ep.max_packet_size = @as(u16, data[off + 4]) | (@as(u16, data[off + 5]) << 8);
                        ep.interval = data[off + 6];
                        ep.active = true;
                        break;
                    }
                }
            }
        }
        off += len;
    }
}

// =============================================================================
// Periodic Schedule - Interrupt Transfers (B2.11b v11)
// =============================================================================
//
// Architecture:
//   - Frame list has 1024 entries, each pointing to QH chain or TERMINATE
//   - For 8ms polling: link QH into every 8th frame entry
//   - Hardware automatically traverses frame list every 1ms
//   - qTD completion checked by pollPeriodicEndpoints() (called from HID timer)
//
// Memory layout (xfer_page 0x800+):
//   0x800 + i*0x40: QH for periodic endpoint i (64B aligned)
//   0xC00 + i*0x20: qTD for periodic endpoint i (32B aligned)
//
// Memory layout (data_page 0x800+):
//   0x800 + i*0x40: Data buffer for periodic endpoint i (64B)

/// Register an interrupt endpoint for periodic polling
pub fn registerPeriodicEndpoint(dev: *usb.UsbDevice, endpoint: u8, report_size: u8, interval_ms: u8) bool {
    if (ehci_count == 0) return false;
    const ehci = &ehci_controllers[0];
    if (!ehci.initialized) return false;
    if (ehci.periodic_count >= MAX_PERIODIC_EPS) return false;

    const idx = ehci.periodic_count;
    var pep = &ehci.periodic_endpoints[idx];

    pep.active = true;
    pep.usb_device = dev;
    pep.endpoint = endpoint;
    pep.max_packet = if (report_size > 0) @as(u16, report_size) else 8;
    pep.interval_ms = if (interval_ms >= 1) interval_ms else 8;
    pep.report_size = report_size;
    pep.data_toggle = 0;
    pep.qh_offset = PERIODIC_QH_OFFSET + idx * 0x40;
    pep.qtd_offset = PERIODIC_QTD_OFFSET + idx * 0x20;
    pep.data_offset = PERIODIC_DATA_OFFSET + idx * 0x40;

    // Build the interrupt QH and qTD
    buildPeriodicQh(ehci, pep, idx);

    // Link QH into frame list at regular intervals
    linkToFrameList(ehci, pep, idx);

    ehci.periodic_count += 1;
    ehci.periodic_active = true;

    // Ensure PSE is enabled
    const cmd = mmioRead32(ehci.op_base + EHCI_USBCMD);
    if ((cmd & USBCMD_PSE) == 0) {
        mmioWrite32(ehci.op_base + EHCI_USBCMD, cmd | USBCMD_PSE);
        timer.sleep(2);
    }

    serial.writeString("[EHCI] Periodic EP");
    printU8(endpoint & 0x0F);
    serial.writeString(" registered (");
    printU8(report_size);
    serial.writeString("B, ");
    printU8(pep.interval_ms);
    serial.writeString("ms)\n");

    return true;
}

fn buildPeriodicQh(ehci: *EhciController, pep: *PeriodicEndpoint, idx: usize) void {
    _ = idx;
    const dev = pep.usb_device orelse return;
    const addr: u7 = @truncate(dev.address & 0x7F);
    const ep_num: u4 = @truncate(pep.endpoint & 0x0F);
    const mps: u32 = @min(64, pep.max_packet);
    const data_len: u16 = pep.report_size;

    const qh_v = ehci.xfer_page_virt + pep.qh_offset;
    const qtd_v = ehci.xfer_page_virt + pep.qtd_offset;
    const qtd_p: u32 = @truncate(ehci.xfer_page_phys + pep.qtd_offset);
    const data_buf_p: u32 = @truncate(ehci.data_page_phys + pep.data_offset);

    // Clear
    @memset(@as([*]u8, @ptrFromInt(qh_v))[0..0x40], 0);
    @memset(@as([*]u8, @ptrFromInt(qtd_v))[0..0x20], 0);

    // Build qTD: IN transfer
    const token: u32 = QTD_ACTIVE | QTD_PID_IN | QTD_IOC | (3 << 10) | (@as(u32, data_len) << 16);
    wr32(qtd_v + 0x00, QTD_TERMINATE); // next
    wr32(qtd_v + 0x04, QTD_TERMINATE); // alt_next
    wr32(qtd_v + 0x08, token);
    wr32(qtd_v + 0x0C, data_buf_p);
    wr32(qtd_v + 0x10, 0);
    wr32(qtd_v + 0x14, 0);
    wr32(qtd_v + 0x18, 0);
    wr32(qtd_v + 0x1C, 0);

    // Build QH for interrupt endpoint
    // DW0: horizontal link = TERMINATE (will be set by linkToFrameList)
    wr32(qh_v + 0x00, QH_TERMINATE);

    // DW1: endpoint characteristics
    // For interrupt QH: NO QH_HEAD flag, include endpoint number
    var ec: u32 = @as(u32, addr);
    ec |= (@as(u32, ep_num) << 8);
    ec |= QH_EPS_HIGH; // High speed
    ec |= QH_DTC; // Data toggle from qTD
    ec |= (mps << 16);
    ec |= (0 << 28); // RL=0 for interrupt
    wr32(qh_v + 0x04, ec);

    // DW2: endpoint capabilities
    // S-mask: which microframes to poll (bits 0-7)
    // For 8ms interval on high-speed: poll in microframe 0 of every 8th frame
    // S-mask = 0x01 (microframe 0 only)
    // C-mask = 0x1C (complete in microframes 2,3,4) — needed for split transactions
    // For high-speed direct: just S-mask is needed
    var caps: u32 = (1 << 30); // mult=1
    caps |= 0x01; // S-mask: microframe 0
    wr32(qh_v + 0x08, caps);

    // DW3: current qTD
    wr32(qh_v + 0x0C, qtd_p);

    // DW4-11: overlay = copy of qTD
    wr32(qh_v + 0x10, QTD_TERMINATE);
    wr32(qh_v + 0x14, QTD_TERMINATE);
    wr32(qh_v + 0x18, token);
    wr32(qh_v + 0x1C, data_buf_p);
    wr32(qh_v + 0x20, 0);
    wr32(qh_v + 0x24, 0);
    wr32(qh_v + 0x28, 0);
    wr32(qh_v + 0x2C, 0);

    fence();
}

fn linkToFrameList(ehci: *EhciController, pep: *PeriodicEndpoint, idx: usize) void {
    _ = idx;
    const qh_phys: u32 = @truncate(ehci.xfer_page_phys + pep.qh_offset);
    const fl: [*]volatile u32 = @ptrFromInt(ehci.frame_list_virt);

    // Link QH into frame list at regular intervals
    // interval_ms maps to frame indices (1 frame = 1ms at high speed)
    const interval: u32 = @max(1, @min(256, @as(u32, pep.interval_ms)));

    var frame: u32 = 0;
    while (frame < 1024) : (frame += interval) {
        const existing = fl[frame];
        if ((existing & QH_TERMINATE) != 0) {
            // Empty slot — point directly to our QH
            fl[frame] = qh_phys | QH_TYPE_QH;
        } else {
            // Chain: set our QH's next to existing, point frame to us
            const qh_v = ehci.xfer_page_virt + pep.qh_offset;
            wr32(qh_v + 0x00, existing);
            fl[frame] = qh_phys | QH_TYPE_QH;
        }
    }

    fence();
}

/// Poll periodic endpoints for completed transfers (non-blocking)
/// Called from hid.zig via processPending()
pub fn pollPeriodicEndpoints() bool {
    if (ehci_count == 0) return false;
    const ehci = &ehci_controllers[0];
    if (!ehci.initialized or !ehci.periodic_active) return false;

    var any_data = false;

    for (&ehci.periodic_endpoints) |*pep| {
        if (!pep.active) continue;

        pep.poll_count += 1;

        const qh_v = ehci.xfer_page_virt + pep.qh_offset;
        const qtd_v = ehci.xfer_page_virt + pep.qtd_offset;
        const data_v = ehci.data_page_virt + pep.data_offset;

        fence();

        // Check QH overlay token (DW6 = offset 0x18)
        const overlay_token = rd32(qh_v + 0x18);

        // Also check the actual qTD
        const qtd_token = rd32(qtd_v + 0x08);

        // Transfer complete if ACTIVE bit is clear
        const overlay_done = (overlay_token & QTD_ACTIVE) == 0;
        const qtd_done = (qtd_token & QTD_ACTIVE) == 0;

        if (!overlay_done and !qtd_done) {
            // Still in progress
            continue;
        }

        // Check for errors
        const has_error = ((overlay_token | qtd_token) & QTD_ERROR_MASK) != 0;

        if (has_error) {
            pep.error_count += 1;
            if (pep.error_count > 100) {
                pep.active = false;
                serial.writeString("[EHCI] Periodic EP disabled (errors)\n");
            }
            // Rearm anyway to retry
            rearmPeriodicQtd(ehci, pep);
            continue;
        }

        // Success! Check if data actually changed
        const rsize = pep.report_size;
        const data_ptr = @as([*]u8, @ptrFromInt(data_v));

        // Check if any non-zero data (QEMU sends zeros when idle)
        var has_nonzero = false;
        var changed = false;
        for (0..rsize) |j| {
            if (data_ptr[j] != 0) has_nonzero = true;
            if (data_ptr[j] != pep.last_report[j]) changed = true;
        }

        if (has_nonzero or changed) {
            // Copy to last_report
            @memcpy(pep.last_report[0..rsize], data_ptr[0..rsize]);
            pep.new_data_ready = true;
            pep.success_count += 1;
            pep.error_count = 0;
            any_data = true;
        }

        // Rearm for next transfer
        rearmPeriodicQtd(ehci, pep);
    }

    // Clear any pending USB interrupts
    const sts = mmioRead32(ehci.op_base + EHCI_USBSTS);
    if ((sts & (USBSTS_USBINT | USBSTS_USBERRINT)) != 0) {
        mmioWrite32(ehci.op_base + EHCI_USBSTS, sts & 0x3F);
    }

    return any_data;
}

fn rearmPeriodicQtd(ehci: *EhciController, pep: *PeriodicEndpoint) void {
    const qh_v = ehci.xfer_page_virt + pep.qh_offset;
    const qtd_v = ehci.xfer_page_virt + pep.qtd_offset;
    const qtd_p: u32 = @truncate(ehci.xfer_page_phys + pep.qtd_offset);
    const data_buf_p: u32 = @truncate(ehci.data_page_phys + pep.data_offset);
    const data_buf_v = ehci.data_page_virt + pep.data_offset;
    const data_len: u16 = pep.report_size;

    // Toggle data toggle
    pep.data_toggle ^= 1;

    // Clear data buffer
    @memset(@as([*]u8, @ptrFromInt(data_buf_v))[0..64], 0);

    // Rebuild qTD with ACTIVE bit set
    const dt_bit: u32 = if (pep.data_toggle == 1) QTD_DT else 0;
    const token: u32 = QTD_ACTIVE | QTD_PID_IN | QTD_IOC | dt_bit | (3 << 10) | (@as(u32, data_len) << 16);

    wr32(qtd_v + 0x00, QTD_TERMINATE);
    wr32(qtd_v + 0x04, QTD_TERMINATE);
    wr32(qtd_v + 0x08, token);
    wr32(qtd_v + 0x0C, data_buf_p);
    wr32(qtd_v + 0x10, 0);
    wr32(qtd_v + 0x14, 0);
    wr32(qtd_v + 0x18, 0);
    wr32(qtd_v + 0x1C, 0);

    // Update QH: set current_qtd and refresh overlay
    wr32(qh_v + 0x0C, qtd_p); // current_qtd pointer

    // Overlay (DW4-DW11)
    wr32(qh_v + 0x10, QTD_TERMINATE); // next
    wr32(qh_v + 0x14, QTD_TERMINATE); // alt_next
    wr32(qh_v + 0x18, token); // token with ACTIVE
    wr32(qh_v + 0x1C, data_buf_p); // buffer[0]
    wr32(qh_v + 0x20, 0);
    wr32(qh_v + 0x24, 0);
    wr32(qh_v + 0x28, 0);
    wr32(qh_v + 0x2C, 0);

    fence();
}

/// Read latest report from a periodic endpoint (non-blocking)
pub fn readPeriodicReport(ep_index: usize, buf: []u8) bool {
    if (ehci_count == 0) return false;
    const ehci = &ehci_controllers[0];
    if (ep_index >= ehci.periodic_count) return false;

    var pep = &ehci.periodic_endpoints[ep_index];
    if (!pep.active or !pep.new_data_ready) return false;

    const copy_len = @min(buf.len, pep.report_size);
    @memcpy(buf[0..copy_len], pep.last_report[0..copy_len]);
    pep.new_data_ready = false;

    return true;
}

/// Check if periodic schedule has any active endpoints
pub fn hasPeriodicEndpoints() bool {
    if (ehci_count == 0) return false;
    return ehci_controllers[0].periodic_active;
}

/// Get periodic endpoint count
pub fn getPeriodicCount() usize {
    if (ehci_count == 0) return 0;
    return ehci_controllers[0].periodic_count;
}

/// Get stats for a periodic endpoint
pub fn getPeriodicStats(ep_index: usize) ?struct { polls: u64, successes: u64, errors: u32 } {
    if (ehci_count == 0) return null;
    const ehci = &ehci_controllers[0];
    if (ep_index >= ehci.periodic_count) return null;
    const pep = &ehci.periodic_endpoints[ep_index];
    return .{ .polls = pep.poll_count, .successes = pep.success_count, .errors = pep.error_count };
}

// =============================================================================
// Legacy interruptTransfer (kept for API compatibility, uses periodic now)
// =============================================================================

pub fn interruptTransfer(dev: *usb.UsbDevice, endpoint: u8, data: []u8) bool {
    if (ehci_count == 0) return false;
    const ehci = &ehci_controllers[0];
    if (!ehci.initialized) return false;

    // Check if this endpoint is registered in periodic schedule
    for (&ehci.periodic_endpoints) |*pep| {
        if (!pep.active) continue;
        if (pep.usb_device == dev and pep.endpoint == endpoint) {
            // Read from periodic buffer (non-blocking!)
            return readPeriodicReport(
                @divExact(@intFromPtr(pep) - @intFromPtr(&ehci.periodic_endpoints[0]), @sizeOf(PeriodicEndpoint)),
                data,
            );
        }
    }

    // Not in periodic schedule — return false
    return false;
}

// =============================================================================
// Public Interface
// =============================================================================
pub fn isInitialized() bool {
    return ehci_count > 0 and ehci_controllers[0].initialized;
}
pub fn getControllerCount() usize {
    return ehci_count;
}
pub fn getController(index: usize) ?*const EhciController {
    if (index >= ehci_count) return null;
    return &ehci_controllers[index];
}
pub fn getPortStatus(ctrl_index: usize, port: u8) u32 {
    if (ctrl_index >= ehci_count) return 0;
    if (port >= MAX_PORTS_PER_EHCI) return 0;
    return ehci_controllers[ctrl_index].port_status[port];
}
pub fn getVersion(ctrl_index: usize) u16 {
    if (ctrl_index >= ehci_count) return 0;
    return ehci_controllers[ctrl_index].hci_version;
}
pub fn controlTransfer(dev: *usb.UsbDevice, setup: *const usb.SetupPacket, data: ?[]u8, dir_in: bool) bool {
    if (ehci_count == 0) return false;
    const e = &ehci_controllers[0];
    if (!e.initialized) return false;
    return controlXfer(e, @truncate(dev.address & 0x7F), dev.max_packet_size0, setup, data, dir_in);
}
pub fn handleInterrupt() void {
    for (ehci_controllers[0..ehci_count]) |*e| {
        if (!e.initialized) continue;
        const s = mmioRead32(e.op_base + EHCI_USBSTS);
        if ((s & 0x3F) != 0) mmioWrite32(e.op_base + EHCI_USBSTS, s & 0x3F);
    }
}

// =============================================================================
// PCI
// =============================================================================
fn pciRead(bus: u8, dev: u8, func: u8, off: u8) u32 {
    const a: u32 = 0x80000000 | (@as(u32, bus) << 16) | (@as(u32, dev) << 11) | (@as(u32, func) << 8) | (@as(u32, off) & 0xFC);
    asm volatile ("outl %[v], %[p]"
        :
        : [v] "{eax}" (a),
          [p] "N{dx}" (@as(u16, 0xCF8)),
    );
    return asm volatile ("inl %[p], %[r]"
        : [r] "={eax}" (-> u32),
        : [p] "N{dx}" (@as(u16, 0xCFC)),
    );
}
fn pciWrite(bus: u8, dev: u8, func: u8, off: u8, val: u32) void {
    const a: u32 = 0x80000000 | (@as(u32, bus) << 16) | (@as(u32, dev) << 11) | (@as(u32, func) << 8) | (@as(u32, off) & 0xFC);
    asm volatile ("outl %[v], %[p]"
        :
        : [v] "{eax}" (a),
          [p] "N{dx}" (@as(u16, 0xCF8)),
    );
    asm volatile ("outl %[v], %[p]"
        :
        : [v] "{eax}" (val),
          [p] "N{dx}" (@as(u16, 0xCFC)),
    );
}

// =============================================================================
// Print helpers
// =============================================================================
fn printU8(v: u8) void {
    if (v >= 100) serial.writeChar('0' + v / 100);
    if (v >= 10) serial.writeChar('0' + (v / 10) % 10);
    serial.writeChar('0' + v % 10);
}
fn printHex16(v: u16) void {
    const h = "0123456789ABCDEF";
    serial.writeChar(h[(v >> 12) & 0xF]);
    serial.writeChar(h[(v >> 8) & 0xF]);
    serial.writeChar(h[(v >> 4) & 0xF]);
    serial.writeChar(h[v & 0xF]);
}
fn printHex32(v: u32) void {
    const h = "0123456789ABCDEF";
    var s: u5 = 28;
    while (true) {
        serial.writeChar(h[@as(usize, (v >> s) & 0xF)]);
        if (s == 0) break;
        s -= 4;
    }
}
fn printHex64(v: u64) void {
    const h = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) : (i -= 4) {
        serial.writeChar(h[@truncate((v >> i) & 0xF)]);
        if (i == 0) break;
    }
}
