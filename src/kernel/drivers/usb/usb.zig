//! Zamrud OS - USB Core Driver
//! B2.11: USB subsystem with UHCI/EHCI support and full enumeration

const serial = @import("../../drivers/serial/serial.zig");
const pci = @import("../../drivers/pci/pci.zig");
const pmm = @import("../../mm/pmm.zig");
const heap = @import("../../mm/heap.zig");
const timer = @import("../../drivers/timer/timer.zig");
const uhci = @import("uhci.zig");
const ehci = @import("ehci.zig");

// =============================================================================
// USB Constants
// =============================================================================

pub const USB_CLASS: u8 = 0x0C;
pub const USB_SUBCLASS: u8 = 0x03;

pub const USB_PROGIF_UHCI: u8 = 0x00;
pub const USB_PROGIF_OHCI: u8 = 0x10;
pub const USB_PROGIF_EHCI: u8 = 0x20;
pub const USB_PROGIF_XHCI: u8 = 0x30;

pub const USB_SPEED_LOW: u8 = 0;
pub const USB_SPEED_FULL: u8 = 1;
pub const USB_SPEED_HIGH: u8 = 2;
pub const USB_SPEED_SUPER: u8 = 3;

pub const USB_REQ_HOST_TO_DEVICE: u8 = 0x00;
pub const USB_REQ_DEVICE_TO_HOST: u8 = 0x80;
pub const USB_REQ_TYPE_STANDARD: u8 = 0x00;
pub const USB_REQ_TYPE_CLASS: u8 = 0x20;
pub const USB_REQ_TYPE_VENDOR: u8 = 0x40;
pub const USB_REQ_RECIPIENT_DEVICE: u8 = 0x00;
pub const USB_REQ_RECIPIENT_INTERFACE: u8 = 0x01;
pub const USB_REQ_RECIPIENT_ENDPOINT: u8 = 0x02;

pub const USB_REQ_GET_STATUS: u8 = 0x00;
pub const USB_REQ_CLEAR_FEATURE: u8 = 0x01;
pub const USB_REQ_SET_FEATURE: u8 = 0x03;
pub const USB_REQ_SET_ADDRESS: u8 = 0x05;
pub const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const USB_REQ_SET_DESCRIPTOR: u8 = 0x07;
pub const USB_REQ_GET_CONFIGURATION: u8 = 0x08;
pub const USB_REQ_SET_CONFIGURATION: u8 = 0x09;
pub const USB_REQ_GET_INTERFACE: u8 = 0x0A;
pub const USB_REQ_SET_INTERFACE: u8 = 0x0B;
pub const USB_REQ_SYNCH_FRAME: u8 = 0x0C;

pub const USB_DESC_DEVICE: u8 = 0x01;
pub const USB_DESC_CONFIGURATION: u8 = 0x02;
pub const USB_DESC_STRING: u8 = 0x03;
pub const USB_DESC_INTERFACE: u8 = 0x04;
pub const USB_DESC_ENDPOINT: u8 = 0x05;
pub const USB_DESC_DEVICE_QUALIFIER: u8 = 0x06;
pub const USB_DESC_OTHER_SPEED_CONFIG: u8 = 0x07;
pub const USB_DESC_INTERFACE_POWER: u8 = 0x08;
pub const USB_DESC_HID: u8 = 0x21;
pub const USB_DESC_HID_REPORT: u8 = 0x22;

pub const USB_CLASS_PER_INTERFACE: u8 = 0x00;
pub const USB_CLASS_AUDIO: u8 = 0x01;
pub const USB_CLASS_CDC: u8 = 0x02;
pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_CLASS_PHYSICAL: u8 = 0x05;
pub const USB_CLASS_IMAGE: u8 = 0x06;
pub const USB_CLASS_PRINTER: u8 = 0x07;
pub const USB_CLASS_MASS_STORAGE: u8 = 0x08;
pub const USB_CLASS_HUB: u8 = 0x09;
pub const USB_CLASS_CDC_DATA: u8 = 0x0A;
pub const USB_CLASS_WIRELESS: u8 = 0xE0;
pub const USB_CLASS_VENDOR_SPECIFIC: u8 = 0xFF;

pub const USB_HID_SUBCLASS_NONE: u8 = 0x00;
pub const USB_HID_SUBCLASS_BOOT: u8 = 0x01;
pub const USB_HID_PROTOCOL_NONE: u8 = 0x00;
pub const USB_HID_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const USB_HID_PROTOCOL_MOUSE: u8 = 0x02;

pub const USB_MSC_SUBCLASS_SCSI: u8 = 0x06;
pub const USB_MSC_PROTOCOL_BBB: u8 = 0x50;

pub const USB_EP_TYPE_CONTROL: u8 = 0x00;
pub const USB_EP_TYPE_ISOCHRONOUS: u8 = 0x01;
pub const USB_EP_TYPE_BULK: u8 = 0x02;
pub const USB_EP_TYPE_INTERRUPT: u8 = 0x03;

pub const USB_EP_DIR_OUT: u8 = 0x00;
pub const USB_EP_DIR_IN: u8 = 0x80;

// =============================================================================
// USB Structures
// =============================================================================

pub const DeviceDescriptor = extern struct {
    bLength: u8,
    bDescriptorType: u8,
    bcdUSB: u16,
    bDeviceClass: u8,
    bDeviceSubClass: u8,
    bDeviceProtocol: u8,
    bMaxPacketSize0: u8,
    idVendor: u16,
    idProduct: u16,
    bcdDevice: u16,
    iManufacturer: u8,
    iProduct: u8,
    iSerialNumber: u8,
    bNumConfigurations: u8,
};

pub const ConfigurationDescriptor = extern struct {
    bLength: u8,
    bDescriptorType: u8,
    wTotalLength: u16,
    bNumInterfaces: u8,
    bConfigurationValue: u8,
    iConfiguration: u8,
    bmAttributes: u8,
    bMaxPower: u8,
};

pub const InterfaceDescriptor = extern struct {
    bLength: u8,
    bDescriptorType: u8,
    bInterfaceNumber: u8,
    bAlternateSetting: u8,
    bNumEndpoints: u8,
    bInterfaceClass: u8,
    bInterfaceSubClass: u8,
    bInterfaceProtocol: u8,
    iInterface: u8,
};

pub const EndpointDescriptor = extern struct {
    bLength: u8,
    bDescriptorType: u8,
    bEndpointAddress: u8,
    bmAttributes: u8,
    wMaxPacketSize: u16,
    bInterval: u8,

    pub fn getNumber(self: *const EndpointDescriptor) u4 {
        return @truncate(self.bEndpointAddress & 0x0F);
    }

    pub fn isIn(self: *const EndpointDescriptor) bool {
        return (self.bEndpointAddress & USB_EP_DIR_IN) != 0;
    }

    pub fn getType(self: *const EndpointDescriptor) u2 {
        return @truncate(self.bmAttributes & 0x03);
    }
};

pub const SetupPacket = extern struct {
    bmRequestType: u8,
    bRequest: u8,
    wValue: u16,
    wIndex: u16,
    wLength: u16,
};

// =============================================================================
// Device State
// =============================================================================

pub const DeviceState = enum {
    detached,
    attached,
    powered,
    default,
    addressed,
    configured,
    suspended,
};

pub const ControllerType = enum {
    none,
    uhci,
    ohci,
    ehci,
    xhci,

    pub fn toString(self: ControllerType) []const u8 {
        return switch (self) {
            .none => "None",
            .uhci => "UHCI",
            .ohci => "OHCI",
            .ehci => "EHCI",
            .xhci => "xHCI",
        };
    }
};

// =============================================================================
// USB Device Structure
// =============================================================================

pub const MAX_DEVICES: usize = 32;
pub const MAX_ENDPOINTS: usize = 16;
pub const MAX_INTERFACES: usize = 8;

pub const UsbEndpoint = struct {
    address: u8 = 0,
    attributes: u8 = 0,
    max_packet_size: u16 = 0,
    interval: u8 = 0,
    toggle: u1 = 0,
    active: bool = false,
};

pub const UsbInterface = struct {
    number: u8 = 0,
    alt_setting: u8 = 0,
    class: u8 = 0,
    subclass: u8 = 0,
    protocol: u8 = 0,
    num_endpoints: u8 = 0,
    endpoints: [MAX_ENDPOINTS]UsbEndpoint = [_]UsbEndpoint{.{}} ** MAX_ENDPOINTS,
    active: bool = false,
};

pub const UsbDevice = struct {
    address: u8 = 0,
    speed: u8 = USB_SPEED_FULL,
    state: DeviceState = .detached,
    controller_type: ControllerType = .none,
    controller_index: u8 = 0,
    port: u8 = 0,

    vendor_id: u16 = 0,
    product_id: u16 = 0,
    device_class: u8 = 0,
    device_subclass: u8 = 0,
    device_protocol: u8 = 0,
    max_packet_size0: u8 = 8,

    current_config: u8 = 0,
    num_interfaces: u8 = 0,
    interfaces: [MAX_INTERFACES]UsbInterface = [_]UsbInterface{.{}} ** MAX_INTERFACES,

    manufacturer: [64]u8 = [_]u8{0} ** 64,
    product: [64]u8 = [_]u8{0} ** 64,
    serial_num: [32]u8 = [_]u8{0} ** 32,

    ep0: UsbEndpoint = .{},
    allocated: bool = false,

    pub fn isHid(self: *const UsbDevice) bool {
        if (self.device_class == USB_CLASS_HID) return true;
        for (self.interfaces[0..self.num_interfaces]) |iface| {
            if (iface.active and iface.class == USB_CLASS_HID) return true;
        }
        return false;
    }

    pub fn isMassStorage(self: *const UsbDevice) bool {
        if (self.device_class == USB_CLASS_MASS_STORAGE) return true;
        for (self.interfaces[0..self.num_interfaces]) |iface| {
            if (iface.active and iface.class == USB_CLASS_MASS_STORAGE) return true;
        }
        return false;
    }

    pub fn isHub(self: *const UsbDevice) bool {
        return self.device_class == USB_CLASS_HUB;
    }

    pub fn isKeyboard(self: *const UsbDevice) bool {
        for (self.interfaces[0..self.num_interfaces]) |iface| {
            if (iface.active and iface.class == USB_CLASS_HID and
                iface.subclass == USB_HID_SUBCLASS_BOOT and
                iface.protocol == USB_HID_PROTOCOL_KEYBOARD)
            {
                return true;
            }
        }
        return false;
    }

    pub fn isMouse(self: *const UsbDevice) bool {
        for (self.interfaces[0..self.num_interfaces]) |iface| {
            if (iface.active and iface.class == USB_CLASS_HID and
                iface.subclass == USB_HID_SUBCLASS_BOOT and
                iface.protocol == USB_HID_PROTOCOL_MOUSE)
            {
                return true;
            }
        }
        return false;
    }

    pub fn isTablet(self: *const UsbDevice) bool {
        // QEMU USB tablet: VID=0627 PID=0001
        if (self.vendor_id == 0x0627 and self.product_id == 0x0001) return true;
        return false;
    }

    pub fn getClassName(self: *const UsbDevice) []const u8 {
        // Check for tablet first
        if (self.isTablet()) return "HID Tablet";

        // Check interfaces
        for (self.interfaces[0..self.num_interfaces]) |iface| {
            if (iface.active) {
                if (iface.class == USB_CLASS_HID) {
                    if (iface.protocol == USB_HID_PROTOCOL_KEYBOARD) return "HID Keyboard";
                    if (iface.protocol == USB_HID_PROTOCOL_MOUSE) return "HID Mouse";
                    return "HID";
                }
                if (iface.class == USB_CLASS_MASS_STORAGE) return "Mass Storage";
            }
        }

        return switch (self.device_class) {
            USB_CLASS_PER_INTERFACE => "Composite",
            USB_CLASS_AUDIO => "Audio",
            USB_CLASS_CDC => "CDC",
            USB_CLASS_HID => "HID",
            USB_CLASS_PHYSICAL => "Physical",
            USB_CLASS_IMAGE => "Image",
            USB_CLASS_PRINTER => "Printer",
            USB_CLASS_MASS_STORAGE => "Mass Storage",
            USB_CLASS_HUB => "Hub",
            USB_CLASS_CDC_DATA => "CDC Data",
            USB_CLASS_WIRELESS => "Wireless",
            USB_CLASS_VENDOR_SPECIFIC => "Vendor",
            else => "Unknown",
        };
    }

    pub fn getSpeedString(self: *const UsbDevice) []const u8 {
        return switch (self.speed) {
            USB_SPEED_LOW => "Low (1.5M)",
            USB_SPEED_FULL => "Full (12M)",
            USB_SPEED_HIGH => "High (480M)",
            USB_SPEED_SUPER => "Super (5G)",
            else => "Unknown",
        };
    }

    pub fn getStateString(self: *const UsbDevice) []const u8 {
        return switch (self.state) {
            .detached => "Detached",
            .attached => "Attached",
            .powered => "Powered",
            .default => "Default",
            .addressed => "Addressed",
            .configured => "Configured",
            .suspended => "Suspended",
        };
    }
};

// =============================================================================
// USB Controller Info
// =============================================================================

pub const MAX_CONTROLLERS: usize = 8;

pub const UsbController = struct {
    controller_type: ControllerType = .none,
    pci_bus: u8 = 0,
    pci_device: u8 = 0,
    pci_function: u8 = 0,
    base_addr: u64 = 0,
    is_mmio: bool = false,
    irq: u8 = 0,
    num_ports: u8 = 0,
    initialized: bool = false,
    devices_found: u8 = 0,
};

// =============================================================================
// Global State
// =============================================================================

var controllers: [MAX_CONTROLLERS]UsbController = [_]UsbController{.{}} ** MAX_CONTROLLERS;
var controller_count: usize = 0;

var devices: [MAX_DEVICES]UsbDevice = [_]UsbDevice{.{}} ** MAX_DEVICES;
var device_count: usize = 0;
var next_address: u8 = 1;

var initialized: bool = false;
var hhdm_offset: u64 = 0;

// Statistics
var total_enumerations: u32 = 0;
var failed_enumerations: u32 = 0;
var total_transfers: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() bool {
    serial.writeString("[USB] Initializing USB subsystem...\n");

    hhdm_offset = pmm.getHhdmOffset();

    if (!pci.isInitialized()) {
        pci.init();
    }

    // Reset state
    controller_count = 0;
    device_count = 0;
    next_address = 1;
    total_enumerations = 0;
    failed_enumerations = 0;
    total_transfers = 0;

    for (&devices) |*dev| {
        dev.* = UsbDevice{};
    }

    // Scan for USB controllers
    const pci_devices = pci.getDevices();

    for (pci_devices) |dev| {
        if (dev.class_code == USB_CLASS and dev.subclass == USB_SUBCLASS) {
            if (controller_count >= MAX_CONTROLLERS) break;

            const ctrl_type: ControllerType = switch (dev.prog_if) {
                USB_PROGIF_UHCI => .uhci,
                USB_PROGIF_OHCI => .ohci,
                USB_PROGIF_EHCI => .ehci,
                USB_PROGIF_XHCI => .xhci,
                else => .none,
            };

            if (ctrl_type == .none) continue;

            // UHCI uses I/O ports (BAR4), EHCI/OHCI/xHCI use MMIO (BAR0)
            var base_addr: u64 = 0;
            var is_mmio = false;

            if (ctrl_type == .uhci) {
                // UHCI: BAR4 contains I/O port base address
                // BAR4 is at PCI config offset 0x20
                const bar4 = pci.readConfig(dev.bus, dev.device, dev.function, 0x20);
                if ((bar4 & 0x01) != 0) {
                    // I/O space
                    base_addr = bar4 & 0xFFFFFFFC;
                    is_mmio = false;
                } else {
                    // Fallback to BAR0 if BAR4 is not I/O
                    base_addr = dev.bar0 & 0xFFFFFFFC;
                    is_mmio = false;
                }
            } else {
                // EHCI/OHCI/xHCI: BAR0 is MMIO
                base_addr = dev.bar0 & 0xFFFFFFF0;
                is_mmio = true;
            }

            controllers[controller_count] = .{
                .controller_type = ctrl_type,
                .pci_bus = dev.bus,
                .pci_device = dev.device,
                .pci_function = dev.function,
                .base_addr = base_addr,
                .is_mmio = is_mmio,
                .irq = dev.irq_line,
                .initialized = false,
                .devices_found = 0,
            };

            serial.writeString("[USB] Found ");
            serial.writeString(ctrl_type.toString());
            serial.writeString(" at PCI ");
            printU8(dev.bus);
            serial.writeString(":");
            printU8(dev.device);
            serial.writeString(".");
            printU8(dev.function);
            serial.writeString(" ");
            if (is_mmio) {
                serial.writeString("MMIO=0x");
            } else {
                serial.writeString("I/O=0x");
            }
            printHex32(@truncate(base_addr));
            serial.writeString(" IRQ=");
            printU8(dev.irq_line);
            serial.writeString("\n");

            controller_count += 1;
        }
    }

    if (controller_count == 0) {
        serial.writeString("[USB] No USB controllers found\n");
        initialized = true;
        return false;
    }

    serial.writeString("[USB] Found ");
    printU8(@intCast(controller_count));
    serial.writeString(" USB controller(s)\n");

    // Initialize each controller
    var init_count: usize = 0;
    for (0..controller_count) |i| {
        if (initController(i)) {
            init_count += 1;
        }
    }

    initialized = true;

    // Count actual devices
    device_count = 0;
    for (&devices) |*dev| {
        if (dev.allocated) device_count += 1;
    }

    serial.writeString("[USB] USB subsystem initialized (");
    printU8(@intCast(init_count));
    serial.writeString(" controllers, ");
    printU8(@intCast(device_count));
    serial.writeString(" devices)\n");

    return init_count > 0;
}

fn initController(index: usize) bool {
    if (index >= controller_count) return false;

    const ctrl = &controllers[index];

    // Enable PCI bus mastering and I/O or memory space
    const pci_dev = pci.findDevice(
        pci.getVendorId(ctrl.pci_bus, ctrl.pci_device, ctrl.pci_function),
        pci.getDeviceId(ctrl.pci_bus, ctrl.pci_device, ctrl.pci_function),
    ) orelse return false;

    pci.enableBusMaster(pci_dev);
    if (ctrl.is_mmio) {
        pci.enableMemorySpace(pci_dev);
    } else {
        pci.enableIoSpace(pci_dev);
    }

    // Count devices before init
    const before = getDeviceCount();

    // Initialize based on controller type
    const success = switch (ctrl.controller_type) {
        .uhci => uhci.init(ctrl),
        .ehci => ehci.init(ctrl),
        else => false,
    };

    ctrl.initialized = success;

    // Update port count from driver
    if (success) {
        switch (ctrl.controller_type) {
            .uhci => ctrl.num_ports = 2,
            .ehci => {},
            else => {},
        }

        const after = getDeviceCount();
        ctrl.devices_found = @intCast(after - before);
    }

    return success;
}

// =============================================================================
// Device Management
// =============================================================================

pub fn allocateDevice() ?*UsbDevice {
    for (&devices) |*dev| {
        if (!dev.allocated) {
            dev.* = UsbDevice{};
            dev.allocated = true;
            dev.address = next_address;
            next_address += 1;
            if (next_address > 127) next_address = 1;
            total_enumerations += 1;
            return dev;
        }
    }
    return null;
}

pub fn freeDevice(dev: *UsbDevice) void {
    if (dev.allocated) {
        dev.allocated = false;
        dev.state = .detached;
        failed_enumerations += 1;
    }
}

pub fn getDeviceCount() usize {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated) count += 1;
    }
    return count;
}

pub fn getDevice(index: usize) ?*const UsbDevice {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated) {
            if (count == index) return dev;
            count += 1;
        }
    }
    return null;
}

pub fn getDeviceMut(index: usize) ?*UsbDevice {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated) {
            if (count == index) return dev;
            count += 1;
        }
    }
    return null;
}

// =============================================================================
// Controller Query
// =============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn getControllerCount() usize {
    return controller_count;
}

pub fn getController(index: usize) ?*const UsbController {
    if (index >= controller_count) return null;
    return &controllers[index];
}

pub fn hasUhci() bool {
    for (controllers[0..controller_count]) |ctrl| {
        if (ctrl.controller_type == .uhci and ctrl.initialized) return true;
    }
    return false;
}

pub fn hasEhci() bool {
    for (controllers[0..controller_count]) |ctrl| {
        if (ctrl.controller_type == .ehci and ctrl.initialized) return true;
    }
    return false;
}

pub fn getInitializedControllerCount() usize {
    var count: usize = 0;
    for (controllers[0..controller_count]) |ctrl| {
        if (ctrl.initialized) count += 1;
    }
    return count;
}

pub fn getTotalPorts() usize {
    var total: usize = 0;
    for (controllers[0..controller_count]) |ctrl| {
        if (ctrl.initialized) total += ctrl.num_ports;
    }
    return total;
}

// =============================================================================
// Device Statistics
// =============================================================================

pub fn getKeyboardCount() usize {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated and dev.isKeyboard()) count += 1;
    }
    return count;
}

pub fn getMouseCount() usize {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated and dev.isMouse()) count += 1;
    }
    return count;
}

pub fn getTabletCount() usize {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated and dev.isTablet()) count += 1;
    }
    return count;
}

pub fn getHidCount() usize {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated and dev.isHid()) count += 1;
    }
    return count;
}

pub fn getMassStorageCount() usize {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated and dev.isMassStorage()) count += 1;
    }
    return count;
}

pub fn getConfiguredCount() usize {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated and dev.state == .configured) count += 1;
    }
    return count;
}

pub fn getAddressedCount() usize {
    var count: usize = 0;
    for (&devices) |*dev| {
        if (dev.allocated and (dev.state == .addressed or dev.state == .configured)) count += 1;
    }
    return count;
}

// Statistics
pub fn getTotalEnumerations() u32 {
    return total_enumerations;
}

pub fn getFailedEnumerations() u32 {
    return failed_enumerations;
}

pub fn getTotalTransfers() u64 {
    return total_transfers;
}

pub fn incrementTransfers() void {
    total_transfers += 1;
}

// =============================================================================
// Print Helpers
// =============================================================================

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 12) & 0xF]);
    serial.writeChar(hex[(val >> 8) & 0xF]);
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    var shift: u5 = 28;
    while (true) {
        const nibble = (val >> shift) & 0xF;
        serial.writeChar(hex[@as(usize, nibble)]);
        if (shift == 0) break;
        shift -= 4;
    }
}
