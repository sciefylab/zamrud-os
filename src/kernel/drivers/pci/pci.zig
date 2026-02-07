//! Zamrud OS - PCI Bus Driver
//! Basic PCI configuration space access

const serial = @import("../serial/serial.zig");

// =============================================================================
// Constants (Public)
// =============================================================================

pub const PCI_CONFIG_ADDR: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

pub const PCI_VENDOR_INVALID: u16 = 0xFFFF;

// Common PCI Vendor IDs
pub const VENDOR_INTEL: u16 = 0x8086;
pub const VENDOR_VIRTIO: u16 = 0x1AF4;
pub const VENDOR_REALTEK: u16 = 0x10EC;
pub const VENDOR_AMD: u16 = 0x1022;
pub const VENDOR_QEMU: u16 = 0x1234;
pub const VENDOR_REDHAT: u16 = 0x1B36;

// Common Device IDs
pub const DEVICE_E1000: u16 = 0x100E;
pub const DEVICE_E1000E: u16 = 0x10D3;
pub const DEVICE_VIRTIO_NET: u16 = 0x1000;
pub const DEVICE_VIRTIO_BLK: u16 = 0x1001;
pub const DEVICE_VIRTIO_NET_MODERN: u16 = 0x1041;

// PCI Class Codes
pub const CLASS_UNCLASSIFIED: u8 = 0x00;
pub const CLASS_MASS_STORAGE: u8 = 0x01;
pub const CLASS_NETWORK: u8 = 0x02;
pub const CLASS_DISPLAY: u8 = 0x03;
pub const CLASS_MULTIMEDIA: u8 = 0x04;
pub const CLASS_MEMORY: u8 = 0x05;
pub const CLASS_BRIDGE: u8 = 0x06;
pub const CLASS_COMMUNICATION: u8 = 0x07;
pub const CLASS_SYSTEM: u8 = 0x08;
pub const CLASS_INPUT: u8 = 0x09;
pub const CLASS_SERIAL_BUS: u8 = 0x0C;

// PCI Subclass Codes (Network)
pub const SUBCLASS_ETHERNET: u8 = 0x00;
pub const SUBCLASS_TOKEN_RING: u8 = 0x01;
pub const SUBCLASS_FDDI: u8 = 0x02;

// =============================================================================
// Types
// =============================================================================

pub const PciDevice = struct {
    bus: u8,
    device: u8,
    function: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    header_type: u8,
    bar0: u32,
    bar1: u32,
    bar2: u32,
    bar3: u32,
    bar4: u32,
    bar5: u32,
    irq_line: u8,
    irq_pin: u8,

    pub fn isMultiFunction(self: *const PciDevice) bool {
        return (self.header_type & 0x80) != 0;
    }

    pub fn isBridge(self: *const PciDevice) bool {
        return self.class_code == CLASS_BRIDGE;
    }

    pub fn isNetwork(self: *const PciDevice) bool {
        return self.class_code == CLASS_NETWORK;
    }

    pub fn isStorage(self: *const PciDevice) bool {
        return self.class_code == CLASS_MASS_STORAGE;
    }

    pub fn getBar0Address(self: *const PciDevice) u32 {
        return self.bar0 & 0xFFFFFFF0;
    }

    pub fn isBar0Mmio(self: *const PciDevice) bool {
        return (self.bar0 & 0x01) == 0;
    }

    pub fn isBar0Io(self: *const PciDevice) bool {
        return (self.bar0 & 0x01) != 0;
    }
};

pub const PciAddress = struct {
    bus: u8,
    device: u8,
    function: u8,

    pub fn toConfigAddress(self: PciAddress, offset: u8) u32 {
        return 0x80000000 |
            (@as(u32, self.bus) << 16) |
            (@as(u32, self.device) << 11) |
            (@as(u32, self.function) << 8) |
            (@as(u32, offset) & 0xFC);
    }
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var devices: [64]PciDevice = undefined;
var device_count: usize = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[PCI] Initializing PCI bus...\n");

    device_count = 0;

    // Scan all buses
    scanBuses();

    initialized = true;
    serial.writeString("[PCI] PCI bus initialized (");
    printU8(@intCast(device_count));
    serial.writeString(" devices found)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn reinit() void {
    initialized = false;
    device_count = 0;
    init();
}

fn scanBuses() void {
    for (0..256) |bus| {
        for (0..32) |device| {
            scanDevice(@intCast(bus), @intCast(device));
        }
    }
}

fn scanDevice(bus: u8, device: u8) void {
    const vendor = getVendorId(bus, device, 0);
    if (vendor == PCI_VENDOR_INVALID) return;

    // Check if multi-function device
    const header_type = getHeaderType(bus, device, 0);
    if ((header_type & 0x80) != 0) {
        // Multi-function device
        for (0..8) |func| {
            if (getVendorId(bus, device, @intCast(func)) != PCI_VENDOR_INVALID) {
                addDevice(bus, device, @intCast(func));
            }
        }
    } else {
        addDevice(bus, device, 0);
    }
}

fn addDevice(bus: u8, device: u8, function: u8) void {
    if (device_count >= devices.len) return;

    const config0 = readConfig(bus, device, function, 0x00);
    const config8 = readConfig(bus, device, function, 0x08);
    const config0C = readConfig(bus, device, function, 0x0C);
    const config10 = readConfig(bus, device, function, 0x10);
    const config14 = readConfig(bus, device, function, 0x14);
    const config18 = readConfig(bus, device, function, 0x18);
    const config1C = readConfig(bus, device, function, 0x1C);
    const config20 = readConfig(bus, device, function, 0x20);
    const config24 = readConfig(bus, device, function, 0x24);
    const config3C = readConfig(bus, device, function, 0x3C);

    devices[device_count] = .{
        .bus = bus,
        .device = device,
        .function = function,
        .vendor_id = @intCast(config0 & 0xFFFF),
        .device_id = @intCast((config0 >> 16) & 0xFFFF),
        .class_code = @intCast((config8 >> 24) & 0xFF),
        .subclass = @intCast((config8 >> 16) & 0xFF),
        .prog_if = @intCast((config8 >> 8) & 0xFF),
        .header_type = @intCast((config0C >> 16) & 0xFF),
        .bar0 = config10,
        .bar1 = config14,
        .bar2 = config18,
        .bar3 = config1C,
        .bar4 = config20,
        .bar5 = config24,
        .irq_line = @intCast(config3C & 0xFF),
        .irq_pin = @intCast((config3C >> 8) & 0xFF),
    };

    device_count += 1;
}

// =============================================================================
// Configuration Space Access
// =============================================================================

pub fn readConfig(bus: u8, device: u8, func: u8, offset: u8) u32 {
    const address: u32 = 0x80000000 |
        (@as(u32, bus) << 16) |
        (@as(u32, device) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);

    outl(PCI_CONFIG_ADDR, address);
    return inl(PCI_CONFIG_DATA);
}

pub fn writeConfig(bus: u8, device: u8, func: u8, offset: u8, value: u32) void {
    const address: u32 = 0x80000000 |
        (@as(u32, bus) << 16) |
        (@as(u32, device) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);

    outl(PCI_CONFIG_ADDR, address);
    outl(PCI_CONFIG_DATA, value);
}

pub fn readConfigWord(bus: u8, device: u8, func: u8, offset: u8) u16 {
    const val = readConfig(bus, device, func, offset & 0xFC);
    const shift: u5 = @intCast((offset & 2) * 8);
    return @intCast((val >> shift) & 0xFFFF);
}

pub fn readConfigByte(bus: u8, device: u8, func: u8, offset: u8) u8 {
    const val = readConfig(bus, device, func, offset & 0xFC);
    const shift: u5 = @intCast((offset & 3) * 8);
    return @intCast((val >> shift) & 0xFF);
}

pub fn getVendorId(bus: u8, device: u8, function: u8) u16 {
    return @intCast(readConfig(bus, device, function, 0x00) & 0xFFFF);
}

pub fn getDeviceId(bus: u8, device: u8, function: u8) u16 {
    return @intCast((readConfig(bus, device, function, 0x00) >> 16) & 0xFFFF);
}

fn getHeaderType(bus: u8, device: u8, function: u8) u8 {
    return @intCast((readConfig(bus, device, function, 0x0C) >> 16) & 0xFF);
}

// =============================================================================
// Device Lookup
// =============================================================================

pub fn findDevice(vendor_id: u16, device_id: u16) ?*const PciDevice {
    for (devices[0..device_count]) |*dev| {
        if (dev.vendor_id == vendor_id and dev.device_id == device_id) {
            return dev;
        }
    }
    return null;
}

pub fn findDeviceMut(vendor_id: u16, device_id: u16) ?*PciDevice {
    for (&devices[0..device_count]) |dev| {
        if (dev.vendor_id == vendor_id and dev.device_id == device_id) {
            return dev;
        }
    }
    return null;
}

pub fn findByClass(class_code: u8, subclass: u8) ?*const PciDevice {
    for (devices[0..device_count]) |*dev| {
        if (dev.class_code == class_code and dev.subclass == subclass) {
            return dev;
        }
    }
    return null;
}

pub fn findAllByClass(class_code: u8, subclass: u8, out_buffer: []?*const PciDevice) usize {
    var count: usize = 0;
    for (devices[0..device_count]) |*dev| {
        if (dev.class_code == class_code and dev.subclass == subclass) {
            if (count < out_buffer.len) {
                out_buffer[count] = dev;
                count += 1;
            }
        }
    }
    return count;
}

pub fn findByVendor(vendor_id: u16, out_buffer: []?*const PciDevice) usize {
    var count: usize = 0;
    for (devices[0..device_count]) |*dev| {
        if (dev.vendor_id == vendor_id) {
            if (count < out_buffer.len) {
                out_buffer[count] = dev;
                count += 1;
            }
        }
    }
    return count;
}

pub fn getDevices() []const PciDevice {
    return devices[0..device_count];
}

pub fn getDeviceCount() usize {
    return device_count;
}

pub fn getDevice(index: usize) ?*const PciDevice {
    if (index >= device_count) return null;
    return &devices[index];
}

pub fn hasNetworkDevice() bool {
    return findByClass(CLASS_NETWORK, SUBCLASS_ETHERNET) != null;
}

pub fn hasVirtioDevice() bool {
    return findDevice(VENDOR_VIRTIO, DEVICE_VIRTIO_NET) != null or
        findDevice(VENDOR_VIRTIO, DEVICE_VIRTIO_NET_MODERN) != null;
}

pub fn hasE1000Device() bool {
    return findDevice(VENDOR_INTEL, DEVICE_E1000) != null or
        findDevice(VENDOR_INTEL, DEVICE_E1000E) != null;
}

// =============================================================================
// Class Code Names
// =============================================================================

pub fn getClassName(class_code: u8) []const u8 {
    return switch (class_code) {
        0x00 => "Unclassified",
        0x01 => "Mass Storage",
        0x02 => "Network",
        0x03 => "Display",
        0x04 => "Multimedia",
        0x05 => "Memory",
        0x06 => "Bridge",
        0x07 => "Communication",
        0x08 => "System",
        0x09 => "Input",
        0x0A => "Docking",
        0x0B => "Processor",
        0x0C => "Serial Bus",
        0x0D => "Wireless",
        0x0E => "Intelligent I/O",
        0x0F => "Satellite",
        0x10 => "Encryption",
        0x11 => "Signal Processing",
        else => "Unknown",
    };
}

pub fn getSubclassName(class_code: u8, subclass: u8) []const u8 {
    return switch (class_code) {
        CLASS_NETWORK => switch (subclass) {
            0x00 => "Ethernet",
            0x01 => "Token Ring",
            0x02 => "FDDI",
            0x03 => "ATM",
            0x04 => "ISDN",
            0x80 => "Other",
            else => "Unknown",
        },
        CLASS_MASS_STORAGE => switch (subclass) {
            0x00 => "SCSI",
            0x01 => "IDE",
            0x02 => "Floppy",
            0x03 => "IPI",
            0x04 => "RAID",
            0x05 => "ATA",
            0x06 => "SATA",
            0x07 => "SAS",
            0x08 => "NVM",
            else => "Unknown",
        },
        else => "Unknown",
    };
}

pub fn getVendorName(vendor_id: u16) []const u8 {
    return switch (vendor_id) {
        VENDOR_INTEL => "Intel",
        VENDOR_VIRTIO => "VirtIO",
        VENDOR_REALTEK => "Realtek",
        VENDOR_AMD => "AMD",
        VENDOR_QEMU => "QEMU",
        VENDOR_REDHAT => "Red Hat",
        else => "Unknown",
    };
}

// =============================================================================
// Enable/Disable Functions
// =============================================================================

pub fn enableBusMaster(dev: *const PciDevice) void {
    const cmd = readConfig(dev.bus, dev.device, dev.function, 0x04);
    writeConfig(dev.bus, dev.device, dev.function, 0x04, cmd | 0x04);
}

pub fn enableMemorySpace(dev: *const PciDevice) void {
    const cmd = readConfig(dev.bus, dev.device, dev.function, 0x04);
    writeConfig(dev.bus, dev.device, dev.function, 0x04, cmd | 0x02);
}

pub fn enableIoSpace(dev: *const PciDevice) void {
    const cmd = readConfig(dev.bus, dev.device, dev.function, 0x04);
    writeConfig(dev.bus, dev.device, dev.function, 0x04, cmd | 0x01);
}

pub fn disableInterrupts(dev: *const PciDevice) void {
    const cmd = readConfig(dev.bus, dev.device, dev.function, 0x04);
    writeConfig(dev.bus, dev.device, dev.function, 0x04, cmd | 0x400);
}

// =============================================================================
// Port I/O
// =============================================================================

fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "N{dx}" (port),
    );
}

fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "N{dx}" (port),
    );
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

// =============================================================================
// Debug Functions
// =============================================================================

pub fn printDeviceInfo(dev: *const PciDevice) void {
    serial.writeString("PCI ");
    printU8(dev.bus);
    serial.writeString(":");
    printU8(dev.device);
    serial.writeString(".");
    printU8(dev.function);
    serial.writeString(" - ");
    serial.writeString(getVendorName(dev.vendor_id));
    serial.writeString(" ");
    serial.writeString(getClassName(dev.class_code));
    serial.writeString("\n");
}

pub fn listAllDevices() void {
    serial.writeString("\n[PCI] Device List:\n");
    for (devices[0..device_count]) |*dev| {
        printDeviceInfo(dev);
    }
    serial.writeString("\n");
}
