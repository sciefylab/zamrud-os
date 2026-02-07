//! Zamrud OS - Loopback Network Interface

const network = @import("network.zig");
const serial = @import("../serial/serial.zig");

var loopback_iface: ?*network.NetworkInterface = null;
var initialized: bool = false;

pub fn init() void {
    loopback_iface = network.getInterfaceByName("lo");
    if (loopback_iface != null) {
        initialized = true;
    }
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn send(data: []const u8) bool {
    if (loopback_iface) |iface| {
        return iface.send(data);
    }
    return false;
}

pub fn getInterface() ?*network.NetworkInterface {
    return loopback_iface;
}
