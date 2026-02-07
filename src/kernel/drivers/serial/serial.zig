//! Zamrud OS - Serial Port Driver (COM1)

const COM1: u16 = 0x3F8;

fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [port] "{dx}" (port),
          [val] "{al}" (val),
    );
}

fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[ret]"
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub fn init() void {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

fn isTransmitEmpty() bool {
    return (inb(COM1 + 5) & 0x20) != 0;
}

pub fn writeChar(c: u8) void {
    while (!isTransmitEmpty()) {}
    outb(COM1, c);
}

pub fn writeString(s: []const u8) void {
    for (s) |c| writeChar(c);
}

// check point 8 scheduller
