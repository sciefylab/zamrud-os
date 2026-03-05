//! Zamrud OS - Programmable Interrupt Controller
//! B2.9a: Added maskIrq0Only() for APIC timer transition

const cpu = @import("../../core/cpu.zig");
const serial = @import("../../drivers/serial/serial.zig");

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;

pub fn remap(offset1: u8, offset2: u8) void {
    serial.writeString("  PIC: Remapping IRQs...\n");

    // Save current masks
    const mask1 = cpu.inb(PIC1_DATA);
    const mask2 = cpu.inb(PIC2_DATA);

    serial.writeString("  PIC: Old masks - PIC1: 0x");
    printHex(mask1);
    serial.writeString(" PIC2: 0x");
    printHex(mask2);
    serial.writeString("\n");

    // Start initialization
    cpu.outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
    cpu.ioWait();
    cpu.outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
    cpu.ioWait();

    // Set vector offsets
    cpu.outb(PIC1_DATA, offset1);
    cpu.ioWait();
    cpu.outb(PIC2_DATA, offset2);
    cpu.ioWait();

    // Tell PICs about each other
    cpu.outb(PIC1_DATA, 0x04);
    cpu.ioWait();
    cpu.outb(PIC2_DATA, 0x02);
    cpu.ioWait();

    // Set 8086 mode
    cpu.outb(PIC1_DATA, ICW4_8086);
    cpu.ioWait();
    cpu.outb(PIC2_DATA, ICW4_8086);
    cpu.ioWait();

    // === Enable IRQ0 (Timer), IRQ1 (Keyboard), IRQ2 (Cascade to slave) ===
    // 0xF8 = 11111000 binary
    // Bit 0 = 0 → IRQ0 (Timer) ENABLED ✅
    // Bit 1 = 0 → IRQ1 (Keyboard) ENABLED ✅
    // Bit 2 = 0 → IRQ2 (Cascade) ENABLED ✅
    cpu.outb(PIC1_DATA, 0xF8);

    // === Enable IRQ12 (Mouse) on slave PIC ===
    // 0xEF = 11101111 binary
    // Bit 4 = 0 → IRQ12 (Mouse) ENABLED ✅
    cpu.outb(PIC2_DATA, 0xEF);

    // Verify masks
    const new_mask1 = cpu.inb(PIC1_DATA);
    const new_mask2 = cpu.inb(PIC2_DATA);
    serial.writeString("  PIC: New masks - PIC1: 0x");
    printHex(new_mask1);
    serial.writeString(" PIC2: 0x");
    printHex(new_mask2);
    serial.writeString("\n");
    serial.writeString("   PIC: IRQ0 (Timer) = ");
    if ((new_mask1 & 0x01) == 0) serial.writeString("ENABLED\n") else serial.writeString("MASKED\n");
    serial.writeString("   PIC: IRQ1 (Keyboard) = ");
    if ((new_mask1 & 0x02) == 0) serial.writeString("ENABLED\n") else serial.writeString("MASKED\n");
    serial.writeString("   PIC: IRQ2 (Cascade) = ");
    if ((new_mask1 & 0x04) == 0) serial.writeString("ENABLED\n") else serial.writeString("MASKED\n");
    serial.writeString("   PIC: IRQ12 (Mouse) = ");
    if ((new_mask2 & 0x10) == 0) serial.writeString("ENABLED\n") else serial.writeString("MASKED\n");
}

/// B2.9a: Mask IRQ0 (PIT Timer) only, keep IRQ1 (Keyboard), IRQ2 (Cascade), IRQ12 (Mouse)
/// Called when transitioning to APIC timer for scheduling
pub fn maskIrq0Only() void {
    serial.writeString("  PIC: Masking IRQ0 (PIT) for APIC timer transition...\n");

    const old_mask = cpu.inb(PIC1_DATA);

    // 0xF9 = 11111001 binary
    // Bit 0 = 1 → IRQ0 (Timer) MASKED ❌
    // Bit 1 = 0 → IRQ1 (Keyboard) ENABLED ✅
    // Bit 2 = 0 → IRQ2 (Cascade) ENABLED ✅
    cpu.outb(PIC1_DATA, 0xF9);

    const new_mask = cpu.inb(PIC1_DATA);

    serial.writeString("  PIC: Master mask 0x");
    printHex(old_mask);
    serial.writeString(" -> 0x");
    printHex(new_mask);
    serial.writeString("\n");
    serial.writeString("   PIC: IRQ0 (PIT Timer) = MASKED\n");
    serial.writeString("   PIC: IRQ1 (Keyboard)  = ENABLED\n");
    serial.writeString("   PIC: IRQ2 (Cascade)   = ENABLED\n");
}

/// B2.9a: Unmask IRQ0 (restore PIT Timer) - for fallback
pub fn unmaskIrq0() void {
    serial.writeString("  PIC: Unmasking IRQ0 (PIT)...\n");
    const old_mask = cpu.inb(PIC1_DATA);
    cpu.outb(PIC1_DATA, old_mask & 0xFE); // Clear bit 0
    serial.writeString("   PIC: IRQ0 (PIT Timer) = ENABLED\n");
}

/// Check if IRQ0 is masked
pub fn isIrq0Masked() bool {
    return (cpu.inb(PIC1_DATA) & 0x01) != 0;
}

pub fn sendEoi(irq: u8) void {
    if (irq >= 8) {
        cpu.outb(PIC2_CMD, 0x20);
    }
    cpu.outb(PIC1_CMD, 0x20);
}

fn printHex(value: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(value >> 4) & 0x0F]);
    serial.writeChar(hex[value & 0x0F]);
}

pub fn getMask1() u8 {
    return cpu.inb(PIC1_DATA);
}

pub fn getMask2() u8 {
    return cpu.inb(PIC2_DATA);
}
