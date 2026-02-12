// =============================================================================
// F2: Shared Memory Commands
// =============================================================================

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const capability = @import("../../security/capability.zig");
const ipc = @import("../../ipc/ipc.zig");

/// shmem -- show shared memory status
pub fn cmdShmem(args: []const u8) void {
    if (!ipc.shared_mem.isInitialized()) {
        shell.println("  Shared memory not initialized");
        return;
    }
    const parsed = helpers.parseArgs(args);
    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        shell.println("");
        shell.println("  === SHARED MEMORY STATUS (F2) ===");
        shell.println("  ---------------------------------");
        const s = ipc.shared_mem.getStats();
        shell.print("  Active regions: ");
        helpers.printDec(ipc.shared_mem.getActiveRegionCount());
        shell.newLine();
        shell.print("  Created:        ");
        helpers.printDec64(s.total_created);
        shell.newLine();
        shell.print("  Destroyed:      ");
        helpers.printDec64(s.total_destroyed);
        shell.newLine();
        shell.print("  Attached:       ");
        helpers.printDec64(s.total_attached);
        shell.newLine();
        shell.print("  Detached:       ");
        helpers.printDec64(s.total_detached);
        shell.newLine();
        shell.print("  Reads:          ");
        helpers.printDec64(s.total_reads);
        shell.newLine();
        shell.print("  Writes:         ");
        helpers.printDec64(s.total_writes);
        shell.newLine();
        shell.print("  Bytes read:     ");
        helpers.printDec64(s.bytes_read);
        shell.newLine();
        shell.print("  Bytes written:  ");
        helpers.printDec64(s.bytes_written);
        shell.newLine();
        shell.print("  CAP violations: ");
        helpers.printDec64(s.cap_violations);
        shell.newLine();
        shell.println("  ---------------------------------");
        ipc.shared_mem.printStatus();
        shell.println("  (See serial for details)");
        shell.println("");
    } else shell.println("  Usage: shmem [status]");
}

/// shmtest -- run F2 shared memory test suite
pub fn cmdShmTest(_: []const u8) void {
    if (!ipc.shared_mem.isInitialized()) {
        shell.println("  Shared memory not initialized");
        return;
    }

    helpers.printTestHeader("F2 SHARED MEMORY");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Register test processes with CAP_MEMORY
    if (capability.isInitialized()) {
        _ = capability.registerProcess(30, capability.CAP_MEMORY | capability.CAP_IPC);
        _ = capability.registerProcess(40, capability.CAP_MEMORY | capability.CAP_IPC);
        _ = capability.registerProcess(50, capability.CAP_IPC); // NO CAP_MEMORY
    }

    passed += helpers.doTest("SHM initialized", ipc.shared_mem.isInitialized(), &failed);

    // Create region
    const c1 = ipc.shared_mem.create(30, "test_region", 1024);
    passed += helpers.doTest("Create region", c1.result == .ok, &failed);
    passed += helpers.doTest("Region ID > 0", c1.id > 0, &failed);

    // Active count
    passed += helpers.doTest("Active regions >= 1", ipc.shared_mem.getActiveRegionCount() >= 1, &failed);

    // Duplicate name blocked
    const c2 = ipc.shared_mem.create(30, "test_region", 512);
    passed += helpers.doTest("Dup name blocked", c2.result == .already_exists, &failed);

    // Too large blocked
    const c3 = ipc.shared_mem.create(30, "huge", 100 * 1024);
    passed += helpers.doTest("Too large blocked", c3.result == .too_large, &failed);

    // Owner auto-attached as RW
    passed += helpers.doTest("Owner attached", ipc.shared_mem.isAttached(30, c1.id), &failed);
    passed += helpers.doTest("Owner perm=RW", ipc.shared_mem.getAttachmentPerm(30, c1.id) == .read_write, &failed);

    // Write data
    const w1 = ipc.shared_mem.writeData(30, c1.id, 0, "Hello SharedMem!");
    passed += helpers.doTest("Write ok", w1.result == .ok, &failed);
    passed += helpers.doTest("Wrote 16 bytes", w1.written == 16, &failed);

    // Read data back
    var rbuf: [64]u8 = undefined;
    const r1 = ipc.shared_mem.readData(30, c1.id, 0, &rbuf);
    passed += helpers.doTest("Read ok", r1.result == .ok, &failed);
    passed += helpers.doTest("Read correct len", r1.bytes_read >= 16, &failed);

    // Verify content
    const match = rbuf[0] == 'H' and rbuf[5] == ' ' and rbuf[6] == 'S';
    passed += helpers.doTest("Content matches", match, &failed);

    // Attach pid=40 as read-only
    const a1 = ipc.shared_mem.attach(40, c1.id, .read_only);
    passed += helpers.doTest("Attach pid=40 RO", a1 == .ok, &failed);

    // pid=40 can read
    var rbuf2: [64]u8 = undefined;
    const r2 = ipc.shared_mem.readData(40, c1.id, 0, &rbuf2);
    passed += helpers.doTest("pid=40 read ok", r2.result == .ok, &failed);

    // pid=40 cannot write (RO)
    const w2 = ipc.shared_mem.writeData(40, c1.id, 0, "hack!");
    passed += helpers.doTest("pid=40 write denied", w2.result == .permission_denied, &failed);

    // pid=50 no CAP_MEMORY - attach blocked
    const a2 = ipc.shared_mem.attach(50, c1.id, .read_only);
    passed += helpers.doTest("No CAP_MEMORY blocked", a2 == .no_cap, &failed);

    // Not attached pid cannot read
    const r3 = ipc.shared_mem.readData(99, c1.id, 0, &rbuf);
    passed += helpers.doTest("Unattached read denied", r3.result == .not_attached, &failed);

    // Lock region
    passed += helpers.doTest("Lock region", ipc.shared_mem.lockRegion(30, c1.id) == .ok, &failed);

    // Write while locked
    const w3 = ipc.shared_mem.writeData(30, c1.id, 0, "locked!");
    passed += helpers.doTest("Write while locked", w3.result == .region_locked, &failed);

    // Unlock
    passed += helpers.doTest("Unlock region", ipc.shared_mem.unlockRegion(30, c1.id) == .ok, &failed);

    // Write after unlock
    const w4 = ipc.shared_mem.writeData(30, c1.id, 0, "unlocked!");
    passed += helpers.doTest("Write after unlock", w4.result == .ok, &failed);

    // Out of bounds
    const w5 = ipc.shared_mem.writeData(30, c1.id, 2000, "oob");
    passed += helpers.doTest("OOB write denied", w5.result == .out_of_bounds, &failed);

    // Find by name
    const found = ipc.shared_mem.findRegionByName("test_region");
    passed += helpers.doTest("Find by name", found != null and found.? == c1.id, &failed);

    // Detach pid=40
    passed += helpers.doTest("Detach pid=40", ipc.shared_mem.detach(40, c1.id) == .ok, &failed);
    passed += helpers.doTest("pid=40 detached", !ipc.shared_mem.isAttached(40, c1.id), &failed);

    // Destroy
    passed += helpers.doTest("Destroy region", ipc.shared_mem.destroy(30, c1.id) == .ok, &failed);
    passed += helpers.doTest("Region gone", ipc.shared_mem.findRegionByName("test_region") == null, &failed);

    // Stats
    const st = ipc.shared_mem.getStats();
    passed += helpers.doTest("Stats: created>0", st.total_created > 0, &failed);
    passed += helpers.doTest("Stats: writes>0", st.total_writes > 0, &failed);
    passed += helpers.doTest("Stats: reads>0", st.total_reads > 0, &failed);

    // Cleanup
    if (capability.isInitialized()) {
        capability.unregisterProcess(30);
        capability.unregisterProcess(40);
        capability.unregisterProcess(50);
    }

    helpers.printTestResults(passed, failed);
}
