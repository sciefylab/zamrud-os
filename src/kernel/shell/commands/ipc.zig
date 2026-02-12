//! Zamrud OS - Shell Commands IPC
// F1: IPC Commands
const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const capability = @import("../../security/capability.zig");
const ipc = @import("../../ipc/ipc.zig");

pub fn cmdIpc(args: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }
    const parsed = helpers.parseArgs(args);
    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        shell.println("");
        shell.println("  === IPC STATUS (F1+F2) ===");
        shell.println("  -----------------------------");
        const ms = ipc.message.getStats();
        shell.print("  Mailboxes:    ");
        helpers.printDec(ipc.message.getMailboxCount());
        shell.newLine();
        shell.print("  Msgs sent:    ");
        helpers.printDec64(ms.total_sent);
        shell.newLine();
        shell.print("  Msgs recv:    ");
        helpers.printDec64(ms.total_received);
        shell.newLine();
        const ps = ipc.pipe.getStats();
        shell.println("  -----------------------------");
        shell.print("  Pipes active: ");
        helpers.printDec(ipc.pipe.getActivePipeCount());
        shell.newLine();
        shell.print("  Pipe bytes W: ");
        helpers.printDec64(ps.total_bytes_written);
        shell.newLine();
        shell.print("  Pipe bytes R: ");
        helpers.printDec64(ps.total_bytes_read);
        shell.newLine();
        const ss = ipc.signal.getStats();
        shell.println("  -----------------------------");
        shell.print("  Sig procs:    ");
        helpers.printDec(ipc.signal.getRegisteredCount());
        shell.newLine();
        shell.print("  Sigs sent:    ");
        helpers.printDec64(ss.total_sent);
        shell.newLine();
        const shm = ipc.shared_mem.getStats();
        shell.println("  -----------------------------");
        shell.print("  Shm regions:  ");
        helpers.printDec(ipc.shared_mem.getActiveRegionCount());
        shell.newLine();
        shell.print("  Shm created:  ");
        helpers.printDec64(shm.total_created);
        shell.newLine();
        shell.print("  Shm bytes W:  ");
        helpers.printDec64(shm.bytes_written);
        shell.newLine();
        shell.print("  Shm bytes R:  ");
        helpers.printDec64(shm.bytes_read);
        shell.newLine();
        shell.println("  -----------------------------");
        shell.println("");
    } else shell.println("  Usage: ipc [status]");
}

pub fn cmdMsgSend(args: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }
    const parsed = helpers.parseArgs(args);
    if (parsed.cmd.len == 0 or parsed.rest.len == 0) {
        shell.println("  Usage: msgsend <pid> <message>");
        return;
    }
    const pid = helpers.parseDec16(parsed.cmd) orelse {
        shell.println("  Invalid PID");
        return;
    };
    const result = ipc.message.send(0, pid, .data, parsed.rest);
    if (result == .ok) {
        shell.print("  Sent to pid=");
        helpers.printDec(pid);
        shell.newLine();
    } else if (result == .no_mailbox) shell.println("  No mailbox") else shell.println("  Send failed");
}

pub fn cmdMsgRecv(args: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }
    if (args.len == 0) {
        shell.println("  Usage: msgrecv <pid>");
        return;
    }
    const pid = helpers.parseDec16(args) orelse {
        shell.println("  Invalid PID");
        return;
    };
    var count: u32 = 0;
    while (count < 10) : (count += 1) {
        const result = ipc.message.recv(pid);
        if (!result.success) {
            shell.println("  (no access)");
            break;
        }
        if (result.message) |msg| {
            shell.print("  [");
            helpers.printDec(count);
            shell.print("] from=");
            helpers.printDec(msg.sender_pid);
            shell.print(" \"");
            shell.print(msg.getData());
            shell.println("\"");
        } else break;
    }
    if (count == 0) shell.println("  (no messages)");
}

pub fn cmdIpcTest(_: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }
    helpers.printTestHeader("F1 IPC SUBSYSTEM");
    var passed: u32 = 0;
    var failed: u32 = 0;
    passed += helpers.doTest("IPC initialized", ipc.isInitialized(), &failed);
    passed += helpers.doTest("Create mbox pid=10", ipc.message.createMailbox(10), &failed);
    passed += helpers.doTest("Create mbox pid=20", ipc.message.createMailbox(20), &failed);
    passed += helpers.doTest("Mailbox count>=2", ipc.message.getMailboxCount() >= 2, &failed);
    const s1 = ipc.message.send(0, 10, .data, "hello from kernel");
    passed += helpers.doTest("Send kernel->10", s1 == .ok, &failed);
    passed += helpers.doTest("Pending=1", ipc.message.pendingCount(10) == 1, &failed);
    const r1 = ipc.message.recv(10);
    passed += helpers.doTest("Recv success", r1.success, &failed);
    passed += helpers.doTest("Recv has msg", r1.message != null, &failed);
    passed += helpers.doTest("Pending=0", ipc.message.pendingCount(10) == 0, &failed);
    if (capability.isInitialized()) {
        _ = capability.registerProcess(10, capability.CAP_IPC);
        _ = capability.registerProcess(20, capability.CAP_IPC);
    }
    passed += helpers.doTest("Send 10->20", ipc.message.send(10, 20, .request, "ping") == .ok, &failed);
    passed += helpers.doTest("Broadcast", ipc.message.broadcast(0, .system, "bcast") >= 1, &failed);
    const pid = ipc.pipe.create(10, 20);
    passed += helpers.doTest("Create pipe", pid != null, &failed);
    if (pid) |p| {
        const wr = ipc.pipe.write(p, 10, "hello pipe");
        passed += helpers.doTest("Pipe write ok", wr.result == .ok, &failed);
        passed += helpers.doTest("Pipe wrote 10", wr.written == 10, &failed);
        passed += helpers.doTest("Pipe avail=10", ipc.pipe.available(p) == 10, &failed);
        var rbuf: [64]u8 = undefined;
        const rd = ipc.pipe.read(p, 20, &rbuf);
        passed += helpers.doTest("Pipe read ok", rd.result == .ok, &failed);
        passed += helpers.doTest("Pipe read 10", rd.bytes_read == 10, &failed);
        passed += helpers.doTest("Pipe empty", ipc.pipe.available(p) == 0, &failed);
        passed += helpers.doTest("Pipe close", ipc.pipe.close(p), &failed);
    }
    _ = ipc.signal.registerProcess(10);
    _ = ipc.signal.registerProcess(20);
    passed += helpers.doTest("Send SIGUSR1", ipc.signal.sendSignal(0, 10, ipc.signal.SIG_USR1) == .ok, &failed);
    passed += helpers.doTest("Sig pending", ipc.signal.hasPending(10), &failed);
    const con = ipc.signal.consumeNext(10);
    passed += helpers.doTest("Consume sig", con != null, &failed);
    if (con) |c| {
        passed += helpers.doTest("Sig=USR1", c.signal == ipc.signal.SIG_USR1, &failed);
    } else {
        passed += helpers.doTest("Sig=USR1", false, &failed);
    }
    passed += helpers.doTest("No pending", !ipc.signal.hasPending(10), &failed);
    passed += helpers.doTest("Block USR2", ipc.signal.blockSignal(10, ipc.signal.SIG_USR2), &failed);
    passed += helpers.doTest("USR2 blocked", ipc.signal.sendSignal(0, 10, ipc.signal.SIG_USR2) == .signal_blocked, &failed);
    passed += helpers.doTest("Cant block KILL", !ipc.signal.blockSignal(10, ipc.signal.SIG_KILL), &failed);
    ipc.cleanupProcess(10);
    ipc.cleanupProcess(20);
    if (capability.isInitialized()) {
        capability.unregisterProcess(10);
        capability.unregisterProcess(20);
    }
    helpers.printTestResults(passed, failed);
}
