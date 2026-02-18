//! Zamrud OS - IPC Syscalls (SC3)
//! SYS_MSG_SEND, SYS_MSG_RECV, SYS_PIPE_CREATE,
//! SYS_PIPE_WRITE, SYS_PIPE_READ, SYS_SIG_SEND, SYS_SIG_MASK

const numbers = @import("numbers.zig");
const process = @import("../proc/process.zig");
const ipc = @import("../ipc/ipc.zig");
const message = ipc.message;
const pipe = ipc.pipe;
const signal = ipc.signal;

// =============================================================================
// Dispatcher
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return switch (num) {
        numbers.SYS_MSG_SEND => sysMsgSend(a1, a2, a3, a4),
        numbers.SYS_MSG_RECV => sysMsgRecv(a1, a2),
        numbers.SYS_PIPE_CREATE => sysPipeCreate(a1),
        numbers.SYS_PIPE_WRITE => sysPipeWrite(a1, a2, a3),
        numbers.SYS_PIPE_READ => sysPipeRead(a1, a2, a3),
        numbers.SYS_SIG_SEND => sysSigSend(a1, a2),
        numbers.SYS_SIG_MASK => sysSigMask(a1, a2),
        else => numbers.ENOSYS,
    };
}

// =============================================================================
// Pointer Validation
// =============================================================================

fn validatePtr(ptr: u64, len: u64) bool {
    if (ptr == 0) return false;
    if (len == 0) return true;
    const result = @addWithOverflow(ptr, len);
    return result[1] == 0;
}

fn currentPid16() u16 {
    return @truncate(process.getCurrentPid());
}

// =============================================================================
// SYS_MSG_SEND (200) — Send message to another process
//   a1 = receiver_pid
//   a2 = data_ptr
//   a3 = data_len
//   a4 = msg_type (0=data, 1=signal, 2=request, 3=reply, 4=broadcast)
//   Returns: 0 on success, negative error
// =============================================================================

fn sysMsgSend(receiver_raw: u64, data_ptr: u64, data_len: u64, msg_type_raw: u64) i64 {
    const sender = currentPid16();
    const receiver: u16 = @truncate(receiver_raw);
    const len = @min(data_len, message.MAX_MSG_DATA);

    if (data_ptr == 0 and len > 0) return numbers.EFAULT;
    if (len > 0 and !validatePtr(data_ptr, len)) return numbers.EFAULT;

    // Ensure receiver has a mailbox (auto-create)
    if (!message.hasMailbox(receiver)) {
        if (!message.createMailbox(receiver)) return numbers.ENOMEM;
    }

    // Get data slice
    const data: []const u8 = if (len > 0)
        @as([*]const u8, @ptrFromInt(data_ptr))[0..len]
    else
        &[_]u8{};

    // Map msg_type
    const msg_type: message.MsgType = switch (msg_type_raw) {
        0 => .data,
        1 => .signal,
        2 => .request,
        3 => .reply,
        4 => .broadcast,
        5 => .system,
        else => .data,
    };

    const result = message.send(sender, receiver, msg_type, data);

    return switch (result) {
        .ok => numbers.SUCCESS,
        .no_cap => numbers.EPERM,
        .no_mailbox => numbers.ESRCH,
        .mailbox_full => numbers.EAGAIN,
        .invalid_pid => numbers.EINVAL,
        .self_send => numbers.EINVAL,
        .killed => numbers.EPERM,
        .encrypt_failed => numbers.EIO,
    };
}

// =============================================================================
// SYS_MSG_RECV (201) — Receive message from mailbox
//   a1 = buf_ptr   (where to write message data, must be >= 64 bytes)
//   a2 = info_ptr  (optional, where to write sender_pid + msg_type, 8 bytes)
//   Returns: data_len on success, 0 if no message, negative error
// =============================================================================

fn sysMsgRecv(buf_ptr: u64, info_ptr: u64) i64 {
    const pid = currentPid16();

    // Ensure we have a mailbox
    if (!message.hasMailbox(pid)) {
        if (!message.createMailbox(pid)) return numbers.ENOMEM;
    }

    const result = message.recv(pid);

    if (!result.success) return numbers.EPERM;

    const msg = result.message orelse return 0; // no message pending

    // Copy data to user buffer
    if (buf_ptr != 0 and msg.data_len > 0) {
        if (!validatePtr(buf_ptr, msg.data_len)) return numbers.EFAULT;
        const buf: [*]u8 = @ptrFromInt(buf_ptr);
        for (0..msg.data_len) |i| {
            buf[i] = msg.data[i];
        }
    }

    // Write sender info if requested
    if (info_ptr != 0 and validatePtr(info_ptr, 8)) {
        const info: *MsgInfo = @ptrFromInt(info_ptr);
        info.sender_pid = msg.sender_pid;
        info.msg_type = @intFromEnum(msg.msg_type);
        info.msg_id = msg.msg_id;
        info._pad = 0;
    }

    return @intCast(msg.data_len);
}

const MsgInfo = extern struct {
    sender_pid: u16 = 0,
    msg_type: u8 = 0,
    _pad: u8 = 0,
    msg_id: u32 = 0,
};

// =============================================================================
// SYS_PIPE_CREATE (202) — Create a pipe
//   a1 = reader_pid (0 = self)
//   Returns: pipe_id on success, negative error
// =============================================================================

fn sysPipeCreate(reader_raw: u64) i64 {
    const writer = currentPid16();
    const reader: u16 = if (reader_raw == 0) writer else @truncate(reader_raw);

    const pipe_id = pipe.create(writer, reader) orelse {
        return numbers.ENOMEM;
    };

    return @intCast(pipe_id);
}

// =============================================================================
// SYS_PIPE_WRITE (203) — Write to pipe
//   a1 = pipe_id
//   a2 = data_ptr
//   a3 = data_len
//   Returns: bytes written on success, negative error
// =============================================================================

fn sysPipeWrite(pipe_id_raw: u64, data_ptr: u64, data_len: u64) i64 {
    const pid = currentPid16();
    const pipe_id: u16 = @truncate(pipe_id_raw);
    const len = @min(data_len, pipe.PIPE_BUF_SIZE);

    if (data_ptr == 0 and len > 0) return numbers.EFAULT;
    if (len > 0 and !validatePtr(data_ptr, len)) return numbers.EFAULT;

    const data: []const u8 = if (len > 0)
        @as([*]const u8, @ptrFromInt(data_ptr))[0..len]
    else
        &[_]u8{};

    const result = pipe.write(pipe_id, pid, data);

    return switch (result.result) {
        .ok => @intCast(result.written),
        .no_cap => numbers.EPERM,
        .pipe_full => numbers.EAGAIN,
        .pipe_closed => numbers.EPIPE,
        .not_found => numbers.EBADF,
        .not_owner => numbers.EPERM,
        .pipe_empty => numbers.EAGAIN,
        .table_full => numbers.ENOMEM,
    };
}

// =============================================================================
// SYS_PIPE_READ (204) — Read from pipe
//   a1 = pipe_id
//   a2 = buf_ptr
//   a3 = buf_len
//   Returns: bytes read on success, 0 if empty, negative error
// =============================================================================

fn sysPipeRead(pipe_id_raw: u64, buf_ptr: u64, buf_len: u64) i64 {
    const pid = currentPid16();
    const pipe_id: u16 = @truncate(pipe_id_raw);
    const len = @min(buf_len, pipe.PIPE_BUF_SIZE);

    if (buf_ptr == 0) return numbers.EFAULT;
    if (!validatePtr(buf_ptr, len)) return numbers.EFAULT;

    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    const result = pipe.read(pipe_id, pid, buf[0..len]);

    return switch (result.result) {
        .ok => @intCast(result.bytes_read),
        .no_cap => numbers.EPERM,
        .pipe_empty => 0,
        .pipe_closed => 0, // EOF
        .not_found => numbers.EBADF,
        .not_owner => numbers.EPERM,
        .pipe_full => numbers.EAGAIN,
        .table_full => numbers.ENOMEM,
    };
}

// =============================================================================
// SYS_SIG_SEND (205) — Send signal to process
//   a1 = target_pid
//   a2 = signal_number
//   Returns: 0 on success, negative error
// =============================================================================

fn sysSigSend(target_raw: u64, sig_raw: u64) i64 {
    const sender = currentPid16();
    const target: u16 = @truncate(target_raw);
    const sig: u8 = @truncate(sig_raw);

    if (sig > signal.MAX_SIGNAL) return numbers.EINVAL;

    // Auto-register sender and target
    _ = signal.registerProcess(sender);
    _ = signal.registerProcess(target);

    const result = signal.sendSignal(sender, target, sig);

    return switch (result) {
        .ok => numbers.SUCCESS,
        .no_cap => numbers.EPERM,
        .invalid_signal => numbers.EINVAL,
        .target_not_found => numbers.ESRCH,
        .signal_blocked => numbers.EAGAIN,
        .self_signal => numbers.EINVAL,
    };
}

// =============================================================================
// SYS_SIG_MASK (206) — Set signal mask
//   a1 = operation: 0=get, 1=block, 2=unblock, 3=set_mask
//   a2 = signal_number (for block/unblock) or mask_value (for set_mask)
//   Returns: current mask on get, 0 on success, negative error
// =============================================================================

fn sysSigMask(op: u64, value: u64) i64 {
    const pid = currentPid16();

    // Auto-register
    _ = signal.registerProcess(pid);

    switch (op) {
        // GET mask
        0 => return @intCast(signal.getSignalMask(pid)),

        // BLOCK signal
        1 => {
            const sig: u8 = @truncate(value);
            if (signal.blockSignal(pid, sig)) return numbers.SUCCESS;
            return numbers.EINVAL;
        },

        // UNBLOCK signal
        2 => {
            const sig: u8 = @truncate(value);
            if (signal.unblockSignal(pid, sig)) return numbers.SUCCESS;
            return numbers.EINVAL;
        },

        // SET full mask
        3 => {
            // Block each bit that's set
            const mask: u32 = @truncate(value);
            var s: u8 = 0;
            while (s <= signal.MAX_SIGNAL) : (s += 1) {
                if ((mask & (@as(u32, 1) << @intCast(s))) != 0) {
                    _ = signal.blockSignal(pid, s);
                } else {
                    _ = signal.unblockSignal(pid, s);
                }
            }
            return numbers.SUCCESS;
        },

        else => return numbers.EINVAL,
    }
}
