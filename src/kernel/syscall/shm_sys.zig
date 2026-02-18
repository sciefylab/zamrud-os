//! Zamrud OS - Shared Memory Syscalls (SC4)
//! SYS_SHM_CREATE (210), SYS_SHM_ATTACH (211), SYS_SHM_DETACH (212),
//! SYS_SHM_DESTROY (213), SYS_SHM_WRITE (214), SYS_SHM_READ (215)

const numbers = @import("numbers.zig");
const process = @import("../proc/process.zig");
const shared_mem = @import("../ipc/shared_mem.zig");

// =============================================================================
// Dispatcher
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return switch (num) {
        numbers.SYS_SHM_CREATE => sysShmCreate(a1, a2, a3),
        numbers.SYS_SHM_ATTACH => sysShmAttach(a1, a2),
        numbers.SYS_SHM_DETACH => sysShmDetach(a1),
        numbers.SYS_SHM_DESTROY => sysShmDestroy(a1),
        numbers.SYS_SHM_WRITE => sysShmWrite(a1, a2, a3, a4),
        numbers.SYS_SHM_READ => sysShmRead(a1, a2, a3, a4),
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
// SYS_SHM_CREATE (210) — Create a named shared memory region
//   a1 = name_ptr (pointer to name string)
//   a2 = name_len
//   a3 = size (bytes, max 64KB)
//   Returns: region_id on success, negative error
// =============================================================================

fn sysShmCreate(name_ptr: u64, name_len_raw: u64, size_raw: u64) i64 {
    const pid = currentPid16();
    const name_len = @min(name_len_raw, shared_mem.MAX_NAME_LEN);
    const size: u32 = if (size_raw > shared_mem.MAX_REGION_SIZE)
        return numbers.EINVAL
    else if (size_raw == 0)
        return numbers.EINVAL
    else
        @intCast(size_raw & 0xFFFFFFFF);

    // Get name
    const name: []const u8 = if (name_ptr != 0 and name_len > 0) blk: {
        if (!validatePtr(name_ptr, name_len)) return numbers.EFAULT;
        break :blk @as([*]const u8, @ptrFromInt(name_ptr))[0..name_len];
    } else {
        return numbers.EINVAL; // name required
    };

    // Ensure initialized
    if (!shared_mem.isInitialized()) {
        shared_mem.init();
    }

    const result = shared_mem.create(pid, name, size);

    return switch (result.result) {
        .ok => @intCast(result.id),
        .no_cap => numbers.EPERM,
        .already_exists => numbers.EEXIST,
        .table_full => numbers.ENOMEM,
        .too_large => numbers.EINVAL,
        .process_limit => numbers.EAGAIN,
        .not_found => numbers.EIO,
        else => numbers.EIO,
    };
}

// =============================================================================
// SYS_SHM_ATTACH (211) — Attach to a shared memory region
//   a1 = region_id
//   a2 = perm (1=read_only, 2=read_write)
//   Returns: 0 on success, negative error
// =============================================================================

fn sysShmAttach(region_id_raw: u64, perm_raw: u64) i64 {
    const pid = currentPid16();
    const region_id: u16 = @truncate(region_id_raw);

    const perm: shared_mem.ShmPerm = switch (perm_raw) {
        1 => .read_only,
        2 => .read_write,
        else => return numbers.EINVAL,
    };

    if (!shared_mem.isInitialized()) return numbers.ENODEV;

    const result = shared_mem.attach(pid, region_id, perm);

    return mapShmResult(result);
}

// =============================================================================
// SYS_SHM_DETACH (212) — Detach from a shared memory region
//   a1 = region_id
//   Returns: 0 on success, negative error
// =============================================================================

fn sysShmDetach(region_id_raw: u64) i64 {
    const pid = currentPid16();
    const region_id: u16 = @truncate(region_id_raw);

    if (!shared_mem.isInitialized()) return numbers.ENODEV;

    const result = shared_mem.detach(pid, region_id);

    return mapShmResult(result);
}

// =============================================================================
// SYS_SHM_DESTROY (213) — Destroy a shared memory region (owner only)
//   a1 = region_id
//   Returns: 0 on success, negative error
// =============================================================================

fn sysShmDestroy(region_id_raw: u64) i64 {
    const pid = currentPid16();
    const region_id: u16 = @truncate(region_id_raw);

    if (!shared_mem.isInitialized()) return numbers.ENODEV;

    const result = shared_mem.destroy(pid, region_id);

    return mapShmResult(result);
}

// =============================================================================
// SYS_SHM_WRITE (214) — Write data to shared memory region
//   a1 = region_id
//   a2 = offset
//   a3 = data_ptr
//   a4 = data_len
//   Returns: bytes written on success, negative error
// =============================================================================

fn sysShmWrite(region_id_raw: u64, offset_raw: u64, data_ptr: u64, data_len: u64) i64 {
    const pid = currentPid16();
    const region_id: u16 = @truncate(region_id_raw);
    const offset: u32 = @intCast(offset_raw & 0xFFFFFFFF);
    const len = @min(data_len, shared_mem.MAX_REGION_SIZE);

    if (data_ptr == 0 and len > 0) return numbers.EFAULT;
    if (len > 0 and !validatePtr(data_ptr, len)) return numbers.EFAULT;

    if (!shared_mem.isInitialized()) return numbers.ENODEV;

    const data: []const u8 = if (len > 0)
        @as([*]const u8, @ptrFromInt(data_ptr))[0..len]
    else
        &[_]u8{};

    const result = shared_mem.writeData(pid, region_id, offset, data);

    return switch (result.result) {
        .ok => @intCast(result.written),
        .not_found => numbers.EBADF,
        .not_attached => numbers.EACCES,
        .permission_denied => numbers.EPERM,
        .region_locked => numbers.EBUSY,
        .out_of_bounds => numbers.EINVAL,
        else => numbers.EIO,
    };
}

// =============================================================================
// SYS_SHM_READ (215) — Read data from shared memory region
//   a1 = region_id
//   a2 = offset
//   a3 = buf_ptr
//   a4 = buf_len
//   Returns: bytes read on success, negative error
// =============================================================================

fn sysShmRead(region_id_raw: u64, offset_raw: u64, buf_ptr: u64, buf_len: u64) i64 {
    const pid = currentPid16();
    const region_id: u16 = @truncate(region_id_raw);
    const offset: u32 = @intCast(offset_raw & 0xFFFFFFFF);
    const len = @min(buf_len, shared_mem.MAX_REGION_SIZE);

    if (buf_ptr == 0) return numbers.EFAULT;
    if (!validatePtr(buf_ptr, len)) return numbers.EFAULT;

    if (!shared_mem.isInitialized()) return numbers.ENODEV;

    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    const result = shared_mem.readData(pid, region_id, offset, buf[0..len]);

    return switch (result.result) {
        .ok => @intCast(result.bytes_read),
        .not_found => numbers.EBADF,
        .not_attached => numbers.EACCES,
        .permission_denied => numbers.EPERM,
        .out_of_bounds => numbers.EINVAL,
        else => numbers.EIO,
    };
}

// =============================================================================
// ShmResult → errno mapper
// =============================================================================

fn mapShmResult(result: shared_mem.ShmResult) i64 {
    return switch (result) {
        .ok => numbers.SUCCESS,
        .no_cap => numbers.EPERM,
        .not_found => numbers.EBADF,
        .already_exists => numbers.EEXIST,
        .table_full => numbers.ENOMEM,
        .too_large => numbers.EINVAL,
        .not_owner => numbers.EPERM,
        .not_attached => numbers.EACCES,
        .already_attached => numbers.EEXIST,
        .attach_full => numbers.EAGAIN,
        .permission_denied => numbers.EPERM,
        .region_locked => numbers.EBUSY,
        .process_limit => numbers.EAGAIN,
        .out_of_bounds => numbers.EINVAL,
    };
}
