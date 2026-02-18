//! Zamrud OS - Syscall Numbers (UNIFIED)
//! Single source of truth for ALL syscall numbers.
//!
//! Layout:
//!   0-49    Core (POSIX-like)
//!   50-99   Process management
//!   100-119 Identity
//!   120-139 Integrity
//!   140-159 Boot/Security
//!   160-179 Crypto
//!   180-199 Chain/Blockchain
//!   200-209 IPC Messages
//!   210-219 Shared Memory
//!   220-229 User/Auth
//!   230-239 Process Extended
//!   240-249 Capability
//!   250-259 Network
//!   260-269 Encrypted FS
//!   270-279 ELF/Loader
//!   280-289 FS Extended
//!   300-319 Graphics/Framebuffer
//!   320-339 Input
//!   400-419 Zamrud Debug

// =============================================================================
// Core Syscalls (0-49) — POSIX-like
// =============================================================================

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 5;
pub const SYS_FSTAT: u64 = 6;
pub const SYS_LSEEK: u64 = 7;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_GETPID: u64 = 20;
pub const SYS_GETUID: u64 = 24;
pub const SYS_GETGID: u64 = 25;
pub const SYS_GETEUID: u64 = 26;
pub const SYS_GETEGID: u64 = 27;
pub const SYS_GETPPID: u64 = 28;
pub const SYS_GETCWD: u64 = 30;
pub const SYS_CHDIR: u64 = 31;
pub const SYS_MKDIR: u64 = 32;
pub const SYS_RMDIR: u64 = 33;
pub const SYS_UNLINK: u64 = 34;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_SCHED_YIELD: u64 = 42;
pub const SYS_EXIT: u64 = 60;

// =============================================================================
// Process Syscalls (50-99)
// =============================================================================

pub const SYS_FORK: u64 = 50;
pub const SYS_EXEC: u64 = 51;
pub const SYS_WAIT: u64 = 52;
pub const SYS_WAITPID: u64 = 53;
pub const SYS_KILL: u64 = 54;
pub const SYS_SIGNAL: u64 = 55;
pub const SYS_SIGACTION: u64 = 56;
pub const SYS_SIGRETURN: u64 = 57;

// =============================================================================
// Identity Syscalls (100-119) — Zamrud identity system
// =============================================================================

pub const SYS_IDENTITY_CREATE: u64 = 100;
pub const SYS_IDENTITY_DELETE: u64 = 101;
pub const SYS_IDENTITY_LIST: u64 = 102;
pub const SYS_IDENTITY_GET: u64 = 103;
pub const SYS_IDENTITY_GET_CURRENT: u64 = 104;
pub const SYS_IDENTITY_SET_CURRENT: u64 = 105;
pub const SYS_IDENTITY_UNLOCK: u64 = 106;
pub const SYS_IDENTITY_LOCK: u64 = 107;
pub const SYS_IDENTITY_IS_UNLOCKED: u64 = 108;
pub const SYS_IDENTITY_SIGN: u64 = 109;
pub const SYS_IDENTITY_VERIFY: u64 = 110;
pub const SYS_IDENTITY_GET_ADDRESS: u64 = 111;
pub const SYS_IDENTITY_GET_PUBKEY: u64 = 112;
pub const SYS_PRIVACY_GET_MODE: u64 = 115;
pub const SYS_PRIVACY_SET_MODE: u64 = 116;
pub const SYS_NAME_REGISTER: u64 = 117;
pub const SYS_NAME_LOOKUP: u64 = 118;
pub const SYS_NAME_AVAILABLE: u64 = 119;

// =============================================================================
// Integrity Syscalls (120-139)
// =============================================================================

pub const SYS_INTEGRITY_REGISTER: u64 = 120;
pub const SYS_INTEGRITY_VERIFY: u64 = 121;
pub const SYS_INTEGRITY_UNREGISTER: u64 = 122;
pub const SYS_INTEGRITY_GET_HASH: u64 = 123;
pub const SYS_INTEGRITY_STATUS: u64 = 124;
pub const SYS_QUARANTINE_ADD: u64 = 130;
pub const SYS_QUARANTINE_REMOVE: u64 = 131;
pub const SYS_QUARANTINE_LIST: u64 = 132;
pub const SYS_QUARANTINE_CHECK: u64 = 133;
pub const SYS_MONITOR_START: u64 = 135;
pub const SYS_MONITOR_STOP: u64 = 136;
pub const SYS_MONITOR_STATUS: u64 = 137;

// =============================================================================
// Boot/Security Syscalls (140-159)
// =============================================================================

pub const SYS_BOOT_STATUS: u64 = 140;
pub const SYS_BOOT_VERIFY: u64 = 141;
pub const SYS_BOOT_GET_HASH: u64 = 142;
pub const SYS_BOOT_GET_POLICY: u64 = 143;
pub const SYS_BOOT_SET_POLICY: u64 = 144;
pub const SYS_SECURITY_LEVEL: u64 = 150;
pub const SYS_SECURITY_AUDIT: u64 = 151;

// =============================================================================
// Crypto Syscalls (160-179)
// =============================================================================

pub const SYS_CRYPTO_HASH: u64 = 160;
pub const SYS_CRYPTO_HMAC: u64 = 161;
pub const SYS_CRYPTO_RANDOM: u64 = 162;
pub const SYS_CRYPTO_SIGN: u64 = 163;
pub const SYS_CRYPTO_VERIFY: u64 = 164;
pub const SYS_CRYPTO_DERIVE_KEY: u64 = 165;

// =============================================================================
// Chain/Blockchain Syscalls (180-199)
// =============================================================================

pub const SYS_CHAIN_STATUS: u64 = 180;
pub const SYS_CHAIN_GET_HEIGHT: u64 = 181;
pub const SYS_CHAIN_GET_BLOCK: u64 = 182;
pub const SYS_CHAIN_SUBMIT_ENTRY: u64 = 183;
pub const SYS_CHAIN_VERIFY_ENTRY: u64 = 184;
pub const SYS_AUTHORITY_IS_VALIDATOR: u64 = 190;
pub const SYS_AUTHORITY_GET_VALIDATORS: u64 = 191;

// =============================================================================
// IPC Syscalls (200-209)
// =============================================================================

pub const SYS_MSG_SEND: u64 = 200;
pub const SYS_MSG_RECV: u64 = 201;
pub const SYS_PIPE_CREATE: u64 = 202;
pub const SYS_PIPE_WRITE: u64 = 203;
pub const SYS_PIPE_READ: u64 = 204;
pub const SYS_SIG_SEND: u64 = 205;
pub const SYS_SIG_MASK: u64 = 206;

// =============================================================================
// Shared Memory Syscalls (210-219)
// =============================================================================

pub const SYS_SHM_CREATE: u64 = 210;
pub const SYS_SHM_ATTACH: u64 = 211;
pub const SYS_SHM_DETACH: u64 = 212;
pub const SYS_SHM_DESTROY: u64 = 213;
pub const SYS_SHM_WRITE: u64 = 214;
pub const SYS_SHM_READ: u64 = 215;

// =============================================================================
// User/Auth Syscalls (220-229)
// =============================================================================

pub const SYS_SETUID: u64 = 220;
pub const SYS_SETGID: u64 = 221;
pub const SYS_GET_USERNAME: u64 = 222;
pub const SYS_LOGIN: u64 = 223;
pub const SYS_LOGOUT: u64 = 224;

// =============================================================================
// Process Extended Syscalls (230-239)
// =============================================================================

pub const SYS_SPAWN: u64 = 230;
pub const SYS_PROC_KILL: u64 = 231;
pub const SYS_PROC_WAITPID: u64 = 232;
pub const SYS_PROC_YIELD: u64 = 233;
pub const SYS_GETPRIORITY: u64 = 234;
pub const SYS_SETPRIORITY: u64 = 235;

// =============================================================================
// Capability Syscalls (240-249)
// =============================================================================

pub const SYS_CAP_GET: u64 = 240;
pub const SYS_CAP_CHECK: u64 = 241;
pub const SYS_CAP_DROP: u64 = 242;

// =============================================================================
// Network Syscalls (250-259)
// =============================================================================

pub const SYS_SOCKET: u64 = 250;
pub const SYS_BIND: u64 = 251;
pub const SYS_LISTEN: u64 = 252;
pub const SYS_ACCEPT: u64 = 253;
pub const SYS_CONNECT: u64 = 254;
pub const SYS_SENDTO: u64 = 255;
pub const SYS_RECVFROM: u64 = 256;

// =============================================================================
// Encrypted FS Syscalls (260-269)
// =============================================================================

pub const SYS_ENC_WRITE: u64 = 260;
pub const SYS_ENC_READ: u64 = 261;
pub const SYS_ENC_SETKEY: u64 = 262;
pub const SYS_ENC_STATUS: u64 = 263;

// =============================================================================
// ELF/Loader Syscalls (270-279)
// =============================================================================

pub const SYS_EXEC_ELF: u64 = 270;
pub const SYS_EXEC_ZAM: u64 = 271;

// =============================================================================
// FS Extended Syscalls (280-289)
// =============================================================================

pub const SYS_FSTAT_PATH: u64 = 280;
pub const SYS_READDIR: u64 = 281;
pub const SYS_RENAME: u64 = 282;
pub const SYS_TRUNCATE: u64 = 283;
pub const SYS_SEEK: u64 = 284;

// =============================================================================
// Graphics/Framebuffer Syscalls (300-319)
// =============================================================================

pub const SYS_FB_GET_INFO: u64 = 300;
pub const SYS_FB_MAP: u64 = 301;
pub const SYS_FB_UNMAP: u64 = 302;
pub const SYS_FB_FLUSH: u64 = 303;
pub const SYS_CURSOR_SET_POS: u64 = 310;
pub const SYS_CURSOR_SET_VISIBLE: u64 = 311;
pub const SYS_CURSOR_SET_TYPE: u64 = 312;
pub const SYS_SCREEN_GET_ORIENTATION: u64 = 315;

// =============================================================================
// Input Syscalls (320-339)
// =============================================================================

pub const SYS_INPUT_POLL: u64 = 320;
pub const SYS_INPUT_WAIT: u64 = 321;
pub const SYS_INPUT_GET_TOUCH_CAPS: u64 = 325;

// =============================================================================
// Zamrud Debug Syscalls (400-419)
// =============================================================================

pub const SYS_DEBUG_PRINT: u64 = 400;
pub const SYS_GET_TICKS: u64 = 401;
pub const SYS_GET_UPTIME: u64 = 402;
pub const SYS_SYSCALL_COUNT: u64 = 403;
pub const SYS_SYSCALL_TEST: u64 = 410;

// =============================================================================
// Error Codes (unified, i64 for handler return)
// =============================================================================

pub const SUCCESS: i64 = 0;
pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EIO: i64 = -5;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EBUSY: i64 = -16;
pub const EEXIST: i64 = -17;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;
pub const ERANGE: i64 = -34;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;
pub const ENOTSUP: i64 = -95;
pub const EPIPE: i64 = -32;

// Identity errors
pub const EIDENT_NOTFOUND: i64 = -100;
pub const EIDENT_EXISTS: i64 = -101;
pub const EIDENT_LOCKED: i64 = -102;
pub const EIDENT_BADPIN: i64 = -103;
pub const EIDENT_FULL: i64 = -104;
pub const EIDENT_INVALID: i64 = -105;

// Integrity errors
pub const EINTEG_MISMATCH: i64 = -110;
pub const EINTEG_NOTFOUND: i64 = -111;
pub const EINTEG_QUARANTINE: i64 = -112;

// Boot errors
pub const EBOOT_UNVERIFIED: i64 = -120;
pub const EBOOT_TAMPERED: i64 = -121;

// =============================================================================
// Range helpers (for dispatcher routing)
// =============================================================================

pub fn isCoreSyscall(num: u64) bool {
    return num < 100 or num == SYS_EXIT;
}

pub fn isIdentitySyscall(num: u64) bool {
    return num >= 100 and num < 120;
}

pub fn isIntegritySyscall(num: u64) bool {
    return num >= 120 and num < 140;
}

pub fn isBootSyscall(num: u64) bool {
    return num >= 140 and num < 160;
}

pub fn isCryptoSyscall(num: u64) bool {
    return num >= 160 and num < 180;
}

pub fn isChainSyscall(num: u64) bool {
    return num >= 180 and num < 200;
}

pub fn isIpcSyscall(num: u64) bool {
    return num >= 200 and num < 210;
}

pub fn isShmSyscall(num: u64) bool {
    return num >= 210 and num < 220;
}

pub fn isUserSyscall(num: u64) bool {
    return num >= 220 and num < 230;
}

pub fn isProcExtSyscall(num: u64) bool {
    return num >= 230 and num < 240;
}

pub fn isCapSyscall(num: u64) bool {
    return num >= 240 and num < 250;
}

pub fn isNetSyscall(num: u64) bool {
    return num >= 250 and num < 260;
}

pub fn isEncFsSyscall(num: u64) bool {
    return num >= 260 and num < 270;
}

pub fn isLoaderSyscall(num: u64) bool {
    return num >= 270 and num < 280;
}

pub fn isFsExtSyscall(num: u64) bool {
    return num >= 280 and num < 290;
}

pub fn isGraphicsSyscall(num: u64) bool {
    return num >= 300 and num < 320;
}

pub fn isInputSyscall(num: u64) bool {
    return num >= 320 and num < 340;
}

pub fn isDebugSyscall(num: u64) bool {
    return num >= 400 and num < 420;
}
