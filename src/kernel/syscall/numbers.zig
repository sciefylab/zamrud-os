//! Zamrud OS - Syscall Numbers
//! Defines all system call numbers

// =============================================================================
// Core Syscalls (0-49)
// =============================================================================

pub const SYS_EXIT: usize = 0;
pub const SYS_READ: usize = 1;
pub const SYS_WRITE: usize = 2;
pub const SYS_OPEN: usize = 3;
pub const SYS_CLOSE: usize = 4;
pub const SYS_STAT: usize = 5;
pub const SYS_FSTAT: usize = 6;
pub const SYS_LSEEK: usize = 7;
pub const SYS_MMAP: usize = 8;
pub const SYS_MUNMAP: usize = 9;
pub const SYS_BRK: usize = 10;
pub const SYS_IOCTL: usize = 11;
pub const SYS_GETPID: usize = 20;
pub const SYS_GETUID: usize = 21;
pub const SYS_GETEUID: usize = 22;
pub const SYS_GETGID: usize = 23;
pub const SYS_GETEGID: usize = 24;
pub const SYS_GETCWD: usize = 30;
pub const SYS_CHDIR: usize = 31;
pub const SYS_TIME: usize = 40;
pub const SYS_NANOSLEEP: usize = 41;
pub const SYS_YIELD: usize = 42;

// =============================================================================
// Process Syscalls (50-99)
// =============================================================================

pub const SYS_FORK: usize = 50;
pub const SYS_EXEC: usize = 51;
pub const SYS_WAIT: usize = 52;
pub const SYS_WAITPID: usize = 53;
pub const SYS_KILL: usize = 54;
pub const SYS_SIGNAL: usize = 55;
pub const SYS_SIGACTION: usize = 56;
pub const SYS_SIGRETURN: usize = 57;

// =============================================================================
// Identity Syscalls (100-119)
// =============================================================================

pub const SYS_IDENTITY_CREATE: usize = 100;
pub const SYS_IDENTITY_DELETE: usize = 101;
pub const SYS_IDENTITY_LIST: usize = 102;
pub const SYS_IDENTITY_GET: usize = 103;
pub const SYS_IDENTITY_GET_CURRENT: usize = 104;
pub const SYS_IDENTITY_SET_CURRENT: usize = 105;
pub const SYS_IDENTITY_UNLOCK: usize = 106;
pub const SYS_IDENTITY_LOCK: usize = 107;
pub const SYS_IDENTITY_IS_UNLOCKED: usize = 108;
pub const SYS_IDENTITY_SIGN: usize = 109;
pub const SYS_IDENTITY_VERIFY: usize = 110;
pub const SYS_IDENTITY_GET_ADDRESS: usize = 111;
pub const SYS_IDENTITY_GET_PUBKEY: usize = 112;

// Privacy
pub const SYS_PRIVACY_GET_MODE: usize = 115;
pub const SYS_PRIVACY_SET_MODE: usize = 116;

// Names
pub const SYS_NAME_REGISTER: usize = 117;
pub const SYS_NAME_LOOKUP: usize = 118;
pub const SYS_NAME_AVAILABLE: usize = 119;

// =============================================================================
// Integrity Syscalls (120-139)
// =============================================================================

pub const SYS_INTEGRITY_REGISTER: usize = 120;
pub const SYS_INTEGRITY_VERIFY: usize = 121;
pub const SYS_INTEGRITY_UNREGISTER: usize = 122;
pub const SYS_INTEGRITY_GET_HASH: usize = 123;
pub const SYS_INTEGRITY_STATUS: usize = 124;

// Quarantine
pub const SYS_QUARANTINE_ADD: usize = 130;
pub const SYS_QUARANTINE_REMOVE: usize = 131;
pub const SYS_QUARANTINE_LIST: usize = 132;
pub const SYS_QUARANTINE_CHECK: usize = 133;

// Monitor
pub const SYS_MONITOR_START: usize = 135;
pub const SYS_MONITOR_STOP: usize = 136;
pub const SYS_MONITOR_STATUS: usize = 137;

// =============================================================================
// Boot/Security Syscalls (140-159)
// =============================================================================

pub const SYS_BOOT_STATUS: usize = 140;
pub const SYS_BOOT_VERIFY: usize = 141;
pub const SYS_BOOT_GET_HASH: usize = 142;
pub const SYS_BOOT_GET_POLICY: usize = 143;
pub const SYS_BOOT_SET_POLICY: usize = 144;

// Security
pub const SYS_SECURITY_LEVEL: usize = 150;
pub const SYS_SECURITY_AUDIT: usize = 151;

// =============================================================================
// Crypto Syscalls (160-179)
// =============================================================================

pub const SYS_CRYPTO_HASH: usize = 160;
pub const SYS_CRYPTO_HMAC: usize = 161;
pub const SYS_CRYPTO_RANDOM: usize = 162;
pub const SYS_CRYPTO_SIGN: usize = 163;
pub const SYS_CRYPTO_VERIFY: usize = 164;
pub const SYS_CRYPTO_DERIVE_KEY: usize = 165;

// =============================================================================
// Chain/Blockchain Syscalls (180-199)
// =============================================================================

pub const SYS_CHAIN_STATUS: usize = 180;
pub const SYS_CHAIN_GET_HEIGHT: usize = 181;
pub const SYS_CHAIN_GET_BLOCK: usize = 182;
pub const SYS_CHAIN_SUBMIT_ENTRY: usize = 183;
pub const SYS_CHAIN_VERIFY_ENTRY: usize = 184;

// Authority
pub const SYS_AUTHORITY_IS_VALIDATOR: usize = 190;
pub const SYS_AUTHORITY_GET_VALIDATORS: usize = 191;

// =============================================================================
// Error Codes
// =============================================================================

pub const ESUCCESS: isize = 0;
pub const EPERM: isize = -1; // Operation not permitted
pub const ENOENT: isize = -2; // No such file or entry
pub const ESRCH: isize = -3; // No such process
pub const EINTR: isize = -4; // Interrupted
pub const EIO: isize = -5; // I/O error
pub const ENOMEM: isize = -12; // Out of memory
pub const EACCES: isize = -13; // Permission denied
pub const EFAULT: isize = -14; // Bad address
pub const EEXIST: isize = -17; // Already exists
pub const EINVAL: isize = -22; // Invalid argument
pub const ENOSYS: isize = -38; // Function not implemented
pub const ENOTSUP: isize = -95; // Not supported

// Identity specific errors
pub const EIDENT_NOTFOUND: isize = -100; // Identity not found
pub const EIDENT_EXISTS: isize = -101; // Identity already exists
pub const EIDENT_LOCKED: isize = -102; // Identity locked
pub const EIDENT_BADPIN: isize = -103; // Wrong PIN
pub const EIDENT_FULL: isize = -104; // Max identities reached
pub const EIDENT_INVALID: isize = -105; // Invalid identity data

// Integrity specific errors
pub const EINTEG_MISMATCH: isize = -110; // Hash mismatch
pub const EINTEG_NOTFOUND: isize = -111; // Not registered
pub const EINTEG_QUARANTINE: isize = -112; // File quarantined

// Boot specific errors
pub const EBOOT_UNVERIFIED: isize = -120; // Boot not verified
pub const EBOOT_TAMPERED: isize = -121; // Kernel tampered
