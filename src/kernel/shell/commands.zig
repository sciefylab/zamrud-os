//! Zamrud OS - Shell Commands Main Dispatcher
//! Phases A-F5.0 + T4.2 (Environment Variables)

const shell = @import("shell.zig");

const helpers = @import("commands/helpers.zig");
const system = @import("commands/system.zig");
const filesystem = @import("commands/filesystem.zig");
const device = @import("commands/device.zig");
const process_cmd = @import("commands/process.zig");
const crypto_cmd = @import("commands/crypto.zig");
const chain_cmd = @import("commands/chain.zig");
const integrity_cmd = @import("commands/integrity.zig");
const identity_cmd = @import("commands/identity.zig");
const syscall_cmd = @import("commands/syscall.zig");
const boot_cmd = @import("commands/boot.zig");
const power_cmd = @import("commands/power.zig");
const network_cmd = @import("commands/network.zig");
const p2p_cmd = @import("commands/p2p.zig");
const gateway_cmd = @import("commands/gateway.zig");
const security_cmd = @import("commands/security.zig");
const smoke_cmd = @import("commands/smoke.zig");
const disk_cmd = @import("commands/disk.zig");
const config_cmd = @import("commands/config.zig");
const netcap_cmd = @import("commands/net_capability.zig");
const ipc_cmd = @import("commands/ipc.zig");
const shmem_cmd = @import("commands/shmem.zig");
const vio_cmd = @import("commands/violation.zig");
const user_cmd = @import("commands/user.zig");
const encfs_cmd = @import("commands/encfs.zig");
const enc_int_cmd = @import("commands/enc_int.zig"); // F4.1
const sys_encrypt_cmd = @import("commands/sys_encrypt.zig"); // F4.2
const zam_cmd = @import("commands/zam.zig"); // F5.0
const mouse_cmd = @import("commands/mouse.zig");

// =============================================================================
// Command Execution
// =============================================================================

pub fn execute(input: []const u8) void {
    const parsed = helpers.parseArgs(input);
    const command = parsed.cmd;
    const args = parsed.rest;

    if (command.len == 0) return;

    // T4.2: Environment variable commands
    if (helpers.strEql(command, "set")) {
        system.cmdSet(args);
    } else if (helpers.strEql(command, "unset")) {
        system.cmdUnset(args);
    } else if (helpers.strEql(command, "env")) {
        system.cmdEnv(args);
    } else if (helpers.strEql(command, "export")) {
        system.cmdExport(args);
    } else if (helpers.strEql(command, "printenv")) {
        system.cmdPrintenv(args);
    }
    // System commands
    else if (helpers.strEql(command, "help")) {
        system.cmdHelp(args);
    } else if (helpers.strEql(command, "clear")) {
        system.cmdClear(args);
    } else if (helpers.strEql(command, "info")) {
        system.cmdInfo(args);
    } else if (helpers.strEql(command, "uptime")) {
        system.cmdUptime(args);
    } else if (helpers.strEql(command, "mem") or helpers.strEql(command, "memory")) {
        system.cmdMemory(args);
    } else if (helpers.strEql(command, "history")) {
        system.cmdHistory(args);
    } else if (helpers.strEql(command, "echo")) {
        system.cmdEcho(args);
    } else if (helpers.strEql(command, "theme")) {
        system.cmdTheme(args);
    }
    // Filesystem
    else if (helpers.strEql(command, "ls")) {
        filesystem.cmdLs(args);
    } else if (helpers.strEql(command, "cd")) {
        filesystem.cmdCd(args);
    } else if (helpers.strEql(command, "pwd")) {
        filesystem.cmdPwd(args);
    } else if (helpers.strEql(command, "mkdir")) {
        filesystem.cmdMkdir(args);
    } else if (helpers.strEql(command, "touch")) {
        filesystem.cmdTouch(args);
    } else if (helpers.strEql(command, "rm")) {
        filesystem.cmdRm(args);
    } else if (helpers.strEql(command, "rmdir")) {
        filesystem.cmdRmdir(args);
    } else if (helpers.strEql(command, "cat")) {
        filesystem.cmdCat(args);
    } else if (helpers.strEql(command, "write")) {
        filesystem.cmdWrite(args);
    }
    // Device
    else if (helpers.strEql(command, "lsdev")) {
        device.cmdLsDev(args);
    } else if (helpers.strEql(command, "devtest")) {
        device.cmdDevTest(args);
    }
    // Disk
    else if (helpers.strEql(command, "disk")) {
        disk_cmd.execute(args);
    } else if (helpers.strEql(command, "diskinfo")) {
        disk_cmd.execute("list");
    }
    // Config (D3)
    else if (helpers.strEql(command, "config")) {
        config_cmd.execute(args);
    }
    // Process
    else if (helpers.strEql(command, "ps")) {
        process_cmd.cmdPs(args);
    } else if (helpers.strEql(command, "spawn")) {
        process_cmd.cmdSpawn(args);
    } else if (helpers.strEql(command, "kill")) {
        process_cmd.cmdKill(args);
    } else if (helpers.strEql(command, "sched")) {
        process_cmd.cmdSched(args);
    } else if (helpers.strEql(command, "sched-enable")) {
        process_cmd.cmdSchedEnable(args);
    } else if (helpers.strEql(command, "sched-disable")) {
        process_cmd.cmdSchedDisable(args);
    }
    // E3.1: Capability
    else if (helpers.strEql(command, "caps")) {
        process_cmd.cmdCaps(args);
    } else if (helpers.strEql(command, "grant")) {
        process_cmd.cmdGrant(args);
    } else if (helpers.strEql(command, "revoke")) {
        process_cmd.cmdRevoke(args);
    } else if (helpers.strEql(command, "violations")) {
        process_cmd.cmdViolations(args);
    } else if (helpers.strEql(command, "sandbox")) {
        process_cmd.cmdSpawnSandbox(args);
    }
    // E3.2: Unveil
    else if (helpers.strEql(command, "unveil")) {
        process_cmd.cmdUnveil(args);
    } else if (helpers.strEql(command, "paths")) {
        process_cmd.cmdPaths(args);
    } else if (helpers.strEql(command, "sandbox-fs")) {
        process_cmd.cmdSandboxFs(args);
    }
    // E3.3: Binary Verification
    else if (helpers.strEql(command, "verify")) {
        process_cmd.cmdVerifyBin(args);
    } else if (helpers.strEql(command, "trust")) {
        process_cmd.cmdTrust(args);
    } else if (helpers.strEql(command, "untrust")) {
        process_cmd.cmdUntrust(args);
    } else if (helpers.strEql(command, "trusted")) {
        process_cmd.cmdTrusted(args);
    }
    // E3.4: Network Capability
    else if (helpers.strEql(command, "netcap")) {
        netcap_cmd.cmdNetcap(args);
    } else if (helpers.strEql(command, "netprocs")) {
        netcap_cmd.cmdNetprocs(args);
    } else if (helpers.strEql(command, "netsockets")) {
        netcap_cmd.cmdNetsockets(args);
    } else if (helpers.strEql(command, "netallow")) {
        netcap_cmd.cmdNetallow(args);
    } else if (helpers.strEql(command, "netdeny")) {
        netcap_cmd.cmdNetdeny(args);
    } else if (helpers.strEql(command, "netrevoke")) {
        netcap_cmd.cmdNetrevoke(args);
    } else if (helpers.strEql(command, "netrestrict")) {
        netcap_cmd.cmdNetrestrict(args);
    } else if (helpers.strEql(command, "netreset")) {
        netcap_cmd.cmdNetreset(args);
    } else if (helpers.strEql(command, "netviolations")) {
        netcap_cmd.cmdNetviolations(args);
    } else if (helpers.strEql(command, "netreg")) {
        netcap_cmd.cmdNetreg(args);
    } else if (helpers.strEql(command, "nettest")) {
        netcap_cmd.cmdNettest(args);
    }
    // E3.5: Violation Handler
    else if (helpers.strEql(command, "audit")) {
        vio_cmd.cmdAudit(args);
    } else if (helpers.strEql(command, "escalation")) {
        vio_cmd.cmdEscalation(args);
    } else if (helpers.strEql(command, "sectest")) {
        vio_cmd.cmdSectest(args);
    }
    // F1: IPC
    else if (helpers.strEql(command, "ipc")) {
        ipc_cmd.cmdIpc(args);
    } else if (helpers.strEql(command, "msgsend")) {
        ipc_cmd.cmdMsgSend(args);
    } else if (helpers.strEql(command, "msgrecv")) {
        ipc_cmd.cmdMsgRecv(args);
    } else if (helpers.strEql(command, "ipctest")) {
        ipc_cmd.cmdIpcTest(args);
    }
    // F2: Shared Memory
    else if (helpers.strEql(command, "shmem")) {
        shmem_cmd.cmdShmem(args);
    } else if (helpers.strEql(command, "shmtest")) {
        shmem_cmd.cmdShmTest(args);
    }
    // F3: User/Group
    else if (helpers.strEql(command, "login")) {
        user_cmd.cmdLogin(args);
    } else if (helpers.strEql(command, "logout")) {
        user_cmd.cmdLogout(args);
    } else if (helpers.strEql(command, "whoami")) {
        user_cmd.cmdWhoami(args);
    } else if (helpers.strEql(command, "id")) {
        user_cmd.cmdId(args);
    } else if (helpers.strEql(command, "su")) {
        user_cmd.cmdSu(args);
    } else if (helpers.strEql(command, "sudo")) {
        user_cmd.cmdSudo(args);
    } else if (helpers.strEql(command, "sudoend")) {
        user_cmd.cmdSudoEnd(args);
    } else if (helpers.strEql(command, "user")) {
        user_cmd.execute(args);
    } else if (helpers.strEql(command, "usertest")) {
        user_cmd.execute("test");
    }
    // F4: Encrypted Filesystem
    else if (helpers.strEql(command, "encfs")) {
        encfs_cmd.execute(args);
    } else if (helpers.strEql(command, "encrypt")) {
        encfs_cmd.cmdEncrypt(args);
    } else if (helpers.strEql(command, "decrypt")) {
        encfs_cmd.cmdDecrypt(args);
    } else if (helpers.strEql(command, "enckey")) {
        encfs_cmd.cmdEncKey(args);
    } else if (helpers.strEql(command, "encdel")) {
        encfs_cmd.cmdEncDel(args);
    } else if (helpers.strEql(command, "enctest")) {
        encfs_cmd.cmdEncTest();
    }
    // F4.1: Encryption Integration
    else if (helpers.strEql(command, "encwho")) {
        enc_int_cmd.encWhoCommand(args);
    } else if (helpers.strEql(command, "encfiles")) {
        enc_int_cmd.encFilesCommand(args);
    } else if (helpers.strEql(command, "encinttest")) {
        enc_int_cmd.encIntTestCommand(args);
    }
    // F4.2: System Encryption
    else if (helpers.strEql(command, "sysenc")) {
        sys_encrypt_cmd.cmdSysEnc(args);
    } else if (helpers.strEql(command, "sysenctest")) {
        sys_encrypt_cmd.cmdSysEncTest(args);
    }
    // F5.0: ZAM Binary Loader
    else if (helpers.strEql(command, "zam")) {
        zam_cmd.execute(args);
    } else if (helpers.strEql(command, "zamtest")) {
        zam_cmd.cmdZamTest();
    } else if (helpers.strEql(command, "zaminfo")) {
        zam_cmd.execute("info");
    } else if (helpers.strEql(command, "elfinfo")) {
        zam_cmd.execute("elfinfo");
    } else if (helpers.strEql(command, "zamverify")) {
        zam_cmd.execute("verify");
    }
    // Crypto
    else if (helpers.strEql(command, "crypto")) {
        crypto_cmd.execute(args);
    }
    // Chain
    else if (helpers.strEql(command, "chain")) {
        chain_cmd.execute(args);
    }
    // Integrity
    else if (helpers.strEql(command, "integrity")) {
        integrity_cmd.execute(args);
    }
    // Identity
    else if (helpers.strEql(command, "identity")) {
        identity_cmd.execute(args);
    }
    // Network
    else if (helpers.strEql(command, "net")) {
        network_cmd.execute(args);
    } else if (helpers.strEql(command, "ifconfig") or helpers.strEql(command, "ip")) {
        network_cmd.cmdIfconfig(args);
    } else if (helpers.strEql(command, "ping")) {
        network_cmd.cmdPing(args);
    } else if (helpers.strEql(command, "netstat")) {
        network_cmd.cmdNetstat(args);
    } else if (helpers.strEql(command, "arp")) {
        network_cmd.cmdArp(args);
    } else if (helpers.strEql(command, "ntest")) {
        network_cmd.runTest("all");
    }
    // P2P
    else if (helpers.strEql(command, "p2p")) {
        p2p_cmd.execute(args);
    }
    // Gateway
    else if (helpers.strEql(command, "gateway") or helpers.strEql(command, "gw")) {
        gateway_cmd.execute(args);
    }
    // Security
    else if (helpers.strEql(command, "security")) {
        security_cmd.execute(args);
    } else if (helpers.strEql(command, "firewall")) {
        var buffer: [256]u8 = undefined;
        var len: usize = 0;
        const prefix = "firewall ";
        for (prefix) |c| {
            if (len < buffer.len) {
                buffer[len] = c;
                len += 1;
            }
        }
        for (args) |c| {
            if (len < buffer.len) {
                buffer[len] = c;
                len += 1;
            }
        }
        security_cmd.execute(buffer[0..len]);
    }
    // Smoke
    else if (helpers.strEql(command, "smoke")) {
        smoke_cmd.execute(args);
    }
    // Syscall
    else if (helpers.strEql(command, "syscall")) {
        syscall_cmd.execute(args);
    }
    // Boot
    else if (helpers.strEql(command, "boot")) {
        boot_cmd.execute(args);
    }
    // Power
    else if (helpers.strEql(command, "reboot")) {
        power_cmd.reboot();
    } else if (helpers.strEql(command, "shutdown") or helpers.strEql(command, "halt")) {
        power_cmd.shutdown();
    } else if (helpers.strEql(command, "exit")) {
        power_cmd.exit();
    } else if (helpers.strEql(command, "power")) {
        power_cmd.execute(args);
    }

    // In the dispatch function, add:
    else if (helpers.strEql(command, "mouse")) {
        mouse_cmd.execute(args);
    }
    // Test all
    else if (helpers.strEql(command, "testall")) {
        runAllTests();
    }
    // Unknown
    else {
        shell.printError("Unknown command: ");
        shell.print(command);
        shell.newLine();
        shell.println("  Type 'help' for available commands");
        shell.setLastExitSuccess(false);
    }
}

// =============================================================================
// Test All
// =============================================================================

fn runAllTests() void {
    helpers.printTestHeader("ZAMRUD OS - COMPLETE TEST SUITE");

    shell.printInfoLine("=== SMOKE TESTS ===");
    smoke_cmd.execute("run");
    shell.newLine();

    shell.printInfoLine("=== NETWORK TESTS ===");
    network_cmd.runTest("all");
    shell.newLine();

    shell.printInfoLine("=== P2P TESTS ===");
    p2p_cmd.runTest("all");
    shell.newLine();

    shell.printInfoLine("=== GATEWAY TESTS ===");
    gateway_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== SECURITY/FIREWALL TESTS ===");
    security_cmd.runTest("all");
    shell.newLine();

    shell.printInfoLine("=== CRYPTO TESTS ===");
    crypto_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== SYSCALL TESTS ===");
    syscall_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== BOOT TESTS ===");
    boot_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== DISK TESTS ===");
    disk_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== CONFIG PERSISTENCE TESTS ===");
    config_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== CAPABILITY TESTS (E3.1) ===");
    process_cmd.cmdCaps("test");
    shell.newLine();

    shell.printInfoLine("=== UNVEIL TESTS (E3.2) ===");
    process_cmd.cmdUnveil("test");
    shell.newLine();

    shell.printInfoLine("=== BINARY VERIFY TESTS (E3.3) ===");
    process_cmd.cmdVerifyBin("test");
    shell.newLine();

    shell.printInfoLine("=== NETWORK CAPABILITY TESTS (E3.4) ===");
    netcap_cmd.cmdNettest("");
    shell.newLine();

    shell.printInfoLine("=== VIOLATION HANDLER TESTS (E3.5) ===");
    vio_cmd.cmdSectest("");
    shell.newLine();

    shell.printInfoLine("=== IPC TESTS (F1) ===");
    ipc_cmd.cmdIpcTest("");
    shell.newLine();

    shell.printInfoLine("=== SHARED MEMORY TESTS (F2) ===");
    shmem_cmd.cmdShmTest("");
    shell.newLine();

    shell.printInfoLine("=== USER/GROUP TESTS (F3) ===");
    user_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== ENCRYPTED FS TESTS (F4.0) ===");
    encfs_cmd.cmdEncTest();
    shell.newLine();

    shell.printInfoLine("=== ENC INTEGRATION TESTS (F4.1) ===");
    enc_int_cmd.encIntTestCommand("");
    shell.newLine();

    shell.printInfoLine("=== SYSTEM ENCRYPTION TESTS (F4.2) ===");
    sys_encrypt_cmd.cmdSysEncTest("");
    shell.newLine();

    shell.printInfoLine("=== ZAM BINARY LOADER TESTS (F5.0) ===");
    zam_cmd.cmdZamTest();
    shell.newLine();

    // T4.2: Environment variable tests
    shell.printInfoLine("=== ENVIRONMENT VARIABLE TESTS (T4.2) ===");
    system.cmdEnvTest("");
    shell.newLine();

    shell.printInfoLine("########################################");
    shell.printInfoLine("##  COMPLETE TEST SUITE FINISHED      ##");
    shell.printInfoLine("########################################");
    shell.newLine();
}
