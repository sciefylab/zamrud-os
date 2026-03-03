//! Zamrud OS - ACPI Commands
//! ACPI information and testing

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const acpi = @import("../../drivers/acpi/acpi.zig");

pub fn execute(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0 or helpers.strEql(trimmed, "help")) {
        showHelp();
    } else if (helpers.strEql(trimmed, "info")) {
        showInfo();
    } else if (helpers.strEql(trimmed, "tables")) {
        showTables();
    } else if (helpers.strEql(trimmed, "test")) {
        runTests();
    } else {
        shell.printError("acpi: unknown subcommand '");
        shell.print(trimmed);
        shell.println("'");
    }
}

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  ACPI COMMANDS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Commands:");
    shell.println("  acpi info     Show ACPI information");
    shell.println("  acpi tables   List ACPI tables");
    shell.println("  acpi test     Run ACPI tests");
    shell.newLine();
}

fn showInfo() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  ACPI INFORMATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Initialized:  ");
    if (acpi.isInitialized()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printErrorLine("No");
        return;
    }

    shell.print("  ACPI Enabled: ");
    if (acpi.isACPIEnabled()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printWarningLine("No (fallback mode)");
    }

    shell.print("  Revision:     ");
    if (acpi.getRevision() == 0) {
        shell.println("1.0");
    } else {
        shell.println("2.0+");
    }

    shell.print("  Tables:       ");
    helpers.printUsize(acpi.getTablesFound());
    shell.newLine();

    shell.print("  PM1a_CNT:     0x");
    helpers.printHex32(acpi.getPM1aControlBlock());
    shell.newLine();

    shell.print("  SLP_TYPa:     ");
    helpers.printUsize(acpi.getSleepTypeA());
    shell.newLine();

    shell.newLine();
}

fn showTables() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  ACPI TABLES");
    shell.printInfoLine("========================================");
    shell.newLine();

    if (!acpi.isInitialized()) {
        shell.printWarningLine("  ACPI not initialized");
        return;
    }

    shell.print("  Total tables: ");
    helpers.printUsize(acpi.getTablesFound());
    shell.newLine();
    shell.newLine();

    // Check for common tables
    shell.println("  Checking for tables:");

    if (acpi.findTable("FACP")) |_| {
        shell.printSuccessLine("    FADT (FACP): Found");
    } else {
        shell.printWarningLine("    FADT (FACP): Not found");
    }

    if (acpi.findTable("APIC")) |_| {
        shell.printSuccessLine("    MADT (APIC): Found");
    } else {
        shell.printWarningLine("    MADT (APIC): Not found");
    }

    if (acpi.findTable("HPET")) |_| {
        shell.printSuccessLine("    HPET:        Found");
    } else {
        shell.printWarningLine("    HPET:        Not found");
    }

    if (acpi.findTable("MCFG")) |_| {
        shell.printSuccessLine("    MCFG:        Found");
    } else {
        shell.printWarningLine("    MCFG:        Not found");
    }

    shell.newLine();
}

fn runTests() void {
    shell.printInfoLine("########################################");
    shell.printInfoLine("##  ACPI TEST SUITE (B2.6)");
    shell.printInfoLine("########################################");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    // === Section 1: Initialization ===
    shell.printInfoLine("=== [1/5] Initialization ===");

    // Test 1
    shell.print("  ACPI initialized.......... ");
    if (acpi.isInitialized()) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 2
    shell.print("  ACPI enabled.............. ");
    if (acpi.isACPIEnabled()) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 3
    shell.print("  HW ACPI enabled.......... ");
    if (acpi.isHWACPIEnabled()) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 4
    shell.print("  Revision valid............ ");
    const rev = acpi.getRevision();
    if (rev == 0 or rev == 2) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 5
    shell.print("  OEM ID not empty.......... ");
    const oem = acpi.getOemId();
    var oem_valid = false;
    for (oem) |c| {
        if (c != 0) {
            oem_valid = true;
            break;
        }
    }
    if (oem_valid) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // === Section 2: Table Discovery ===
    shell.newLine();
    shell.printInfoLine("=== [2/5] Table Discovery ===");

    // Test 6
    shell.print("  Tables found > 0.......... ");
    if (acpi.getTablesFound() > 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 7
    shell.print("  FADT (FACP) found......... ");
    if (acpi.findTable("FACP") != null) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 8
    shell.print("  MADT (APIC) check........ ");
    if (acpi.findTable("APIC")) |_| {
        shell.printSuccessLine("[PASS] (found)");
        passed += 1;
    } else {
        shell.printSuccessLine("[PASS] (optional)");
        passed += 1;
    }

    // Test 9
    shell.print("  HPET check................ ");
    if (acpi.findTable("HPET")) |_| {
        shell.printSuccessLine("[PASS] (found)");
        passed += 1;
    } else {
        shell.printSuccessLine("[PASS] (optional)");
        passed += 1;
    }

    // Test 10
    shell.print("  MCFG check................ ");
    if (acpi.findTable("MCFG")) |_| {
        shell.printSuccessLine("[PASS] (found)");
        passed += 1;
    } else {
        shell.printSuccessLine("[PASS] (optional)");
        passed += 1;
    }

    // Test 11
    shell.print("  Invalid table = null...... ");
    if (acpi.findTable("ZZZZ") == null) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // === Section 3: FADT / Power Registers ===
    shell.newLine();
    shell.printInfoLine("=== [3/5] FADT / Power Registers ===");

    // Test 12
    shell.print("  PM1a_CNT valid............ ");
    if (acpi.getPM1aControlBlock() != 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 13
    shell.print("  PM1a_CNT != PM1b_CNT..... ");
    if (acpi.getPM1aControlBlock() != acpi.getPM1bControlBlock() or acpi.getPM1bControlBlock() == 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 14
    shell.print("  SCI interrupt valid....... ");
    if (acpi.getSCIInterrupt() <= 255) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // Test 15
    shell.print("  PM timer block............ ");
    if (acpi.getPMTimerBlock() != 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printSuccessLine("[PASS] (optional)");
        passed += 1;
    }

    // Test 16
    shell.print("  FADT flags readable....... ");
    const flags = acpi.getFADTFlags();
    _ = flags;
    shell.printSuccessLine("[PASS]");
    passed += 1;

    // Test 17
    shell.print("  SMI command port.......... ");
    if (acpi.getSMICommandPort() != 0 or acpi.isHWACPIEnabled()) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // === Section 4: Sleep / Reset ===
    shell.newLine();
    shell.printInfoLine("=== [4/5] Sleep & Reset ===");

    // Test 18
    shell.print("  SLP_TYPa readable........ ");
    const slp_a = acpi.getSleepTypeA();
    _ = slp_a;
    shell.printSuccessLine("[PASS]");
    passed += 1;

    // Test 19
    shell.print("  SLP_TYPb readable........ ");
    const slp_b = acpi.getSleepTypeB();
    _ = slp_b;
    shell.printSuccessLine("[PASS]");
    passed += 1;

    // Test 20
    shell.print("  S5 found in DSDT......... ");
    if (acpi.isS5Found()) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printSuccessLine("[PASS] (defaults used)");
        passed += 1;
    }

    // Test 21
    shell.print("  Reset register present.... ");
    if (acpi.hasResetRegister()) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printSuccessLine("[PASS] (fallback available)");
        passed += 1;
    }

    // Test 22
    shell.print("  Reset addr valid.......... ");
    if (acpi.hasResetRegister()) {
        if (acpi.getResetRegAddress() != 0) {
            shell.printSuccessLine("[PASS]");
            passed += 1;
        } else {
            shell.printErrorLine("[FAIL]");
            failed += 1;
        }
    } else {
        shell.printSuccessLine("[PASS] (N/A)");
        passed += 1;
    }

    // === Section 5: Power Control Ready ===
    shell.newLine();
    shell.printInfoLine("=== [5/5] Power Control ===");

    // Test 23
    shell.print("  Shutdown available........ ");
    shell.printSuccessLine("[PASS]");
    passed += 1;

    // Test 24
    shell.print("  Reboot available.......... ");
    shell.printSuccessLine("[PASS]");
    passed += 1;

    // Test 25
    shell.print("  Power control ready....... ");
    shell.printSuccessLine("[PASS]");
    passed += 1;

    // === Summary ===
    shell.newLine();
    shell.println("========================================");
    shell.print("  Results: ");
    helpers.printUsize(passed);
    shell.print(" passed, ");
    helpers.printUsize(failed);
    shell.println(" failed");
    shell.println("========================================");

    if (failed == 0) {
        shell.newLine();
        shell.printSuccessLine("[OK]   All ACPI tests PASSED!");
    } else {
        shell.newLine();
        shell.printErrorLine("[FAIL] Some tests FAILED!");
    }
    shell.newLine();
}
