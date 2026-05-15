const std = @import("std");

pub fn build(b: *std.Build) void {
    // ========================================================================
    // Build Options
    // ========================================================================
    const with_ui = b.option(bool, "with_ui", "Enable UI/Graphics subsystem") orelse false;
    // 🆕 OPSI PRODUCTION (Default: false / Development Mode)
    const is_prod = b.option(bool, "prod", "Enable Strict Production Mode (Disables DevKey)") orelse false;

    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_model = .{ .explicit = &std.Target.x86.cpu.x86_64 },
    });

    const optimize = b.standardOptimizeOption(.{});

    // ========================================================================
    // Build-time Configuration (disuntikkan ke modul 'config' di Kernel)
    // ========================================================================
    const config = b.addOptions();
    config.addOption(bool, "enable_ui", with_ui);
    config.addOption(bool, "is_production", is_prod); // 🆕 Tersedia di Kernel sebagai config.is_production

    const kernel_mod = b.createModule(.{
        .root_source_file = b.path("src/kernel/main.zig"),
        .target = target,
        .optimize = optimize,
        .red_zone = false,
        .stack_check = false,
        .stack_protector = null,
        .pic = false,
        .code_model = .kernel,
        .single_threaded = true,
    });

    kernel_mod.addOptions("config", config);

    const kernel = b.addExecutable(.{
        .name = "kernel",
        .root_module = kernel_mod,
        .use_llvm = true,
        .use_lld = true,
    });

    kernel.entry = .{ .symbol_name = "kernel_main" };
    kernel.pie = false;
    kernel.want_lto = false;
    kernel.setLinkerScript(b.path("linker.ld"));

    b.installArtifact(kernel);

    // ========================================================================
    // Build Steps
    // ========================================================================
    const kernel_step = b.step("kernel", "Build the kernel");
    kernel_step.dependOn(&kernel.step);

    const iso_cmd = b.addSystemCommand(&[_][]const u8{
        "cmd", "/c", "scripts\\build\\build-iso.bat",
    });
    iso_cmd.step.dependOn(b.getInstallStep());

    const iso_step = b.step("iso", "Build bootable ISO image");
    iso_step.dependOn(&iso_cmd.step);

    const run_cmd = b.addSystemCommand(&[_][]const u8{
        "cmd", "/c", "scripts\\run\\run-qemu.bat",
    });
    run_cmd.step.dependOn(iso_step);

    const run_step = b.step("run", "Build ISO and run in QEMU");
    run_step.dependOn(&run_cmd.step);

    const run_direct_cmd = b.addSystemCommand(&[_][]const u8{
        "cmd", "/c", "scripts\\run\\run-direct.bat",
    });
    run_direct_cmd.step.dependOn(b.getInstallStep());

    const run_direct_step = b.step("run-direct", "Run with FAT drive");
    run_direct_step.dependOn(&run_direct_cmd.step);

    const clean_cmd = b.addSystemCommand(&[_][]const u8{
        "cmd",                                                                                                                    "/c",
        "if exist zig-out rmdir /s /q zig-out && if exist .zig-cache rmdir /s /q .zig-cache && if exist build rmdir /s /q build",
    });

    const clean_step = b.step("clean", "Clean build artifacts");
    clean_step.dependOn(&clean_cmd.step);

    // Print mode
    std.debug.print("\n========================================\n", .{});
    std.debug.print("[BUILD] Zamrud OS \n", .{});
    std.debug.print("========================================\n", .{});

    if (with_ui) {
        std.debug.print(" -> Subsystem: UI/Graphics\n", .{});
    } else {
        std.debug.print(" -> Subsystem: Server (No UI)\n", .{});
    }

    if (is_prod) {
        std.debug.print(" -> Env: PRODUCTION (DevKey REJECTED)\n", .{});
    } else {
        std.debug.print(" -> Env: DEVELOPMENT (DevKey ALLOWED)\n", .{});
    }
    std.debug.print("========================================\n\n", .{});
}
