//! Zamrud OS - Gateway Shell Commands
//! Commands for managing Gateway Bridge

const shell = @import("../shell.zig");
const gateway = @import("../../gateway/gateway.zig");
const helpers = @import("helpers.zig");

// =============================================================================
// Main Command Handler
// =============================================================================

pub fn execute(args: []const u8) void {
    if (args.len == 0) {
        showGatewayStatus();
        return;
    }

    const trimmed = helpers.trim(args);

    if (helpers.startsWith(trimmed, "status")) {
        showGatewayStatus();
    } else if (helpers.startsWith(trimmed, "services")) {
        listServices();
    } else if (helpers.startsWith(trimmed, "connections")) {
        listConnections();
    } else if (helpers.startsWith(trimmed, "stats")) {
        showStats();
    } else if (helpers.startsWith(trimmed, "register ")) {
        registerService(trimmed[9..]);
    } else if (helpers.startsWith(trimmed, "remove ")) {
        removeService(trimmed[7..]);
    } else if (helpers.startsWith(trimmed, "allow ")) {
        allowPeer(trimmed[6..]);
    } else if (helpers.startsWith(trimmed, "deny ")) {
        denyPeer(trimmed[5..]);
    } else if (helpers.startsWith(trimmed, "start")) {
        startGateway();
    } else if (helpers.startsWith(trimmed, "stop")) {
        stopGateway();
    } else if (helpers.startsWith(trimmed, "pause")) {
        pauseGateway();
    } else if (helpers.startsWith(trimmed, "lockdown")) {
        enableLockdown();
    } else if (helpers.startsWith(trimmed, "unlock")) {
        disableLockdown();
    } else if (helpers.startsWith(trimmed, "test")) {
        testGateway();
    } else if (helpers.startsWith(trimmed, "help")) {
        showHelp();
    } else {
        shell.println("Unknown gateway command. Type 'gateway help'");
    }
}

// =============================================================================
// Status Display
// =============================================================================

fn showGatewayStatus() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }

    const stats = gateway.getStats();

    shell.newLine();
    shell.println("=== Gateway Bridge Status ===");
    shell.newLine();

    shell.print("State: ");
    shell.println(switch (stats.state) {
        .stopped => "STOPPED",
        .starting => "STARTING",
        .running => "RUNNING",
        .paused => "PAUSED",
        .stopping => "STOPPING",
        .error_state => "ERROR",
        .lockdown => "LOCKDOWN",
    });

    shell.print("Lockdown: ");
    shell.println(if (stats.in_lockdown) "YES" else "NO");

    shell.print("Services: ");
    helpers.printUsize(stats.active_services);
    shell.print("/");
    helpers.printUsize(stats.total_services);
    shell.newLine();

    shell.print("Connections: ");
    helpers.printUsize(stats.active_connections);
    shell.newLine();

    shell.print("Requests: ");
    helpers.printU64(stats.total_requests);
    shell.newLine();

    shell.print("Success: ");
    helpers.printU64(stats.total_success);
    shell.newLine();

    shell.print("Denied: ");
    helpers.printU64(stats.total_denied);
    shell.newLine();

    shell.print("Errors: ");
    helpers.printU64(stats.total_errors);
    shell.newLine();

    shell.newLine();
}

// =============================================================================
// Service Management
// =============================================================================

fn listServices() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }

    const services = gateway.getServices();

    shell.newLine();
    shell.println("=== Registered Services ===");
    shell.newLine();

    if (services.len == 0) {
        shell.println("No services registered");
        shell.newLine();
        return;
    }

    shell.println("Name            | Type       | Port  | Active | Requests");
    shell.println("----------------|------------|-------|--------|----------");

    for (services) |svc| {
        if (svc.name_len == 0) continue;

        // Name
        var name_printed: usize = 0;
        for (svc.service_name[0..svc.name_len]) |c| {
            if (name_printed < 15) {
                shell.printChar(c);
                name_printed += 1;
            }
        }
        while (name_printed < 16) : (name_printed += 1) {
            shell.print(" ");
        }
        shell.print("| ");

        // Type
        const type_str = switch (svc.service_type) {
            .tcp => "TCP       ",
            .udp => "UDP       ",
            .http => "HTTP      ",
            .https => "HTTPS     ",
            .postgresql => "PostgreSQL",
            .mysql => "MySQL     ",
            .redis => "Redis     ",
            .mongodb => "MongoDB   ",
            .custom => "Custom    ",
        };
        shell.print(type_str);
        shell.print(" | ");

        // Port
        helpers.printU16Padded(svc.target_port, 5);
        shell.print(" | ");

        // Active
        if (svc.active) {
            shell.print("YES    ");
        } else {
            shell.print("NO     ");
        }
        shell.print("| ");

        // Requests
        helpers.printU64(svc.requests_total);
        shell.newLine();
    }

    shell.newLine();
}

fn registerService(args: []const u8) void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }

    shell.newLine();
    shell.println("=== Register Service ===");
    shell.newLine();
    shell.println("Usage: gateway register <name> <port> <type>");
    shell.newLine();
    shell.println("Types: tcp, udp, http, https, postgresql, mysql, redis, mongodb");
    shell.newLine();
    shell.println("Example: gateway register myhttp 8080 http");
    shell.newLine();
    _ = args;
}

fn removeService(args: []const u8) void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }

    const name = helpers.trim(args);

    if (name.len == 0) {
        shell.println("Usage: gateway remove <service_name>");
        return;
    }

    if (gateway.getServiceByName(name)) |service| {
        if (gateway.removeService(service.service_id)) {
            shell.print("Service removed: ");
            shell.println(name);
        } else {
            shell.println("Failed to remove service");
        }
    } else {
        shell.print("Service not found: ");
        shell.println(name);
    }
}

fn allowPeer(args: []const u8) void {
    shell.println("Usage: gateway allow <service_name> <peer_id_hex>");
    _ = args;
}

fn denyPeer(args: []const u8) void {
    shell.println("Usage: gateway deny <service_name> <peer_id_hex>");
    _ = args;
}

// =============================================================================
// Gateway Control
// =============================================================================

fn startGateway() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }
    gateway.start();
    shell.println("Gateway started");
}

fn stopGateway() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }
    gateway.stop();
    shell.println("Gateway stopped");
}

fn pauseGateway() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }
    gateway.pause();
    shell.println("Gateway paused");
}

fn enableLockdown() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }
    gateway.enterLockdown();
    shell.newLine();
    shell.println("=== GATEWAY LOCKDOWN ENABLED ===");
    shell.println("All incoming requests will be blocked.");
    shell.println("Use 'gateway unlock' to disable.");
    shell.newLine();
}

fn disableLockdown() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }
    gateway.exitLockdown();
    shell.println("Gateway lockdown disabled");
}

// =============================================================================
// Connection Display
// =============================================================================

fn listConnections() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }

    const conns = gateway.getConnections();

    shell.newLine();
    shell.println("=== Active Connections ===");
    shell.newLine();

    var active_count: usize = 0;

    for (conns) |conn| {
        if (conn.state != .idle and conn.state != .closed) {
            active_count += 1;

            shell.print("Connection #");
            helpers.printU64(conn.id);
            shell.newLine();

            shell.print("  State: ");
            shell.println(switch (conn.state) {
                .idle => "IDLE",
                .connecting => "CONNECTING",
                .authenticating => "AUTH",
                .connected => "CONNECTED",
                .active => "ACTIVE",
                .closing => "CLOSING",
                .closed => "CLOSED",
                .error_state => "ERROR",
            });

            shell.print("  Bytes sent: ");
            helpers.printU64(conn.bytes_sent);
            shell.newLine();

            shell.print("  Bytes received: ");
            helpers.printU64(conn.bytes_received);
            shell.newLine();
        }
    }

    if (active_count == 0) {
        shell.println("No active connections");
    }

    shell.newLine();
}

// =============================================================================
// Statistics
// =============================================================================

fn showStats() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }

    const stats = gateway.getStats();

    shell.newLine();
    shell.println("=== Gateway Statistics ===");
    shell.newLine();

    shell.print("Total Requests: ");
    helpers.printU64(stats.total_requests);
    shell.newLine();

    shell.print("Successful: ");
    helpers.printU64(stats.total_success);
    shell.newLine();

    shell.print("Denied: ");
    helpers.printU64(stats.total_denied);
    shell.newLine();

    shell.print("Errors: ");
    helpers.printU64(stats.total_errors);
    shell.newLine();

    shell.print("Bytes In: ");
    helpers.printU64(stats.total_bytes_in);
    shell.newLine();

    shell.print("Bytes Out: ");
    helpers.printU64(stats.total_bytes_out);
    shell.newLine();

    shell.newLine();
}

// =============================================================================
// Test Gateway
// =============================================================================

fn testGateway() void {
    if (!gateway.isInitialized()) {
        shell.println("Gateway not initialized");
        return;
    }

    shell.newLine();
    shell.println("=== Gateway Test Suite ===");
    shell.newLine();

    // Test 1: Create a service
    shell.println("[TEST 1] Creating test service...");

    const test_owner_id: [32]u8 = [_]u8{0xBB} ** 32;

    if (gateway.registerHTTP("test-http", test_owner_id, 8888)) |service_id| {
        shell.println("  OK: Test service created");

        // Test 2: Unauthorized request
        shell.newLine();
        shell.println("[TEST 2] Testing unauthorized access...");

        const unauthorized_peer: [32]u8 = [_]u8{0xCC} ** 32;

        const test_request1 = gateway.GatewayRequest{
            .request_id = 1,
            .peer_id = unauthorized_peer,
            .service_id = service_id,
            .operation = .query,
            .payload = [_]u8{0} ** 4096,
            .payload_len = 0,
            .signature = [_]u8{0} ** 64,
            .timestamp = 0,
            .source_ip = 0,
            .nonce = 1,
        };

        const response1 = gateway.handleRequest(&test_request1);

        if (response1.status == .peer_not_allowed) {
            shell.println("  OK: Unauthorized peer correctly denied");
        } else {
            shell.print("  FAIL: Expected PEER_NOT_ALLOWED, got: ");
            printStatus(response1.status);
            shell.newLine();
        }

        // Test 3: Allow peer and retry
        shell.newLine();
        shell.println("[TEST 3] Allowing peer and retrying...");

        if (gateway.allowPeer(service_id, unauthorized_peer)) {
            shell.println("  OK: Peer allowed");

            // Use different nonce for second request
            const test_request2 = gateway.GatewayRequest{
                .request_id = 2,
                .peer_id = unauthorized_peer,
                .service_id = service_id,
                .operation = .query,
                .payload = [_]u8{0} ** 4096,
                .payload_len = 0,
                .signature = [_]u8{0} ** 64,
                .timestamp = 0,
                .source_ip = 0,
                .nonce = 2,
            };

            const response2 = gateway.handleRequest(&test_request2);

            if (response2.status == .success) {
                shell.println("  OK: Authorized request succeeded");
            } else if (response2.status == .signature_invalid) {
                shell.println("  OK: Request denied (signature required)");
            } else {
                shell.print("  INFO: Status = ");
                printStatus(response2.status);
                shell.newLine();
            }
        } else {
            shell.println("  FAIL: Failed to allow peer");
        }

        // Cleanup
        shell.newLine();
        shell.println("[CLEANUP] Removing test service...");
        if (gateway.removeService(service_id)) {
            shell.println("  OK: Test service removed");
        } else {
            shell.println("  FAIL: Failed to remove test service");
        }
    } else {
        shell.println("  FAIL: Failed to create test service");
    }

    shell.newLine();
    shell.println("=== Test Complete ===");
    shell.newLine();
}

fn printStatus(status: gateway.ResponseStatus) void {
    shell.print(switch (status) {
        .success => "SUCCESS",
        .failed => "FAILED",
        .denied => "DENIED",
        .timeout => "TIMEOUT",
        .service_unavailable => "UNAVAILABLE",
        .rate_limited => "RATE_LIMITED",
        .signature_invalid => "SIGNATURE_INVALID",
        .peer_not_allowed => "PEER_NOT_ALLOWED",
        .capability_denied => "CAPABILITY_DENIED",
        .firewall_blocked => "FIREWALL_BLOCKED",
        .replay_detected => "REPLAY_DETECTED",
        .timestamp_invalid => "TIMESTAMP_INVALID",
    });
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.newLine();
    shell.println("=== Gateway Commands ===");
    shell.newLine();
    shell.println("  gateway              - Show status");
    shell.println("  gateway status       - Show detailed status");
    shell.println("  gateway services     - List registered services");
    shell.println("  gateway connections  - List active connections");
    shell.println("  gateway stats        - Show statistics");
    shell.println("  gateway start        - Start gateway");
    shell.println("  gateway stop         - Stop gateway");
    shell.println("  gateway pause        - Pause gateway");
    shell.println("  gateway lockdown     - Enable security lockdown");
    shell.println("  gateway unlock       - Disable lockdown");
    shell.println("  gateway test         - Run gateway test");
    shell.println("  gateway help         - Show this help");
    shell.newLine();
}
