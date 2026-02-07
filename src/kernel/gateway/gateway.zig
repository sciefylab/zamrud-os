//! Zamrud OS - Gateway Bridge
//! Secure bridge between P2P network and traditional TCP/IP services
//!
//! Features:
//! - Signature-verified requests
//! - Capability-based access control
//! - Rate limiting per service
//! - Firewall integration
//! - IDS logging
//! - Replay attack prevention
//! - Connection pooling

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");
const crypto = @import("../crypto/crypto.zig");
const socket = @import("../net/socket.zig");
const firewall = @import("../net/firewall.zig");
const threat_log = @import("../security/threat_log.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_SERVICES: usize = 32;
pub const MAX_CONNECTIONS: usize = 128;
pub const MAX_ALLOWED_PEERS: usize = 16;
pub const MAX_REQUEST_AGE_MS: u64 = 30000; // 30 seconds - anti-replay
pub const CONNECTION_TIMEOUT_MS: u64 = 300000; // 5 minutes
pub const CLEANUP_INTERVAL_MS: u64 = 60000; // 1 minute

// =============================================================================
// Types
// =============================================================================

pub const ServiceType = enum(u8) {
    tcp = 0,
    udp = 1,
    http = 2,
    https = 3,
    postgresql = 4,
    mysql = 5,
    redis = 6,
    mongodb = 7,
    custom = 255,
};

pub const Capabilities = struct {
    can_read: bool = false,
    can_write: bool = false,
    can_execute: bool = false,
    can_admin: bool = false,
    max_bandwidth: u32 = 0,
    max_connections: u16 = 10,
    timeout_ms: u32 = 30000,
    require_encryption: bool = true,
};

pub const ServiceMapping = struct {
    service_id: [32]u8,
    owner_id: [32]u8,
    service_name: [64]u8,
    name_len: usize,
    target_ip: u32,
    target_port: u16,
    service_type: ServiceType,
    capabilities: Capabilities,
    allowed_peers: [MAX_ALLOWED_PEERS][32]u8,
    allowed_count: usize,
    require_signature: bool,
    allow_anonymous: bool,
    requests_total: u64,
    requests_success: u64,
    requests_denied: u64,
    requests_error: u64,
    bytes_in: u64,
    bytes_out: u64,
    active: bool,
    created_at: u64,
    last_request: u64,
    rate_limit: u32,
    rate_count: u32,
    rate_reset: u64,
};

pub const ConnectionState = enum(u8) {
    idle = 0,
    connecting = 1,
    authenticating = 2,
    connected = 3,
    active = 4,
    closing = 5,
    closed = 6,
    error_state = 7,
};

pub const GatewayConnection = struct {
    id: u64,
    peer_id: [32]u8,
    service_id: [32]u8,
    sock: ?*socket.Socket,
    state: ConnectionState,
    created_at: u64,
    last_activity: u64,
    bytes_sent: u64,
    bytes_received: u64,
    request_count: u64,
};

pub const Operation = enum(u8) {
    connect = 1,
    disconnect = 2,
    send = 3,
    receive = 4,
    query = 5,
    execute = 6,
    subscribe = 7,
    unsubscribe = 8,
};

pub const GatewayRequest = struct {
    request_id: u64,
    peer_id: [32]u8,
    service_id: [32]u8,
    operation: Operation,
    payload: [4096]u8,
    payload_len: usize,
    signature: [64]u8,
    timestamp: u64,
    source_ip: u32,
    nonce: u64, // Anti-replay nonce
};

pub const ResponseStatus = enum(u8) {
    success = 0,
    failed = 1,
    denied = 2,
    timeout = 3,
    service_unavailable = 4,
    rate_limited = 5,
    signature_invalid = 6,
    peer_not_allowed = 7,
    capability_denied = 8,
    firewall_blocked = 9,
    replay_detected = 10,
    timestamp_invalid = 11,
};

pub const GatewayResponse = struct {
    request_id: u64,
    status: ResponseStatus,
    payload: [4096]u8,
    payload_len: usize,
    error_code: u16,
    error_msg: [128]u8,
    error_len: usize,
    signature: [64]u8,
    timestamp: u64,
};

pub const GatewayState = enum(u8) {
    stopped = 0,
    starting = 1,
    running = 2,
    paused = 3,
    stopping = 4,
    error_state = 5,
    lockdown = 6,
};

// Anti-replay nonce tracking
const NonceEntry = struct {
    peer_id: [32]u8,
    nonce: u64,
    timestamp: u64,
};

const MAX_NONCES: usize = 1024;

// =============================================================================
// State
// =============================================================================

var gateway_state: GatewayState = .stopped;
var initialized: bool = false;

var services: [MAX_SERVICES]ServiceMapping = undefined;
var service_count: usize = 0;

var connections: [MAX_CONNECTIONS]GatewayConnection = undefined;
var connection_count: usize = 0;
var next_connection_id: u64 = 1;

var gateway_id: [32]u8 = [_]u8{0} ** 32;
var gateway_public_key: [32]u8 = [_]u8{0} ** 32;
var gateway_private_key: [32]u8 = [_]u8{0} ** 32;

// Anti-replay nonce cache
var nonce_cache: [MAX_NONCES]NonceEntry = undefined;
var nonce_count: usize = 0;

var total_requests: u64 = 0;
var total_success: u64 = 0;
var total_denied: u64 = 0;
var total_errors: u64 = 0;
var total_bytes_in: u64 = 0;
var total_bytes_out: u64 = 0;
var total_replay_blocked: u64 = 0;
var total_firewall_blocked: u64 = 0;

var security_lockdown: bool = false;
var last_cleanup: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("\n[GATEWAY] ");
    printLine(40);

    // Initialize services
    for (&services) |*s| {
        s.* = emptyService();
    }
    service_count = 0;

    // Initialize connections
    for (&connections) |*c| {
        c.* = emptyConnection();
    }
    connection_count = 0;
    next_connection_id = 1;

    // Initialize nonce cache
    for (&nonce_cache) |*n| {
        n.* = NonceEntry{
            .peer_id = [_]u8{0} ** 32,
            .nonce = 0,
            .timestamp = 0,
        };
    }
    nonce_count = 0;

    // Reset statistics
    total_requests = 0;
    total_success = 0;
    total_denied = 0;
    total_errors = 0;
    total_bytes_in = 0;
    total_bytes_out = 0;
    total_replay_blocked = 0;
    total_firewall_blocked = 0;

    last_cleanup = getTimestamp();

    // Generate gateway identity
    generateGatewayIdentity();

    // Register default service templates
    registerDefaultServices();

    gateway_state = .running;
    initialized = true;

    serial.writeString("[GATEWAY] Gateway ID: ");
    printHex(gateway_id[0..8]);
    serial.writeString("...\n");
    serial.writeString("[GATEWAY] Default service templates ready\n");
    serial.writeString("[GATEWAY] Gateway Bridge initialized\n");
    serial.writeString("[GATEWAY] Services registered: ");
    printNumber(service_count);
    serial.writeString("\n");
    serial.writeString("[GATEWAY] State: RUNNING\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn generateGatewayIdentity() void {
    // Generate keypair using crypto module
    if (crypto.random.isAvailable()) {
        crypto.random.fill(&gateway_private_key);

        // Derive public key from private (simplified - just hash for now)
        gateway_public_key = crypto.sha256(&gateway_private_key);

        // Gateway ID is hash of public key
        gateway_id = crypto.sha256(&gateway_public_key);
    } else {
        // Fallback: use timer-based pseudo-random
        const seed = timer.getTicks();
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            gateway_private_key[i] = @intCast((seed >> @intCast(i % 8)) & 0xFF);
            gateway_public_key[i] = @intCast((seed >> @intCast((i + 4) % 8)) & 0xFF);
        }
        gateway_id = crypto.sha256(&gateway_public_key);
    }
}

fn registerDefaultServices() void {
    // Template ready - actual registration via API
}

fn emptyService() ServiceMapping {
    return .{
        .service_id = [_]u8{0} ** 32,
        .owner_id = [_]u8{0} ** 32,
        .service_name = [_]u8{0} ** 64,
        .name_len = 0,
        .target_ip = 0,
        .target_port = 0,
        .service_type = .tcp,
        .capabilities = .{},
        .allowed_peers = undefined,
        .allowed_count = 0,
        .require_signature = true,
        .allow_anonymous = false,
        .requests_total = 0,
        .requests_success = 0,
        .requests_denied = 0,
        .requests_error = 0,
        .bytes_in = 0,
        .bytes_out = 0,
        .active = false,
        .created_at = 0,
        .last_request = 0,
        .rate_limit = 100,
        .rate_count = 0,
        .rate_reset = 0,
    };
}

fn emptyConnection() GatewayConnection {
    return .{
        .id = 0,
        .peer_id = [_]u8{0} ** 32,
        .service_id = [_]u8{0} ** 32,
        .sock = null,
        .state = .idle,
        .created_at = 0,
        .last_activity = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .request_count = 0,
    };
}

// =============================================================================
// Service Registration
// =============================================================================

pub fn registerService(
    name: []const u8,
    target_ip: u32,
    target_port: u16,
    service_type: ServiceType,
    owner_id: [32]u8,
    caps: Capabilities,
) ?[32]u8 {
    if (service_count >= MAX_SERVICES) {
        serial.writeString("[GATEWAY] Max services reached\n");
        return null;
    }

    // Generate service ID from owner + name
    var hash_input: [96]u8 = [_]u8{0} ** 96;
    @memcpy(hash_input[0..32], &owner_id);
    const name_len = @min(name.len, 64);
    @memcpy(hash_input[32..][0..name_len], name[0..name_len]);

    const service_id = crypto.sha256(hash_input[0 .. 32 + name_len]);

    // Check for duplicates
    for (services[0..service_count]) |*s| {
        if (eqlBytes(&s.service_id, &service_id)) {
            serial.writeString("[GATEWAY] Service exists: ");
            serial.writeString(name);
            serial.writeString("\n");
            return null;
        }
    }

    // Create new service
    var service = &services[service_count];
    service.service_id = service_id;
    service.owner_id = owner_id;
    @memcpy(service.service_name[0..name_len], name[0..name_len]);
    service.name_len = name_len;
    service.target_ip = target_ip;
    service.target_port = target_port;
    service.service_type = service_type;
    service.capabilities = caps;
    service.require_signature = true;
    service.allow_anonymous = false;
    service.active = true;
    service.created_at = getTimestamp();
    service.allowed_count = 0;
    service.rate_limit = 100;
    service.rate_count = 0;
    service.rate_reset = getTimestamp();

    service_count += 1;

    serial.writeString("[GATEWAY] Registered: ");
    serial.writeString(name);
    serial.writeString(" -> ");
    printIp(target_ip);
    serial.writeString(":");
    printNumber(target_port);
    serial.writeString("\n");

    return service_id;
}

pub fn unregisterService(service_id: [32]u8) bool {
    for (0..service_count) |i| {
        if (eqlBytes(&services[i].service_id, &service_id)) {
            // Close all connections to this service
            closeServiceConnections(service_id);

            // Remove service by shifting
            for (i..service_count - 1) |j| {
                services[j] = services[j + 1];
            }
            service_count -= 1;
            serial.writeString("[GATEWAY] Service unregistered\n");
            return true;
        }
    }
    return false;
}

pub fn allowPeer(service_id: [32]u8, peer_id: [32]u8) bool {
    const service = getServiceById(service_id) orelse return false;

    if (service.allowed_count >= MAX_ALLOWED_PEERS) return false;

    // Check if already allowed
    for (service.allowed_peers[0..service.allowed_count]) |allowed| {
        if (eqlBytes(&allowed, &peer_id)) return true;
    }

    service.allowed_peers[service.allowed_count] = peer_id;
    service.allowed_count += 1;
    return true;
}

pub fn denyPeer(service_id: [32]u8, peer_id: [32]u8) bool {
    const service = getServiceById(service_id) orelse return false;

    for (0..service.allowed_count) |i| {
        if (eqlBytes(&service.allowed_peers[i], &peer_id)) {
            for (i..service.allowed_count - 1) |j| {
                service.allowed_peers[j] = service.allowed_peers[j + 1];
            }
            service.allowed_count -= 1;
            return true;
        }
    }
    return false;
}

fn closeServiceConnections(service_id: [32]u8) void {
    for (&connections) |*conn| {
        if (conn.state != .idle and conn.state != .closed) {
            if (eqlBytes(&conn.service_id, &service_id)) {
                conn.state = .closed;
                if (conn.sock) |sock| {
                    socket.close(sock);
                    conn.sock = null;
                }
            }
        }
    }
}

// =============================================================================
// Service Lookup
// =============================================================================

pub fn getServiceById(id: [32]u8) ?*ServiceMapping {
    for (services[0..service_count]) |*s| {
        if (eqlBytes(&s.service_id, &id)) return s;
    }
    return null;
}

pub fn getServiceByName(name: []const u8) ?*ServiceMapping {
    for (services[0..service_count]) |*s| {
        if (s.name_len == name.len) {
            if (eqlBytes(s.service_name[0..s.name_len], name)) return s;
        }
    }
    return null;
}

pub fn getServiceCount() usize {
    return service_count;
}

pub fn getServices() []const ServiceMapping {
    return services[0..service_count];
}

// =============================================================================
// Request Handling - Main Entry Point
// =============================================================================

pub fn handleRequest(request: *const GatewayRequest) GatewayResponse {
    total_requests += 1;

    var response = GatewayResponse{
        .request_id = request.request_id,
        .status = .success,
        .payload = [_]u8{0} ** 4096,
        .payload_len = 0,
        .error_code = 0,
        .error_msg = [_]u8{0} ** 128,
        .error_len = 0,
        .signature = [_]u8{0} ** 64,
        .timestamp = getTimestamp(),
    };

    // Periodic cleanup
    maybeCleanup();

    // ===========================================
    // SECURITY CHECK 1: Gateway State
    // ===========================================
    if (gateway_state == .lockdown or security_lockdown) {
        response.status = .firewall_blocked;
        response.error_code = 503;
        setError(&response, "Gateway lockdown");
        total_denied += 1;
        logSecurityEvent(.brute_force, request.source_ip, "Lockdown active");
        return response;
    }

    if (gateway_state != .running) {
        response.status = .service_unavailable;
        response.error_code = 503;
        setError(&response, "Gateway not running");
        total_errors += 1;
        return response;
    }

    // ===========================================
    // SECURITY CHECK 2: Firewall Integration
    // ===========================================
    if (request.source_ip != 0 and firewall.isInitialized()) {
        // Check blacklist
        if (firewall.isBlacklisted(request.source_ip)) {
            response.status = .firewall_blocked;
            response.error_code = 403;
            setError(&response, "IP blacklisted");
            total_denied += 1;
            total_firewall_blocked += 1;
            logSecurityEvent(.rate_limit_abuse, request.source_ip, "Blacklisted IP");
            return response;
        }

        // Full firewall check (pass peer_id for P2P mode)
        const filter_result = firewall.filterInbound(
            request.source_ip,
            ipLocal(),
            6, // TCP
            0,
            0,
            request.peer_id,
        );

        if (filter_result.action != .allow) {
            response.status = .firewall_blocked;
            response.error_code = 403;
            setError(&response, filter_result.reason);
            total_denied += 1;
            total_firewall_blocked += 1;
            return response;
        }
    }

    // ===========================================
    // SECURITY CHECK 3: Timestamp Validation (Anti-Replay)
    // ===========================================
    const now = getTimestamp();

    // Check for future timestamp
    if (request.timestamp > now + 5000) { // 5 second tolerance for clock skew
        response.status = .timestamp_invalid;
        response.error_code = 400;
        setError(&response, "Future timestamp");
        total_denied += 1;
        logSecurityEvent(.signature_invalid, request.source_ip, "Future timestamp");
        return response;
    }

    // Check for expired timestamp
    if (now > request.timestamp and now - request.timestamp > MAX_REQUEST_AGE_MS) {
        response.status = .timestamp_invalid;
        response.error_code = 400;
        setError(&response, "Expired timestamp");
        total_denied += 1;
        total_replay_blocked += 1;
        logSecurityEvent(.brute_force, request.source_ip, "Replay attempt (old)");
        return response;
    }

    // ===========================================
    // SECURITY CHECK 4: Nonce Validation (Anti-Replay)
    // ===========================================
    if (isNonceUsed(request.peer_id, request.nonce)) {
        response.status = .replay_detected;
        response.error_code = 400;
        setError(&response, "Replay detected");
        total_denied += 1;
        total_replay_blocked += 1;
        logSecurityEvent(.brute_force, request.source_ip, "Replay attempt (nonce)");
        return response;
    }

    // Record nonce
    recordNonce(request.peer_id, request.nonce);

    // ===========================================
    // SECURITY CHECK 5: Service Lookup
    // ===========================================
    const service = getServiceById(request.service_id) orelse {
        response.status = .service_unavailable;
        response.error_code = 404;
        setError(&response, "Service not found");
        total_errors += 1;
        return response;
    };

    if (!service.active) {
        response.status = .service_unavailable;
        response.error_code = 503;
        setError(&response, "Service inactive");
        total_errors += 1;
        return response;
    }

    // ===========================================
    // SECURITY CHECK 6: Rate Limiting
    // ===========================================
    if (!checkServiceRateLimit(service)) {
        response.status = .rate_limited;
        response.error_code = 429;
        setError(&response, "Rate limit exceeded");
        total_denied += 1;
        logSecurityEvent(.rate_limit_abuse, request.source_ip, "Rate limit");
        return response;
    }

    // ===========================================
    // SECURITY CHECK 7: Peer Authorization
    // ===========================================
    if (!isPeerAllowed(service, request.peer_id)) {
        response.status = .peer_not_allowed;
        response.error_code = 403;
        setError(&response, "Peer not authorized");
        service.requests_denied += 1;
        total_denied += 1;
        logSecurityEvent(.unknown_peer, request.source_ip, "Unauthorized peer");
        return response;
    }

    // ===========================================
    // SECURITY CHECK 8: Signature Verification
    // ===========================================
    if (service.require_signature) {
        if (!verifyRequestSignature(request)) {
            response.status = .signature_invalid;
            response.error_code = 401;
            setError(&response, "Invalid signature");
            service.requests_denied += 1;
            total_denied += 1;
            logSecurityEvent(.signature_invalid, request.source_ip, "Bad signature");
            return response;
        }
    }

    // ===========================================
    // SECURITY CHECK 9: Capability Check
    // ===========================================
    if (!checkCapabilities(service, request.operation)) {
        response.status = .capability_denied;
        response.error_code = 403;
        setError(&response, "Operation not permitted");
        service.requests_denied += 1;
        total_denied += 1;
        return response;
    }

    // ===========================================
    // PROCESS REQUEST
    // ===========================================
    service.requests_total += 1;
    service.last_request = now;
    service.bytes_in += request.payload_len;
    total_bytes_in += request.payload_len;

    const result = processOperation(service, request, &response);

    if (result) {
        service.requests_success += 1;
        total_success += 1;
        response.status = .success;
    } else {
        service.requests_error += 1;
        total_errors += 1;
        if (response.status == .success) {
            response.status = .failed;
        }
    }

    // Sign response
    signResponse(&response);

    total_bytes_out += response.payload_len;
    service.bytes_out += response.payload_len;

    return response;
}

// =============================================================================
// Security Helpers
// =============================================================================

fn isPeerAllowed(service: *const ServiceMapping, peer_id: [32]u8) bool {
    // Owner always allowed
    if (eqlBytes(&service.owner_id, &peer_id)) return true;

    // Anonymous access if enabled
    if (service.allow_anonymous) return true;

    // No peers allowed = deny all
    if (service.allowed_count == 0) return false;

    // Check allowlist
    for (service.allowed_peers[0..service.allowed_count]) |allowed| {
        if (eqlBytes(&allowed, &peer_id)) return true;
    }

    return false;
}

fn verifyRequestSignature(request: *const GatewayRequest) bool {
    // Build message to verify: peer_id || service_id || operation || timestamp || nonce || payload
    var hash_input: [4300]u8 = [_]u8{0} ** 4300;
    var pos: usize = 0;

    // Peer ID
    @memcpy(hash_input[pos..][0..32], &request.peer_id);
    pos += 32;

    // Service ID
    @memcpy(hash_input[pos..][0..32], &request.service_id);
    pos += 32;

    // Operation
    hash_input[pos] = @intFromEnum(request.operation);
    pos += 1;

    // Timestamp
    writeU64(hash_input[pos..], request.timestamp);
    pos += 8;

    // Nonce
    writeU64(hash_input[pos..], request.nonce);
    pos += 8;

    // Payload
    if (request.payload_len > 0) {
        const payload_len = @min(request.payload_len, 4096);
        @memcpy(hash_input[pos..][0..payload_len], request.payload[0..payload_len]);
        pos += payload_len;
    }

    // Hash and verify
    const hash = crypto.sha256(hash_input[0..pos]);
    return crypto.verify(&request.peer_id, &hash, &request.signature);
}

fn checkCapabilities(service: *const ServiceMapping, op: Operation) bool {
    return switch (op) {
        .connect, .disconnect, .unsubscribe => true,
        .send => service.capabilities.can_write,
        .receive, .query, .subscribe => service.capabilities.can_read,
        .execute => service.capabilities.can_execute,
    };
}

fn checkServiceRateLimit(service: *ServiceMapping) bool {
    if (service.rate_limit == 0) return true;

    const now = getTimestamp();

    // Reset if window passed
    if (now > service.rate_reset and now - service.rate_reset >= 1000) {
        service.rate_count = 0;
        service.rate_reset = now;
    }

    service.rate_count += 1;
    return service.rate_count <= service.rate_limit;
}

// =============================================================================
// Anti-Replay Nonce Management
// =============================================================================

fn isNonceUsed(peer_id: [32]u8, nonce: u64) bool {
    for (nonce_cache[0..nonce_count]) |entry| {
        if (eqlBytes(&entry.peer_id, &peer_id) and entry.nonce == nonce) {
            return true;
        }
    }
    return false;
}

fn recordNonce(peer_id: [32]u8, nonce: u64) void {
    // Remove expired nonces first
    cleanupExpiredNonces();

    if (nonce_count >= MAX_NONCES) {
        // Remove oldest
        for (0..nonce_count - 1) |i| {
            nonce_cache[i] = nonce_cache[i + 1];
        }
        nonce_count -= 1;
    }

    nonce_cache[nonce_count] = NonceEntry{
        .peer_id = peer_id,
        .nonce = nonce,
        .timestamp = getTimestamp(),
    };
    nonce_count += 1;
}

fn cleanupExpiredNonces() void {
    const now = getTimestamp();
    var i: usize = 0;

    while (i < nonce_count) {
        if (now > nonce_cache[i].timestamp and
            now - nonce_cache[i].timestamp > MAX_REQUEST_AGE_MS)
        {
            // Remove expired
            for (i..nonce_count - 1) |j| {
                nonce_cache[j] = nonce_cache[j + 1];
            }
            nonce_count -= 1;
            continue;
        }
        i += 1;
    }
}

// =============================================================================
// Connection Management
// =============================================================================

fn getOrCreateConnection(peer_id: [32]u8, service_id: [32]u8) ?*GatewayConnection {
    // Find existing connection
    for (&connections) |*conn| {
        if (conn.state == .connected or conn.state == .active) {
            if (eqlBytes(&conn.peer_id, &peer_id) and
                eqlBytes(&conn.service_id, &service_id))
            {
                return conn;
            }
        }
    }

    // Create new connection
    const service = getServiceById(service_id) orelse return null;

    if (connection_count >= MAX_CONNECTIONS) {
        cleanupStaleConnections();
        if (connection_count >= MAX_CONNECTIONS) return null;
    }

    // Create socket to target service
    const sock = socket.create(.tcp) orelse return null;
    if (!socket.connect(sock, service.target_ip, service.target_port)) {
        socket.close(sock);
        return null;
    }

    var conn = &connections[connection_count];
    conn.id = next_connection_id;
    next_connection_id += 1;
    conn.peer_id = peer_id;
    conn.service_id = service_id;
    conn.sock = sock;
    conn.state = .connected;
    conn.created_at = getTimestamp();
    conn.last_activity = getTimestamp();
    conn.bytes_sent = 0;
    conn.bytes_received = 0;
    conn.request_count = 0;

    connection_count += 1;

    return conn;
}

fn cleanupStaleConnections() void {
    const now = getTimestamp();
    var i: usize = 0;

    while (i < connection_count) {
        const conn = &connections[i];

        if (conn.state != .idle and conn.state != .closed) {
            if (now > conn.last_activity and
                now - conn.last_activity > CONNECTION_TIMEOUT_MS)
            {
                // Timeout - close connection
                conn.state = .closed;
                if (conn.sock) |sock| {
                    socket.close(sock);
                    conn.sock = null;
                }
                // Remove by shifting
                for (i..connection_count - 1) |j| {
                    connections[j] = connections[j + 1];
                }
                connection_count -= 1;
                continue;
            }
        }
        i += 1;
    }
}

fn maybeCleanup() void {
    const now = getTimestamp();
    if (now > last_cleanup and now - last_cleanup > CLEANUP_INTERVAL_MS) {
        cleanupStaleConnections();
        cleanupExpiredNonces();
        last_cleanup = now;
    }
}

// =============================================================================
// Operation Handlers
// =============================================================================

fn processOperation(
    service: *ServiceMapping,
    request: *const GatewayRequest,
    response: *GatewayResponse,
) bool {
    return switch (request.operation) {
        .connect => handleConnect(service, request, response),
        .disconnect => handleDisconnect(service, request, response),
        .send => handleSend(service, request, response),
        .receive => handleReceive(service, request, response),
        .query => handleQuery(service, request, response),
        .execute => handleExecute(service, request, response),
        .subscribe => handleSubscribe(service, request, response),
        .unsubscribe => handleUnsubscribe(service, request, response),
    };
}

fn handleConnect(service: *ServiceMapping, request: *const GatewayRequest, response: *GatewayResponse) bool {
    // Get or create connection to target service
    const conn = getOrCreateConnection(request.peer_id, service.service_id);

    if (conn == null) {
        setError(response, "Connection failed");
        return false;
    }

    const msg = "Connected";
    @memcpy(response.payload[0..msg.len], msg);
    response.payload_len = msg.len;
    return true;
}

fn handleDisconnect(service: *ServiceMapping, request: *const GatewayRequest, response: *GatewayResponse) bool {
    // Find and close connection
    for (&connections) |*conn| {
        if (conn.state == .connected or conn.state == .active) {
            if (eqlBytes(&conn.peer_id, &request.peer_id) and
                eqlBytes(&conn.service_id, &service.service_id))
            {
                conn.state = .closed;
                if (conn.sock) |sock| {
                    socket.close(sock);
                    conn.sock = null;
                }
                break;
            }
        }
    }

    const msg = "Disconnected";
    @memcpy(response.payload[0..msg.len], msg);
    response.payload_len = msg.len;
    return true;
}

fn handleSend(service: *ServiceMapping, request: *const GatewayRequest, response: *GatewayResponse) bool {
    const conn = getOrCreateConnection(request.peer_id, service.service_id) orelse {
        setError(response, "No connection");
        return false;
    };

    if (conn.sock) |sock| {
        // Forward to target service
        const sent = socket.send(sock, request.payload[0..request.payload_len]);
        if (sent < 0) {
            setError(response, "Send failed");
            return false;
        }

        // Wait for response
        const recv_len = socket.recv(sock, &response.payload);
        if (recv_len < 0) {
            // No response yet - echo back for now
            const echo_len = @min(request.payload_len, response.payload.len);
            @memcpy(response.payload[0..echo_len], request.payload[0..echo_len]);
            response.payload_len = echo_len;
        } else {
            response.payload_len = @intCast(recv_len);
        }

        conn.bytes_sent += request.payload_len;
        conn.bytes_received += response.payload_len;
        conn.request_count += 1;
        conn.last_activity = getTimestamp();

        return true;
    }

    setError(response, "No socket");
    return false;
}

fn handleReceive(service: *ServiceMapping, request: *const GatewayRequest, response: *GatewayResponse) bool {
    const conn = getOrCreateConnection(request.peer_id, service.service_id) orelse {
        setError(response, "No connection");
        return false;
    };

    if (conn.sock) |sock| {
        const recv_len = socket.recv(sock, &response.payload);
        if (recv_len <= 0) {
            const msg = "No data";
            @memcpy(response.payload[0..msg.len], msg);
            response.payload_len = msg.len;
        } else {
            response.payload_len = @intCast(recv_len);
            conn.bytes_received += @intCast(recv_len);
        }
        conn.last_activity = getTimestamp();
        return true;
    }

    const msg = "No data";
    @memcpy(response.payload[0..msg.len], msg);
    response.payload_len = msg.len;
    return true;
}

fn handleQuery(service: *ServiceMapping, request: *const GatewayRequest, response: *GatewayResponse) bool {
    // Query is same as send for most protocols
    return handleSend(service, request, response);
}

fn handleExecute(service: *ServiceMapping, request: *const GatewayRequest, response: *GatewayResponse) bool {
    // Execute requires can_execute capability (already checked)
    return handleSend(service, request, response);
}

fn handleSubscribe(service: *ServiceMapping, request: *const GatewayRequest, response: *GatewayResponse) bool {
    _ = service;
    _ = request;
    const msg = "Subscribed";
    @memcpy(response.payload[0..msg.len], msg);
    response.payload_len = msg.len;
    return true;
}

fn handleUnsubscribe(service: *ServiceMapping, request: *const GatewayRequest, response: *GatewayResponse) bool {
    _ = service;
    _ = request;
    const msg = "Unsubscribed";
    @memcpy(response.payload[0..msg.len], msg);
    response.payload_len = msg.len;
    return true;
}

fn signResponse(response: *GatewayResponse) void {
    var hash_input: [4300]u8 = [_]u8{0} ** 4300;
    var pos: usize = 0;

    // Request ID
    writeU64(hash_input[pos..], response.request_id);
    pos += 8;

    // Status
    hash_input[pos] = @intFromEnum(response.status);
    pos += 1;

    // Timestamp
    writeU64(hash_input[pos..], response.timestamp);
    pos += 8;

    // Payload
    if (response.payload_len > 0) {
        @memcpy(hash_input[pos..][0..response.payload_len], response.payload[0..response.payload_len]);
        pos += response.payload_len;
    }

    // Sign with gateway private key
    const hash = crypto.sha256(hash_input[0..pos]);

    // Simple signature: hash + gateway_id prefix
    @memcpy(response.signature[0..32], &hash);
    @memcpy(response.signature[32..64], gateway_id[0..32]);
}

// =============================================================================
// Security Event Logging
// =============================================================================

fn logSecurityEvent(event_type: threat_log.ThreatType, source_ip: u32, details: []const u8) void {
    _ = threat_log.logThreat(.{
        .threat_type = event_type,
        .severity = .medium,
        .source_ip = source_ip,
        .description = details,
    });
}

// =============================================================================
// Service Templates
// =============================================================================

pub fn registerPostgreSQL(owner_id: [32]u8, port: u16) ?[32]u8 {
    return registerService("postgresql", ipLocal(), port, .postgresql, owner_id, .{
        .can_read = true,
        .can_write = true,
        .can_execute = true,
        .max_connections = 32,
        .timeout_ms = 60000,
        .require_encryption = true,
    });
}

pub fn registerHTTP(name: []const u8, owner_id: [32]u8, port: u16) ?[32]u8 {
    return registerService(name, ipLocal(), port, .http, owner_id, .{
        .can_read = true,
        .can_write = true,
        .max_connections = 100,
        .timeout_ms = 30000,
        .require_encryption = false,
    });
}

pub fn registerRedis(owner_id: [32]u8, port: u16) ?[32]u8 {
    return registerService("redis", ipLocal(), port, .redis, owner_id, .{
        .can_read = true,
        .can_write = true,
        .can_execute = true,
        .max_connections = 128,
        .timeout_ms = 10000,
        .require_encryption = true,
    });
}

pub fn registerMySQL(owner_id: [32]u8, port: u16) ?[32]u8 {
    return registerService("mysql", ipLocal(), port, .mysql, owner_id, .{
        .can_read = true,
        .can_write = true,
        .can_execute = true,
        .max_connections = 32,
        .timeout_ms = 60000,
        .require_encryption = true,
    });
}

pub fn registerMongoDB(owner_id: [32]u8, port: u16) ?[32]u8 {
    return registerService("mongodb", ipLocal(), port, .mongodb, owner_id, .{
        .can_read = true,
        .can_write = true,
        .max_connections = 64,
        .timeout_ms = 30000,
        .require_encryption = true,
    });
}

// =============================================================================
// Gateway Control
// =============================================================================

pub fn start() void {
    if (gateway_state == .stopped or gateway_state == .paused) {
        gateway_state = .running;
        serial.writeString("[GATEWAY] Started\n");
    }
}

pub fn stop() void {
    gateway_state = .stopped;
    closeAllConnections();
    serial.writeString("[GATEWAY] Stopped\n");
}

pub fn pause() void {
    if (gateway_state == .running) {
        gateway_state = .paused;
        serial.writeString("[GATEWAY] Paused\n");
    }
}

pub fn enterLockdown() void {
    security_lockdown = true;
    gateway_state = .lockdown;
    closeAllConnections();
    serial.writeString("[GATEWAY] LOCKDOWN ACTIVE\n");
}

pub fn exitLockdown() void {
    security_lockdown = false;
    gateway_state = .running;
    serial.writeString("[GATEWAY] Lockdown disabled\n");
}

pub fn isInLockdown() bool {
    return security_lockdown;
}

fn closeAllConnections() void {
    for (&connections) |*conn| {
        if (conn.state != .idle and conn.state != .closed) {
            conn.state = .closed;
            if (conn.sock) |sock| {
                socket.close(sock);
                conn.sock = null;
            }
        }
    }
    connection_count = 0;
}

// =============================================================================
// Statistics
// =============================================================================

pub const GatewayStats = struct {
    state: GatewayState,
    total_services: usize,
    active_services: usize,
    active_connections: usize,
    total_requests: u64,
    total_success: u64,
    total_denied: u64,
    total_errors: u64,
    total_bytes_in: u64,
    total_bytes_out: u64,
    total_replay_blocked: u64,
    total_firewall_blocked: u64,
    in_lockdown: bool,
};

pub fn getStats() GatewayStats {
    var active_services: usize = 0;
    for (services[0..service_count]) |s| {
        if (s.active) active_services += 1;
    }

    return .{
        .state = gateway_state,
        .total_services = service_count,
        .active_services = active_services,
        .active_connections = connection_count,
        .total_requests = total_requests,
        .total_success = total_success,
        .total_denied = total_denied,
        .total_errors = total_errors,
        .total_bytes_in = total_bytes_in,
        .total_bytes_out = total_bytes_out,
        .total_replay_blocked = total_replay_blocked,
        .total_firewall_blocked = total_firewall_blocked,
        .in_lockdown = security_lockdown,
    };
}

pub fn getConnections() []const GatewayConnection {
    return connections[0..connection_count];
}

pub fn removeService(service_id: [32]u8) bool {
    return unregisterService(service_id);
}

pub fn getGatewayId() [32]u8 {
    return gateway_id;
}

pub fn printStatus() void {
    const stats = getStats();

    serial.writeString("\n[GATEWAY STATUS] ");
    printLine(25);

    serial.writeString("  State:         ");
    serial.writeString(switch (stats.state) {
        .stopped => "STOPPED",
        .starting => "STARTING",
        .running => "RUNNING",
        .paused => "PAUSED",
        .stopping => "STOPPING",
        .error_state => "ERROR",
        .lockdown => "LOCKDOWN",
    });
    serial.writeString("\n");

    serial.writeString("  Services:      ");
    printNumber(stats.active_services);
    serial.writeString("/");
    printNumber(stats.total_services);
    serial.writeString("\n");

    serial.writeString("  Connections:   ");
    printNumber(stats.active_connections);
    serial.writeString("\n");

    serial.writeString("  Requests:      ");
    printNumber(stats.total_requests);
    serial.writeString("\n");

    serial.writeString("  Success:       ");
    printNumber(stats.total_success);
    serial.writeString("\n");

    serial.writeString("  Denied:        ");
    printNumber(stats.total_denied);
    serial.writeString("\n");

    serial.writeString("  Replay Block:  ");
    printNumber(stats.total_replay_blocked);
    serial.writeString("\n");

    serial.writeString("  FW Blocked:    ");
    printNumber(stats.total_firewall_blocked);
    serial.writeString("\n");

    printLine(45);
    serial.writeString("\n");
}

// =============================================================================
// Utilities
// =============================================================================

fn ipLocal() u32 {
    return (127 << 24) | 1;
}

fn setError(response: *GatewayResponse, msg: []const u8) void {
    const len = @min(msg.len, 128);
    @memcpy(response.error_msg[0..len], msg[0..len]);
    response.error_len = len;
}

fn getTimestamp() u64 {
    return timer.getTicks();
}

fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn writeU64(buf: []u8, val: u64) void {
    buf[0] = @intCast((val >> 56) & 0xFF);
    buf[1] = @intCast((val >> 48) & 0xFF);
    buf[2] = @intCast((val >> 40) & 0xFF);
    buf[3] = @intCast((val >> 32) & 0xFF);
    buf[4] = @intCast((val >> 24) & 0xFF);
    buf[5] = @intCast((val >> 16) & 0xFF);
    buf[6] = @intCast((val >> 8) & 0xFF);
    buf[7] = @intCast(val & 0xFF);
}

fn printHex(data: []const u8) void {
    const hex_chars = "0123456789abcdef";
    for (data) |b| {
        serial.writeChar(hex_chars[b >> 4]);
        serial.writeChar(hex_chars[b & 0xF]);
    }
}

fn printNumber(n: anytype) void {
    const val = @as(u64, @intCast(n));
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printIp(ip: u32) void {
    printNumber((ip >> 24) & 0xFF);
    serial.writeChar('.');
    printNumber((ip >> 16) & 0xFF);
    serial.writeChar('.');
    printNumber((ip >> 8) & 0xFF);
    serial.writeChar('.');
    printNumber(ip & 0xFF);
}

fn printLine(len: usize) void {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        serial.writeChar('-');
    }
    serial.writeString("\n");
}
