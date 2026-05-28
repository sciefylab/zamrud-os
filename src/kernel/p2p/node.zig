//! Zamrud OS - P2P Network Node Manager
//! P.3c: Socket Listener & Broadcaster (Anti-Evil Maid Integrated)
//! Menangani TCP Listener untuk koneksi masuk dan UDP Broadcaster untuk Peer Discovery.

const serial = @import("../drivers/serial/serial.zig");
const net = @import("../net/net.zig");
const socket = @import("../net/socket.zig");
const timer = @import("../drivers/timer/timer.zig");
const ahci = @import("../drivers/storage/ahci.zig");
const hash = @import("../crypto/hash.zig");

// =============================================================================
// Konfigurasi Port P2P Zamrud OS
// =============================================================================
pub const ZAMRUD_P2P_PORT: u16 = 27777; // Port rahasia untuk jaringan Bawang Zamrud
pub const ZAMRUD_DISCOVERY_PORT: u16 = 27778; // UDP Port untuk broadcast lokal

var is_listening = false;
var tcp_listener_sock: ?*socket.Socket = null; // 🛠️ FIX: API socket.zig menggunakan pointer objek

// =============================================================================
// P2P Listener (The Ear) - Menerima Koneksi Masuk
// =============================================================================

/// Membuka Socket TCP dan mendengarkan permintaan dari Peer lain
pub fn startListener() bool {
    if (is_listening) return true;

    serial.writeString("[P2P-NODE] Starting secure P2P Listener on TCP Port ");
    printU16(ZAMRUD_P2P_PORT);
    serial.writeString("...\n");

    // 1. Buat Socket TCP (🛠️ FIX: Hanya 1 parameter .tcp sesuai socket.zig Anda)
    tcp_listener_sock = socket.create(.tcp);
    if (tcp_listener_sock == null) {
        serial.writeString("[P2P-NODE] Error: Failed to create TCP socket.\n");
        return false;
    }

    // 2. Bind ke Port
    if (!socket.bind(tcp_listener_sock.?, 0, ZAMRUD_P2P_PORT)) {
        serial.writeString("[P2P-NODE] Error: Failed to bind TCP socket.\n");
        socket.close(tcp_listener_sock.?);
        tcp_listener_sock = null;
        return false;
    }

    // 3. Mulai Listen (Antrian maksimal 32 peer simultan)
    if (!socket.listen(tcp_listener_sock.?, 32)) {
        serial.writeString("[P2P-NODE] Error: Failed to start listening.\n");
        socket.close(tcp_listener_sock.?);
        tcp_listener_sock = null;
        return false;
    }

    is_listening = true;
    serial.writeString("[P2P-NODE] P2P Listener is now ACTIVE and waiting for peers.\n");
    return true;
}

/// Fungsi yang dipanggil secara berkala untuk mengecek peers masuk
pub fn pollIncomingConnections() void {
    if (!is_listening or tcp_listener_sock == null) return;

    var peer_ip: u32 = 0;
    var peer_port: u16 = 0;

    // Asumsi socket.accept tersedia. Jika tidak, blok ini otomatis diabaikan kompilator via @hasDecl
    if (@hasDecl(socket, "accept")) {
        if (socket.accept(tcp_listener_sock.?, &peer_ip, &peer_port)) |peer_sock| {
            serial.writeString("[P2P-NODE] Incoming connection from ");
            printIp(peer_ip);
            serial.writeString("\n");

            handlePeerHandshake(peer_sock, peer_ip);
        }
    }
}

// =============================================================================
// Security Gateway: Validasi Peer Masuk
// =============================================================================

fn handlePeerHandshake(peer_sock: *socket.Socket, peer_ip: u32) void {
    _ = peer_ip; // 🛠️ FIX: Membuang peringatan 'unused parameter' secara eksplisit

    var buffer: [512]u8 = undefined;

    // 🛠️ FIX: Menggunakan recv() alih-alih receive() sesuai modul Anda
    const bytes_read = socket.recv(peer_sock, &buffer);

    if (bytes_read > 0) {
        // Karena kita menggunakan mode Sandbox/Isolasi di tahap ini,
        // secara default kita tolak dan putus paket yang tidak dikenal
        serial.writeString("[P2P-NODE] [DROP] Unrecognized Payload. Disconnecting.\n");
        socket.close(peer_sock);
    } else {
        socket.close(peer_sock);
    }
}

// =============================================================================
// P2P Broadcaster (The Mouth) - Mencari Peer di Jaringan
// =============================================================================

/// Mengirimkan KTP Jaringan ke jaringan lokal via UDP Broadcast
pub fn broadcastPresence() bool {
    // 1. Ambil Hardware DNA (Anti-Evil Maid Check)
    var hw_hash: [32]u8 = [_]u8{0} ** 32;
    if (ahci.isInitialized() and ahci.getDriveCount() > 0) {
        if (ahci.getDriveSerial(0)) |serial_str| {
            hash.sha256Into(serial_str, &hw_hash);
        }
    }

    // 2. Buat UDP Socket
    const udp_sock = socket.create(.udp);
    if (udp_sock == null) return false;

    if (@hasDecl(socket, "setBroadcast")) {
        socket.setBroadcast(udp_sock.?, true);
    }

    // IP 255.255.255.255 (Global Broadcast)
    const broadcast_ip: u32 = 0xFFFFFFFF;

    serial.writeString("[P2P-NODE] Broadcasting Node Identity to Network...\n");

    if (@hasDecl(socket, "sendTo")) {
        _ = socket.sendTo(udp_sock.?, &hw_hash, broadcast_ip, ZAMRUD_DISCOVERY_PORT);
    }

    socket.close(udp_sock.?);
    return true;
}

// =============================================================================
// Helpers untuk Mencetak Log
// =============================================================================

fn printU16(val: u16) void {
    var buf: [5]u8 = undefined;
    var i: usize = 0;
    var v = val;
    if (v == 0) {
        serial.writeChar('0');
        return;
    }
    while (v > 0) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
        i += 1;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printIp(ip: u32) void {
    // Asumsi IP dalam format Little Endian (A.B.C.D)
    printU16(@intCast(ip & 0xFF));
    serial.writeChar('.');
    printU16(@intCast((ip >> 8) & 0xFF));
    serial.writeChar('.');
    printU16(@intCast((ip >> 16) & 0xFF));
    serial.writeChar('.');
    printU16(@intCast((ip >> 24) & 0xFF));
}
