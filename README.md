# ZAMRUD OS

```PlainText
┌─────────────────────────────────────────────────────────────────┐
│  ZAMRUD OS - GLOBAL PROJECT STATUS                              │
│  "Security = Identity × Integrity × Isolation × Blockchain"     │
│  Last Updated: F4.3 (Anti-Evil Maid) 100% INTEGRATED          🆕│
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  COMPLETED PHASES (Verified by testall)                         │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  PHASE A: Kernel Foundation                    ✅ PASS          │
│  PHASE B: Core Systems                         ✅ PASS          │
│  PHASE C: Security & Network                   ✅ PASS          │
│  PHASE D: Storage & Persistence                ✅ PASS          │
│  PHASE E: Security Hardening                   ✅ PASS          │
│  PHASE F1-F5: Advanced Features                ✅ PASS          │
│  SYSCALL SC1-SC9                               ✅ PASS (108)    │
│  TERMINAL T1-T5                                ✅ PASS          │
│                                                                 │
│  ─────────────────────────────────────────────────────────      │
│  TOTAL VERIFIED:  1091 tests, ALL PASSING ✅                    │
│  ─────────────────────────────────────────────────────────      │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE B2: Backend Drivers                     ✅ 11/11 (100%)  │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ B2.1-B2.11: All verified (Mouse, FAT32, SATA, Net, Audio)   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE E: Execution & App Security             ✅ 6/6 (100%) 🚀 │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ E3.1: Capability System                      25 tests       │
│  ✅ E3.2: Unveil Sandbox (Filesystem)            20 tests       │
│  ✅ E3.3: Blockchain Binary Verify (BBT)         INTEGRATED     │
│  ✅ E3.4: Network Capability Enforcement         20 tests       │
│  ✅ E3.5: Unified Violation Handler              19 tests       │
│  ✅ E3.6: Anti-Quantum App Signing               INTEGRATED     │
│  │  ├── DevKey vs AuthKey Hierarchical Trust                    │
│  │  ├── SLOR Fiat-Shamir Signature Verification                 │
│  │  ├── Physical Keyboard Approval (Session Auto-Run)           │
│  │  └── Strict Production Lockdown                              │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE F: Storage & Persistence                ✅ 4/4 (100%) 🛡️│
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ F4.0: Encrypted FS (AES-256-CBC)             25 tests       │
│  ✅ F4.1: EncFS Integration                      25 tests       │
│  ✅ F4.2: System Encryption (Master Key)         25 tests       │
│  ✅ F4.3: Blockchain Drive & Volume Binding      INTEGRATED   🆕│
│  │  ├── Physical Drive Serial AHCI Extraction    INTEGRATED     │
│  │  ├── Drive Identity Registered to Ledger      INTEGRATED     │
│  │  └── Eviction Protocol (Anti-Evil Maid)       ACTIVE         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE S: Security Bare Metal                  ✅ 6/6 (100%)    │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ S.1-S.6: All verified (104 tests)                           │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE R: Root Authority & Multi-User          ✅ 5/5 (100%)    │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ R.1-R.5: All verified (25 tests)                            │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE P: Privacy & Anonymity                  🔄 4/5 (80%)     │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ P.1: Anonymous Identity Generation           TESTED         │
│  ✅ P.2: Pseudonymous Mode                       TESTED         │
│  ⬚  P.3: P2P Onion Routing (OTP & SLOR)          IN PROGRESS  🧅│
│  │  ├── P.3a: Packet Types & Magic Constants     DONE         🆕│
│  │  ├── P.3b: Handshake & Hardware Attestation   DONE         🆕│
│  │  ├── P.3c: P2P Socket Listener & Broadcaster  PENDING        │
│  │  ├── P.3d: Multi-Layer Onion Wrapping         PENDING        │
│  │  └── P.3e: Twin-Node Eviction Execution       PENDING        │
│  ✅ P.4: Privacy Modes (Stealth/Public)          TESTED         │
│  ✅ P.5: Metadata Minimization                   TESTED         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE H: Security Hardening & Identity        ✅ 11/11 (100%)  │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ H.1-H.6: Crypto, RNG, Boot, DHCP Sec         117 tests      │
│  ✅ H.7: Identity Keyring (Auth/Store/Export)    50 tests       │
│  ✅ H.8: Threat Scoring & Anomaly Detection      82 tests       │
│  ✅ H.9: Memory Sanitization (Secure Wipe)       25 tests       │
│  ✅ H.10: Anti-Quantum SLOR (Lattice KEM)        INTEGRATED     │
│  ✅ H.11: One-Time Pad (OTP) Identity Encrypt    INTEGRATED     │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE G: Zamrud Secure Shell (ZSH)            ⬚ 0/6 (0%)       │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ⬚  G.1: ZSH Protocol Definition                 PENDING        │
│  ⬚  G.2: Peer Discovery & Handshake              PENDING        │
│  ⬚  G.3: Quantum-Resistant Session (SLOR+OTP)    PENDING        │
│  ⬚  G.4: Server Implementation                   PENDING        │
│  ⬚  G.5: Client Implementation                   PENDING        │
│  ⬚  G.6: Syscall Interface                       PENDING        │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE F6: GUI / Window Manager                ⬚ 0/6 (0%)       │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ⬚  F6.1: Framebuffer Compositor                 PENDING        │
│  ⬚  F6.2: Widget Toolkit                         PENDING        │
│  ⬚  F6.3: Event System (Mouse/Keyboard)          PENDING        │
│  ⬚  F6.4: Window Manager                         PENDING        │
│  ⬚  F6.5: Desktop Environment                    PENDING        │
│  ⬚  F6.6: GUI Applications                       PENDING        │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  SECURITY RATING                                                │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Timing Attacks:        ⭐⭐⭐⭐⭐   <- H.1 FIXED                 │
│  RNG Quality:           ⭐⭐⭐⭐⭐   <- H.2 FIXED                 │
│  Signature Integrity:   ⭐⭐⭐⭐⭐   <- H.1 FIXED                 │
│  Memory Cleanup:        ⭐⭐⭐⭐⭐   <- H.9 FIXED                 │
│  Sybil Resistance:      ⭐⭐⭐⭐⭐   <- H.3 FIXED                 │
│  Eclipse Defense:       ⭐⭐⭐⭐⭐   <- H.4 FIXED                 │
│  Boot Integrity:        ⭐⭐⭐⭐⭐   <- H.5 FIXED                 │
│  DHCP Security:         ⭐⭐⭐⭐⭐   <- H.6 FIXED                 │
│  Identity System:       ⭐⭐⭐⭐⭐   <- H.7 FIXED                 │
│  Threat Detection:      ⭐⭐⭐⭐⭐   <- H.8 FIXED                 │
│  Anti-Quantum KEM:      ⭐⭐⭐⭐⭐   <- H.10 INTEGRATED           │
│  Session Encryption:    ⭐⭐⭐⭐⭐   <- H.11 OTP READY            │
│  App Signing (Lattice): ⭐⭐⭐⭐⭐   <- E3.6 ENFORCING            │
│  Hardware Sovereignty:  ⭐⭐⭐⭐⭐   <- F4.3 ANTI-EVIL MAID     ✅│
│                                                                 │
│  OVERALL:  ⭐⭐⭐⭐⭐ (Nation-State Grade Security)               │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  PROGRESS SUMMARY                                               │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Stage B2: ████████████████████ 11/11  complete (100%) ✅       │
│  Stage E:  ████████████████████  6/6   complete (100%) ✅     🚀│
│  Stage F:  ████████████████████  4/4   complete (100%) ✅     🛡️│
│  Stage S:  ████████████████████  6/6   complete (100%) ✅       │
│  Stage R:  ████████████████████  5/5   complete (100%) ✅       │
│  Stage P:  ████████████████░░░░  4/5   complete (80%)         🧅│
│  Stage H:  ████████████████████ 11/11  complete (100%) ✅       │
│                                                                 │
│  OVERALL:  ████████████████████████████░ 94%                  🚀│
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  NEXT PRIORITIES                                                │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  1. P.3c: Develop P2P Socket Listener & Broadcaster           🧅│
│  2. P.3e: Implement Twin-Node Eviction (Network Kill-Switch)    │
│  3. G.1 : Zamrud Secure Shell (ZSH Protocol Definition)         │
│  4. F6.1: Framebuffer Compositor (GUI Foundation)               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Mode UI (default)

zig build kernel

## Mode Server (tanpa UI)

zig build kernel -Dwith_ui=false

## Mode UI (default) RUN

zig build run -Dwith_ui=true

## Mode Server (tanpa UI) RUN

zig build run -Dwith_ui=false

## Hapus disk lama

del disks\system.qcow2

## Buat disk baru

scripts\run\create-disk.bat

## Jalankan ulang

zig build run

