# ZAMRUD OS

```PlainText
┌─────────────────────────────────────────────────────────────────┐
│  ZAMRUD OS - GLOBAL PROJECT STATUS                              │
│  "Security = Identity × Integrity × Isolation × Blockchain"     │
│  Last Updated: ML-DSA-65 Identity + External ACVP KAT VERIFIED  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  COMPLETED PHASES (Verified by testall / module tests)          │
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
│  TOTAL VERIFIED: 1115+ tests + latest ML-DSA/Identity tests     │
│  ALL CURRENT REPORTED TESTS PASSING ✅                          │
│  ─────────────────────────────────────────────────────────      │
│                                                                 │
│  Latest verified modules:                                      │
│  ✅ security test:   109 passed, 0 failed                       │
│  ✅ p2p test:        8/8 passed                                 │
│  ✅ chain test:      36 passed, 0 failed                        │
│  ✅ authority shell: 10/10 authority command test PASS          │
│  ✅ GOV.1b audit:    persistent bounded ring VERIFIED           │
│  ✅ identity test:   7/7 categories passed                      │
│  ✅ auth test:       15/15 passed                               │
│  ✅ ML-DSA-65 test:  24 passed, 0 failed                        │
│  ✅ FIPS 204 KAT:    external ACVP vectors PASS                 │
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
│  🔄 E3.6: Anti-Quantum App Signing               INTEGRATED     │
│  │  ├── DevKey vs AuthKey Hierarchical Trust                    │
│  │  ├── SLOR Fiat-Shamir legacy path under migration audit      │
│  │  ├── Physical Keyboard Approval (Session Auto-Run)           │
│  │  ├── Strict Production Lockdown                              │
│  │  └── Final target: ML-DSA-65 via gov_sign.zig only           │
│                                                                 │
│  Note:                                                          │
│  E3.6 remains functionally integrated. Legacy signature imports  │
│  must be audited and migrated so production has one signature    │
│  boundary only.                                                  │
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
│  ✅ F4.3: Blockchain Drive & Volume Binding      INTEGRATED     │
│  │  ├── Physical Drive Serial AHCI Extraction                  │
│  │  ├── Drive Identity Registered to Ledger                    │
│  │  └── Eviction Protocol (Anti-Evil Maid)       ACTIVE         │
│                                                                 │
│  Planned hardening:                                             │
│  ⬚ Authenticated encryption/AEAD for sensitive key containers   │
│  ⬚ Versioned and rollback-safe storage migration                │
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
│  STAGE P: Privacy & Anonymity                  ✅ 5/5 (100%) 🧅 │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ P.1: Anonymous Identity Generation           TESTED         │
│  ✅ P.2: Pseudonymous Mode                       TESTED         │
│  ✅ P.3: P2P Onion Routing + Defense Layer       TESTED         │
│  │  ├── P.3a: Packet Types & Magic Constants     DONE           │
│  │  ├── P.3b: Handshake & Hardware Attestation   DONE           │
│  │  ├── P.3c: P2P Socket Listener & Broadcaster  DONE           │
│  │  ├── P.3d: Multi-Layer Onion Wrapping         DONE           │
│  │  └── P.3e: Twin-Node Eviction Execution       DONE ✅        │
│  │      ├── Authority-backed voter gate          PASS           │
│  │      ├── Reputation health gate               PASS           │
│  │      ├── Evidence hash                        PASS           │
│  │      ├── Peer ban + discovery cleanup         PASS           │
│  │      ├── Eclipse connection cleanup           PASS           │
│  │      ├── Firewall Network Kill-Switch         PASS           │
│  │      └── Safe test mode, no false lockdown    PASS           │
│  ✅ P.4: Privacy Modes (Stealth/Public)          TESTED         │
│  ✅ P.5: Metadata Minimization                   TESTED         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE H: Security Hardening & Identity        ✅ 12/12 (100%)  │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ H.1-H.6: Crypto, RNG, Boot, DHCP Sec         117 tests      │
│  ✅ H.7: Identity Keyring + ML-DSA-65            VERIFIED       │
│  ✅ H.8: Threat Scoring & Anomaly Detection      82 tests       │
│  ✅ H.9: Memory Sanitization (Secure Wipe)       25 tests       │
│  ✅ H.10: Anti-Quantum SLOR (Lattice KEM)        INTEGRATED     │
│  🔄 H.11: Identity Secret-Key Protection         INTEGRATED     │
│  ✅ H.12: Security Authority Registry            22 tests       │
│                                                                 │
│  H.7 Identity + ML-DSA-65 verification:                         │
│  ├── Dual credential password/PIN                PASS           │
│  ├── ML-DSA-65 governance key generation         PASS           │
│  ├── Password governance key unlock              PASS           │
│  ├── PIN governance key unlock                   PASS           │
│  ├── Governance sign/verify                      PASS           │
│  ├── Modified message rejection                  PASS           │
│  ├── Domain separation                           PASS           │
│  ├── Lock/session key wipe                       PASS           │
│  ├── Signing denied after lock                   PASS           │
│  ├── Persistence                                 PASS           │
│  ├── Full export/import                          PASS           │
│  └── External FIPS 204 ACVP KAT                  PASS           │
│                                                                 │
│  Latest H.7 results:                                             │
│  ├── Identity categories                         7/7 PASS        │
│  ├── Authentication                              15/15 PASS      │
│  └── ML-DSA-65 backend                           24/24 PASS      │
│                                                                 │
│  H.10 SLOR KEM status:                                           │
│  ├── Identity KEM keypair generation              PASS           │
│  ├── Keyring integration                          PASS           │
│  └── Protocol/KAT assurance planned for Stage G                  │
│                                                                 │
│  H.11 Identity secret protection status:                         │
│  ├── Current GOV secret stream protection         INTEGRATED     │
│  ├── Secret metadata preservation                 FIXED          │
│  ├── Login/session restoration                    PASS           │
│  └── AEAD authenticated container upgrade         PENDING        │
│                                                                 │
│  Note:                                                          │
│  The current GOVS + hash-derived stream-XOR mechanism is not a   │
│  strict information-theoretic One-Time Pad. H.11 retains its     │
│  historical identity-encryption goal, with AEAD as the final     │
│  authenticated secret-container target.                          │
│                                                                 │
│  H.12 Authority Registry:                                        │
│  ├── Root Authority Registry                     PASS           │
│  ├── Validator Registry                          PASS           │
│  ├── Member / Guest Authority                    PASS           │
│  ├── Vote / Commit Permission Gate               PASS           │
│  ├── Quarantine / Restore                        PASS           │
│  └── Revocation Enforcement                      PASS           │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE P2P: Decentralized Network Trust        ✅ 8/8 (100%)    │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ P2P Core Module                             PASS           │
│  ✅ Peer Manager H.3/H.4/P.3e                   4/4 PASS        │
│  ✅ Message Protocol                            6/6 PASS        │
│  ✅ Authority-Backed Reputation                 15/15 PASS      │
│  ✅ Sybil Defense H.3 + P.3e                    6/6 PASS        │
│  ✅ Eclipse Defense H.4 + P.3e                  5/5 PASS        │
│  ✅ P.3 Handshake / Onion                       PASS           │
│  ✅ P.3e Twin-Node Eviction                     5/5 PASS        │
│                                                                 │
│  Core Trust Flow:                                               │
│  security/authority.zig  = authority source-of-truth            │
│  chain/authority.zig     = PoA adapter/cache only               │
│  p2p/reputation.zig      = behavior score + forced ban          │
│  p2p/eviction.zig        = twin-node eviction enforcement       │
│  net/firewall.zig        = network kill-switch                  │
│  chain/ledger.zig        = bounded audit ledger                 │
│                                                                 │
│  Double Authority Status: RESOLVED ✅                           │
│  Double Ledger Status:    AVOIDED ✅                            │
│                                                                 │
│  Secure session extension planned:                              │
│  ML-DSA authentication + SLOR KEM + KDF + AEAD                  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE CHAIN: Blockchain Ledger & PoA          ✅ 6/6 (100%)    │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ Block Structure                             PASS           │
│  ✅ Block Entries                               PASS           │
│  ✅ PoA Authority Adapter                       PASS           │
│  ✅ Ledger                                      PASS           │
│  ✅ Persistence Save                            PASS           │
│  ✅ Persistence Restore                         PASS           │
│                                                                 │
│  Chain Test Result: 36 passed, 0 failed                         │
│                                                                 │
│  Important Rules:                                               │
│  chain/authority.zig must remain adapter/cache only.             │
│  Runtime authority decision belongs to security/authority.zig.   │
│  chain/ledger.zig stores proof/audit only, not authority truth.  │
│                                                                 │
│  GOV.1b Persistence:                                            │
│  ✅ CHAIN.DAT V2 format                                         │
│  ✅ V1 compatibility loader                                     │
│  ✅ bounded audit ring                                          │
│  ✅ max 8 persistent audit records                              │
│  ✅ manual checkpoint support                                   │
│  ✅ audit auto-save OFF by default                              │
│  ✅ tip-hash folding when block capacity is full                 │
│  ✅ lightweight file size policy                                │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE SHELL: Security Commands                ✅ UPDATED       │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ security authority                          VERIFIED        │
│  ✅ security authority status                   VERIFIED        │
│  ✅ security authority list                     VERIFIED        │
│  ✅ security authority revoked                  VERIFIED        │
│  ✅ security authority stats                    VERIFIED        │
│  ✅ security authority test                     10/10 PASS      │
│  ✅ chain audit                                 VERIFIED        │
│  ✅ chain audit latest                          VERIFIED        │
│  ✅ chain audit checkpoint                      VERIFIED        │
│  ✅ chain load audit restore                    VERIFIED        │
│                                                                 │
│  Notes:                                                         │
│  - Commands are visibility/control surfaces only.               │
│  - No new authority database created.                           │
│  - No new ledger database created.                              │
│  - Reads from security/authority.zig and chain/ledger.zig.      │
│                                                                 │
│  Identity command extension planned:                            │
│  ⬚ gov-key status/test                                         │
│  ⬚ explicit generate/rotate/revoke ceremony                     │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE PQSIG: ML-DSA-65 SIGNATURE BACKEND      ✅ COMPLETE      │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Goal:                                                          │
│  Provide one official post-quantum production signature API     │
│  for identity, governance, chain, P2P, and application trust.   │
│                                                                 │
│  ✅ Keccak / SHAKE                              PASS           │
│  ✅ ML-DSA-65 parameters                       PASS           │
│  ✅ Modular reduction                          PASS           │
│  ✅ NTT / inverse NTT                          PASS           │
│  ✅ Polynomial arithmetic                      PASS           │
│  ✅ Rounding and hints                         PASS           │
│  ✅ Sampling                                   PASS           │
│  ✅ Canonical packing                          PASS           │
│  ✅ Key generation                             PASS           │
│  ✅ Deterministic signing                      PASS           │
│  ✅ Randomized signing                         PASS           │
│  ✅ Sign / verify                              PASS           │
│  ✅ Canonical negative suite                   PASS           │
│  ✅ External FIPS 204 ACVP KAT                 PASS           │
│  ✅ Facade production health gate              PASS           │
│  ✅ Identity key generation                    PASS           │
│  ✅ Password/PIN session integration           PASS           │
│  ✅ Governance sign/verify                     PASS           │
│                                                                 │
│  Official production path:                                     │
│                                                                 │
│  identity / governance / chain / P2P / app trust               │
│                          │                                      │
│                          ▼                                      │
│                    crypto/gov_sign.zig                          │
│                          │                                      │
│                          ▼                                      │
│                    crypto/slor_dsa.zig                          │
│                    ├── key generation                           │
│                    ├── signature generation                     │
│                    └── signature verification                   │
│                                                                 │
│  Cleanup remaining:                                             │
│  ⬚ Audit/remove unused legacy signature files                  │
│  ⬚ Migrate remaining production app-signing consumer           │
│  ⬚ Ensure no production consumer bypasses gov_sign.zig         │
│                                                                 │
│  Important file distinctions:                                  │
│                                                                 │
│  slor.zig          = KEM/key exchange, keep                     │
│  slor_dsa_sign.zig = active ML-DSA internal signer, keep       │
│  slor_sign.zig     = possible legacy signature, audit          │
│  signature.zig     = possible legacy facade, audit             │
│  otp.zig           = encryption module, audit separately       │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE GOV: Authority Governance & Blockchain Trust            │
│  GOV.1 COMPLETE + GOV.2 BACKEND COMPLETE                        │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Goal:                                                          │
│  Make authority, governance, eviction, and firewall actions     │
│  auditable, signed, persistent, and chain-verifiable while      │
│  keeping Zamrud OS lightweight.                                 │
│                                                                 │
│  ✅ GOV.1: Blockchain Governance Audit            DONE          │
│  │  ├── authority registered audit                              │
│  │  ├── authority revoked audit                                 │
│  │  ├── authority quarantined audit                             │
│  │  ├── authority restored audit                                │
│  │  ├── P.3e eviction executed audit                            │
│  │  ├── firewall kill-switch audit                              │
│  │  ├── GOV.1a runtime hash-committed audit                     │
│  │  ├── GOV.1b bounded persistent audit ring                    │
│  │  ├── CHAIN.DAT V2 lightweight persistence                    │
│  │  ├── V1 compatibility loader                                 │
│  │  ├── manual audit checkpoint                                 │
│  │  ├── audit auto-save OFF by default                          │
│  │  └── tip-hash folding when full                              │
│                                                                 │
│  🔄 GOV.2: Signed Governance Actions             IN PROGRESS    │
│  │  ├── ML-DSA-65 production backend             DONE           │
│  │  ├── External FIPS 204 ACVP KAT               PASS           │
│  │  ├── Identity governance key generation       PASS           │
│  │  ├── Password/PIN governance key unlock       PASS           │
│  │  ├── Governance sign/verify                   PASS           │
│  │  ├── Domain separation                        PASS           │
│  │  ├── Lock/session-key enforcement             PASS           │
│  │  └── vote/commit/authority action integration NEXT           │
│                                                                 │
│  GOV.2 remaining target:                                        │
│  ⬚ Signed eviction vote and commit                              │
│  ⬚ Signed authority lifecycle actions                          │
│  ⬚ Reject forged, unsigned, replayed, or unauthorized actions  │
│  ⬚ Commit accepted signed actions to governance audit ledger   │
│                                                                 │
│  ⬚ GOV.3: Persistent Authority Registry          PENDING        │
│  │  ├── save/load authority state                               │
│  │  ├── persist revoked/quarantine state                        │
│  │  └── optional chain reconciliation                           │
│                                                                 │
│  ⬚ GOV.4: Authority Lifecycle Commands           PARTIAL        │
│  │  ├── add-root / add-validator                                │
│  │  ├── add-member / add-guest                                  │
│  │  └── quarantine / restore / revoke                           │
│                                                                 │
│  ⬚ GOV.5: Chain-Based Authority Verification     PENDING        │
│  │  ├── authority and validator record verification             │
│  │  ├── revocation proof verification                           │
│  │  └── chain/security mismatch prevention                      │
│                                                                 │
│  ⬚ GOV.6: Hardware Attestation Enforcement       PENDING        │
│  │  ├── hardware-hash validation                                │
│  │  ├── mismatch detection and violation record                 │
│  │  └── integration with P.3e evidence                          │
│                                                                 │
│  ⬚ GOV.7: Distributed Authority Synchronization  PENDING        │
│     ├── signed authority delta synchronization                  │
│     ├── revocation/quarantine propagation                       │
│     └── chain proof validation                                  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE CRYPTO-U: Crypto Unification            🔄 IN PROGRESS   │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Goal:                                                          │
│  One official production boundary for each cryptographic role.  │
│                                                                 │
│  Signature:                                                     │
│  gov_sign.zig → slor_dsa.zig                   ✅ ACTIVE        │
│                                                                 │
│  Key exchange:                                                  │
│  SLOR KEM / slor.zig                           ✅ INTEGRATED    │
│                                                                 │
│  Secret-key protection:                                         │
│  current stream container → AEAD upgrade        🔄 PLANNED      │
│                                                                 │
│  Secure channel:                                                 │
│  ML-DSA + SLOR KEM + KDF + AEAD                ⬚ PENDING       │
│                                                                 │
│  Cleanup targets:                                                │
│  ⬚ Audit slor_sign.zig and signature.zig                        │
│  ⬚ Remove them only if no production consumer remains          │
│  ⬚ Keep slor.zig, slor_dsa_sign.zig, and otp.zig as required   │
│  ⬚ Clean build and full regression after removal               │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE G: Zamrud Secure Shell (ZSH)            ⬚ 0/6 (0%)       │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ⬚ G.1: ZSH Protocol Definition                 PENDING        │
│  ⬚ G.2: Peer Discovery & Handshake              PENDING        │
│  ⬚ G.3: Quantum-Resistant Session               PENDING        │
│  ⬚ G.4: Server Implementation                   PENDING        │
│  ⬚ G.5: Client Implementation                   PENDING        │
│  ⬚ G.6: Syscall Interface                       PENDING        │
│                                                                 │
│  G.3 final composition:                                          │
│  ├── ML-DSA-65 for identity and handshake authentication        │
│  ├── SLOR KEM for shared-secret establishment                   │
│  ├── transcript KDF for purpose-separated session keys          │
│  ├── AEAD for packet encryption and authentication              │
│  └── sequence/replay protection                                 │
│                                                                 │
│  Note:                                                          │
│  Previous "SLOR + OTP" wording is retained as historical intent. │
│  The production session target is SLOR KEM + KDF + AEAD, with    │
│  ML-DSA-65 authenticating the handshake.                         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  STAGE F6: GUI / Window Manager                ⬚ 0/6 (0%)       │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ⬚ F6.1: Framebuffer Compositor                 PENDING        │
│  ⬚ F6.2: Widget Toolkit                         PENDING        │
│  ⬚ F6.3: Event System (Mouse/Keyboard)          PENDING        │
│  ⬚ F6.4: Window Manager                         PENDING        │
│  ⬚ F6.5: Desktop Environment                    PENDING        │
│  ⬚ F6.6: GUI Applications                       PENDING        │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  SECURITY RATING                                                │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Timing Attacks:        ⭐⭐⭐⭐⭐   <- H.1 FIXED                 │
│  RNG Quality:           ⭐⭐⭐⭐⭐   <- H.2 FIXED                 │
│  Signature Integrity:   ⭐⭐⭐⭐⭐   <- ML-DSA ACVP KAT PASS      │
│  Memory Cleanup:        ⭐⭐⭐⭐⭐   <- H.9 FIXED                 │
│  Sybil Resistance:      ⭐⭐⭐⭐⭐   <- H.3 FIXED                 │
│  Eclipse Defense:       ⭐⭐⭐⭐⭐   <- H.4 FIXED                 │
│  Boot Integrity:        ⭐⭐⭐⭐⭐   <- H.5 FIXED                 │
│  DHCP Security:         ⭐⭐⭐⭐⭐   <- H.6 FIXED                 │
│  Identity System:       ⭐⭐⭐⭐⭐   <- H.7 VERIFIED              │
│  Threat Detection:      ⭐⭐⭐⭐⭐   <- H.8 FIXED                 │
│  Anti-Quantum KEM:      ⭐⭐⭐⭐⭐   <- H.10 INTEGRATED           │
│  Secret-Key Protection: ⭐⭐⭐⭐☆   <- AEAD UPGRADE PENDING       │
│  Session Encryption:    ⭐⭐⭐⭐☆   <- KDF + AEAD PENDING          │
│  App Signing:           ⭐⭐⭐⭐☆   <- LEGACY MIGRATION PENDING    │
│  Hardware Sovereignty:  ⭐⭐⭐⭐⭐   <- F4.3 ANTI-EVIL MAID     ✅│
│  Authority Governance:  ⭐⭐⭐⭐⭐   <- H.12 SOURCE-OF-TRUTH    ✅│
│  Chain PoA Adapter:     ⭐⭐⭐⭐⭐   <- NO DOUBLE AUTHORITY     ✅│
│  Network Kill-Switch:   ⭐⭐⭐⭐⭐   <- P.3e FIREWALL ENFORCED  ✅│
│  Governance Audit:      ⭐⭐⭐⭐⭐   <- GOV.1b BOUNDED AUDIT   ✅│
│  Signed GOV Backend:    ⭐⭐⭐⭐⭐   <- ML-DSA-65 OPERATIONAL   ✅│
│  Signed GOV Actions:    ⭐⭐⭐⭐☆   <- ACTION INTEGRATION NEXT     │
│  Lightweight Chain:     ⭐⭐⭐⭐⭐   <- RING BUFFER + FOLDING  ✅│
│                                                                 │
│  ENGINEERING STATUS: ADVANCED SECURITY ARCHITECTURE              │
│  ML-DSA-65 IDENTITY BACKEND VERIFIED                              │
│                                                                 │
│  Security claim note:                                           │
│  "Nation-State Grade" remains a design target until independent  │
│  cryptographic and full-system security assessment is completed. │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  PROGRESS SUMMARY                                               │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Stage B2:    ████████████████████ 11/11 complete (100%) ✅     │
│  Stage E:     ████████████████████  6/6 functional       ✅     │
│  Stage F:     ████████████████████  4/4 functional       ✅     │
│  Stage S:     ████████████████████  6/6 complete (100%) ✅     │
│  Stage R:     ████████████████████  5/5 complete (100%) ✅     │
│  Stage P:     ████████████████████  5/5 complete (100%) ✅     │
│  Stage H:     ████████████████████ 12/12 functional       ✅     │
│  Stage P2P:   ████████████████████  8/8 complete (100%) ✅     │
│  Stage Chain: ████████████████████  6/6 complete (100%) ✅     │
│  Stage Shell: ████████████████████ Authority + Audit DONE ✅    │
│  Stage PQSIG: ████████████████████ ML-DSA-65 COMPLETE    ✅     │
│  Stage GOV.1: ████████████████████ complete              ✅     │
│  Stage GOV.2: ████████████░░░░░░░░ backend complete      🔄     │
│  Stage GOV.3-7:████░░░░░░░░░░░░░░░ pending                  │
│  Stage Crypto-U:████████░░░░░░░░░░░ cleanup in progress      │
│  Stage G:     ░░░░░░░░░░░░░░░░░░░░  0/6 complete (0%)          │
│  Stage F6:    ░░░░░░░░░░░░░░░░░░░░  0/6 complete (0%)          │
│                                                                 │
│  OVERALL: HIGH PROGRESS - SCOPE EXTENDED FOR AEAD/KEM ASSURANCE │
│                                                                 │
│  Note:                                                          │
│  The previous 97% estimate is retained as the legacy roadmap     │
│  estimate. It should be recalculated only after AEAD protection,  │
│  KEM protocol assurance, and crypto cleanup are sized.            │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  CURRENT VERIFIED COMMANDS                                      │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ✅ security test                                                │
│     └── 109 passed, 0 failed                                    │
│                                                                 │
│  ✅ p2p test                                                     │
│     └── 8/8 passed OK                                           │
│                                                                 │
│  ✅ chain test                                                   │
│     └── 36 passed, 0 failed                                     │
│                                                                 │
│  ✅ identity test                                                │
│     ├── 7/7 categories passed                                   │
│     ├── Auth 15/15 passed                                       │
│     ├── persistence passed                                      │
│     └── export/import passed                                    │
│                                                                 │
│  ✅ identity test dsa                                            │
│     ├── ML-DSA-65 24 passed, 0 failed                           │
│     ├── canonical negative suite PASS                            │
│     └── external FIPS 204 ACVP KAT PASS                         │
│                                                                 │
│  ✅ security authority                                           │
│     ├── status display PASS                                     │
│     ├── list display PASS                                       │
│     ├── stats display PASS                                      │
│     ├── revoked display PASS                                    │
│     └── authority test 10/10 PASS                               │
│                                                                 │
│  ✅ chain audit                                                  │
│     ├── GOV.1b status display PASS                              │
│     ├── bounded ring status PASS                                │
│     ├── audit latest display PASS                               │
│     ├── audit checkpoint PASS                                   │
│     ├── audit restore after load PASS                           │
│     └── audit auto-save OFF by default PASS                     │
│                                                                 │
│  ✅ P.3e firewall integration                                    │
│     ├── peer ban PASS                                           │
│     ├── discovery cleanup PASS                                  │
│     ├── firewall block PASS                                     │
│     ├── flow drop path PASS                                     │
│     └── safe test mode PASS                                     │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  PRODUCTION IDENTITY STATUS                                     │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Test identities:                              ✅ VERIFIED       │
│  Production identity @univa:                   ⬚ AUDIT PENDING  │
│                                                                 │
│  Required @univa validation:                                    │
│  ⬚ ML-DSA-65 public/encrypted-secret metadata valid             │
│  ⬚ Login, sign/verify, lock, and export/import test             │
│  ⬚ Record governance public-key fingerprint                     │
│                                                                 │
│  Ceremony policy:                                               │
│                                                                 │
│  Re-encrypt same secret key with AEAD:                          │
│  └── No trust ceremony required                                 │
│                                                                 │
│  Generate or rotate ML-DSA governance key:                      │
│  └── Governance key-rotation ceremony required                  │
│                                                                 │
│  Change boot/chain/authority/P2P trust-anchor public key:       │
│  └── Trust ceremony and anchor update required                  │
│                                                                 │
│  No governance key may be silently generated during login.      │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  REPOSITORY CLEANUP STATUS                                      │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  Keep:                                                          │
│  ✅ gov_sign.zig                                                │
│  ✅ slor_dsa.zig and all slor_dsa_* internals                   │
│  ✅ slor_dsa_kat.zig and negative tests                         │
│  ✅ keccak.zig                                                  │
│  ✅ slor.zig (KEM/key exchange)                                 │
│  ✅ otp.zig until encryption consumer audit is complete         │
│                                                                 │
│  Audit before removal:                                          │
│  ⬚ slor_sign.zig                                                │
│  ⬚ signature.zig                                                │
│                                                                 │
│  Supporting artifact cleanup:                                  │
│  ⬚ Keep docs/kat/nist-acvp source vectors                       │
│  ⬚ Add SHA256SUMS for ACVP source files                         │
│  ⬚ Remove duplicate root ACVP ZIP if not needed                 │
│  ⬚ Audit generated audio_out.wav and system.qcow2 tracking      │
│                                                                 │
│  Removal rule:                                                  │
│  Audit → quarantine → clean build → full tests → final delete.  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  NEXT STAGE TARGETS                                             │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  1. GOV.2 Signed Governance Actions                            🧾│
│     ├── signed vote, commit, and authority actions              │
│     └── anti-forgery, authorization, and replay rejection       │
│                                                                 │
│  2. Crypto Cleanup                                             🧹│
│     ├── audit/remove legacy signature files                     │
│     └── enforce gov_sign.zig as only production signature API   │
│                                                                 │
│  3. AEAD Secret-Key Protection                                🔐│
│     ├── authenticated ML-DSA secret container                   │
│     └── versioned persistence/export migration                  │
│                                                                 │
│  4. SLOR KEM Assurance                                        🔑│
│     ├── encapsulation/decapsulation and negative tests          │
│     └── transcript KDF + AEAD integration in Stage G            │
│                                                                 │
│  5. Production Identity Validation                            👤│
│     ├── audit @univa governance key                             │
│     └── ceremony only if governance public key changes          │
│                                                                 │
│  After GOV/Crypto Closure:                                      │
│  ⬚ GOV.3: Persistent Authority Registry                        │
│  ⬚ GOV.4: Authority Lifecycle Commands                         │
│  ⬚ GOV.5: Chain-Based Authority Verification                   │
│  ⬚ GOV.6: Hardware Attestation Enforcement                     │
│  ⬚ GOV.7: Distributed Authority Synchronization                │
│  ⬚ G.1: Zamrud Secure Shell Protocol Definition                │
│  ⬚ G.2: Peer Discovery & Handshake                             │
│  ⬚ G.3: ML-DSA + SLOR KEM + KDF + AEAD Session                 │
│  ⬚ F6.1: Framebuffer Compositor                                │
│                                                                 │
│  Current Focus:                                                 │
│  GOV.2 action integration → crypto cleanup → AEAD key protection│
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ═══════════════════════════════════════════════════════════    │
│  CURRENT COMPLETION STATUS                                      │
│  ═══════════════════════════════════════════════════════════    │
│                                                                 │
│  ML-DSA-65 implementation:                 ✅ COMPLETED          │
│  External FIPS 204 ACVP KAT:              ✅ PASS               │
│  Identity integration:                    ✅ COMPLETED          │
│  Password/PIN governance unlock:          ✅ PASS               │
│  Governance sign/verify:                  ✅ PASS               │
│  Domain separation:                       ✅ PASS               │
│  Session-key wipe/lock enforcement:       ✅ PASS               │
│  Persistence/export/import:               ✅ PASS               │
│                                                                 │
│  GOV.2 production backend:                ✅ COMPLETED          │
│  GOV.2 signed action integration:          🔄 IN PROGRESS        │
│  Legacy signature cleanup:                ⬚ PENDING AUDIT       │
│  AEAD secret-key container:               ⬚ PENDING             │
│  SLOR KEM protocol assurance:             ⬚ PLANNED             │
│  Production @univa key audit:             ⬚ PENDING             │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  FINAL TARGET CRYPTO ARCHITECTURE                               │
│                                                                 │
│  ML-DSA-65                                                     │
│  └── Identity, governance, chain, P2P, and app signatures       │
│                                                                 │
│  SLOR KEM                                                      │
│  └── Post-quantum shared-secret establishment                   │
│                                                                 │
│  Transcript KDF                                                │
│  └── Purpose-separated directional keys                        │
│                                                                 │
│  AEAD                                                          │
│  ├── Authenticated ML-DSA secret-key storage                    │
│  └── Authenticated secure-session traffic                       │
│                                                                 │
│  gov_sign.zig                                                  │
│  └── Only official production signature facade                 │
│                                                                 │
│  security/authority.zig                                        │
│  └── Only runtime authority source-of-truth                     │
│                                                                 │
│  chain/ledger.zig                                              │
│  └── Bounded governance proof and audit ledger                 │
│                                                                 │
│  No double signature system.                                   │
│  No double authority system.                                   │
│  No double ledger system.                                      │
│  One official facade for each cryptographic purpose.            │
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

