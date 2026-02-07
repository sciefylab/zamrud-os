# scripts/tools/dump_files.py
import os

files = [
    # "src/kernel/crypto/crypto.zig",
    # "src/kernel/crypto/hash.zig", 
    # "src/kernel/crypto/signature.zig",
    # "src/kernel/crypto/keys.zig",
    # "src/kernel/crypto/random.zig",
    # "src/kernel/mm/heap.zig",
    # "src/kernel/chain/block.zig",
    # "src/kernel/chain/chain.zig",
    # "src/kernel/identity/keyring.zig",
    # "src/kernel/crypto/keys.zig",
    "src/kernel/crypto/hash.zig",
    "src/kernel/core/cpu.zig",
    "src/kernel/main.zig"
]

for f in files:
    if os.path.exists(f):
        print(f"\n{'='*60}")
        print(f"FILE: {f}")
        print('='*60)
        with open(f, 'r') as fp:
            print(fp.read())