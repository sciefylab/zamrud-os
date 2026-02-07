#!/usr/bin/env python3
"""
Zamrud OS - Project Reorganizer
Menyusun ulang struktur proyek menjadi lebih profesional
"""

import os
import shutil
from pathlib import Path

# Mapping file lama -> lokasi baru
FILE_MAPPING = {
    # Core
    'src/kernel/main.zig': 'src/kernel/core/main.zig',
    'src/kernel/cpu.zig': 'src/kernel/core/cpu.zig',
    'src/kernel/limine.zig': 'src/kernel/core/limine.zig',
    
    # Architecture (x86_64)
    'src/kernel/gdt.zig': 'src/kernel/arch/x86_64/gdt.zig',
    'src/kernel/idt.zig': 'src/kernel/arch/x86_64/idt.zig',
    'src/kernel/pic.zig': 'src/kernel/arch/x86_64/pic.zig',
    'src/kernel/tss.zig': 'src/kernel/arch/x86_64/tss.zig',
    'src/kernel/switch.zig': 'src/kernel/arch/x86_64/switch.zig',
    
    # Memory Management
    'src/kernel/pmm.zig': 'src/kernel/mm/pmm.zig',
    'src/kernel/vmm.zig': 'src/kernel/mm/vmm.zig',
    'src/kernel/memory.zig': 'src/kernel/mm/memory.zig',
    'src/kernel/heap.zig': 'src/kernel/mm/heap.zig',
    
    # Process Management
    'src/kernel/process.zig': 'src/kernel/proc/process.zig',
    'src/kernel/scheduler.zig': 'src/kernel/proc/scheduler.zig',
    'src/kernel/test_procs.zig': 'src/kernel/proc/test_procs.zig',
    
    # Drivers - Display
    'src/kernel/framebuffer.zig': 'src/kernel/drivers/display/framebuffer.zig',
    'src/kernel/vga.zig': 'src/kernel/drivers/display/vga.zig',
    
    # Drivers - Input
    'src/kernel/keyboard.zig': 'src/kernel/drivers/input/keyboard.zig',
    
    # Drivers - Timer
    'src/kernel/timer.zig': 'src/kernel/drivers/timer/timer.zig',
    
    # Drivers - Serial
    'src/kernel/serial.zig': 'src/kernel/drivers/serial/serial.zig',
    
    # Boot
    'limine.cfg': 'boot/limine.cfg',
    'limine.conf': 'boot/limine.conf',
    
    # Scripts - Build
    'scripts/build-iso.bat': 'scripts/build/build-iso.bat',
    'scripts/setup-limine.bat': 'scripts/build/setup-limine.bat',
    'scripts/write-limine-config.ps1': 'scripts/build/write-limine-config.ps1',
    
    # Scripts - Run
    'scripts/run-qemu.bat': 'scripts/run/run-qemu.bat',
    'scripts/run-direct.bat': 'scripts/run/run-direct.bat',
}

# Folder limine dipindah
FOLDER_MAPPING = {
    'limine': 'boot/limine',
}

# Folder baru yang perlu dibuat
NEW_FOLDERS = [
    'src/kernel/core',
    'src/kernel/arch/x86_64',
    'src/kernel/mm',
    'src/kernel/proc',
    'src/kernel/drivers/display',
    'src/kernel/drivers/input',
    'src/kernel/drivers/timer',
    'src/kernel/drivers/serial',
    'src/kernel/fs',
    'src/kernel/lib',
    'boot/limine',
    'scripts/build',
    'scripts/run',
    'scripts/tools',
    'docs/phases',
    'tests',
]


def create_folders(root: Path):
    """Buat folder baru"""
    print("\n📁 Creating new folders...")
    for folder in NEW_FOLDERS:
        folder_path = root / folder
        if not folder_path.exists():
            folder_path.mkdir(parents=True, exist_ok=True)
            print(f"  ✓ Created: {folder}")
        else:
            print(f"  - Exists: {folder}")


def move_files(root: Path, dry_run: bool = True):
    """Pindahkan file ke lokasi baru"""
    print("\n📄 Moving files...")
    
    moved = 0
    skipped = 0
    not_found = 0
    
    for old_path, new_path in FILE_MAPPING.items():
        old_full = root / old_path
        new_full = root / new_path
        
        if old_full.exists():
            if new_full.exists():
                print(f"  ⚠ Skip (exists): {new_path}")
                skipped += 1
                continue
                
            if dry_run:
                print(f"  [DRY] {old_path} -> {new_path}")
            else:
                new_full.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(old_full), str(new_full))
                print(f"  ✓ Moved: {old_path} -> {new_path}")
            moved += 1
        else:
            print(f"  - Not found: {old_path}")
            not_found += 1
    
    print(f"\n  Summary: {moved} moved, {skipped} skipped, {not_found} not found")


def move_folders(root: Path, dry_run: bool = True):
    """Pindahkan folder ke lokasi baru"""
    print("\n📂 Moving folders...")
    
    for old_folder, new_folder in FOLDER_MAPPING.items():
        old_full = root / old_folder
        new_full = root / new_folder
        
        if old_full.exists() and old_full.is_dir():
            if new_full.exists():
                print(f"  ⚠ Skip (exists): {new_folder}/")
                continue
                
            if dry_run:
                print(f"  [DRY] {old_folder}/ -> {new_folder}/")
            else:
                new_full.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(old_full), str(new_full))
                print(f"  ✓ Moved: {old_folder}/ -> {new_folder}/")
        else:
            print(f"  - Not found: {old_folder}/")


def cleanup_empty_folders(root: Path, dry_run: bool = True):
    """Hapus folder kosong setelah reorganisasi"""
    print("\n🧹 Cleaning up empty folders...")
    
    # Folder yang mungkin kosong setelah move
    folders_to_check = [
        'src/kernel',
        'scripts',
    ]
    
    for folder in folders_to_check:
        folder_path = root / folder
        if folder_path.exists():
            # Cek apakah hanya berisi subfolder (bukan file langsung)
            direct_files = [f for f in folder_path.iterdir() if f.is_file()]
            if not direct_files:
                if dry_run:
                    print(f"  [DRY] Would check: {folder}/")
                else:
                    print(f"  ✓ Checked: {folder}/")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='🔧 Reorganize Zamrud OS project structure',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python reorganize.py                  # Dry run
  python reorganize.py --execute        # Actually move files
  python reorganize.py --folders-only   # Only create folders
        '''
    )
    
    parser.add_argument(
        'path',
        nargs='?',
        default='.',
        help='Project root path (default: current directory)'
    )
    
    parser.add_argument(
        '--execute',
        action='store_true',
        help='Actually move files (default is dry-run)'
    )
    
    parser.add_argument(
        '--folders-only',
        action='store_true',
        help='Only create new folders, do not move files'
    )
    
    args = parser.parse_args()
    
    root = Path(args.path).resolve()
    
    # Validasi project
    if not (root / 'build.zig').exists():
        print(f"❌ Error: Not a Zamrud OS project (no build.zig found)")
        print(f"   Path: {root}")
        return 1
    
    print(f"🔧 Zamrud OS Project Reorganizer")
    print(f"📍 Project: {root}")
    
    if not args.execute:
        print(f"\n⚠️  DRY RUN MODE - No files will be moved")
        print(f"   Use --execute to actually move files\n")
    
    # Step 1: Create folders
    create_folders(root)
    
    if not args.folders_only:
        # Step 2: Move folders
        move_folders(root, dry_run=not args.execute)
        
        # Step 3: Move files
        move_files(root, dry_run=not args.execute)
        
        # Step 4: Cleanup
        cleanup_empty_folders(root, dry_run=not args.execute)
    
    print("\n" + "=" * 50)
    if args.execute:
        print("✅ Reorganization complete!")
        print("\n📋 Next steps:")
        print("   1. Run: python scripts/tools/generate_migration.py")
        print("   2. Update imports based on docs/MIGRATION.md")
        print("   3. Update build.zig root_source_file path")
    else:
        print("📋 Dry run complete!")
        print("   Run with --execute to apply changes")
    print("=" * 50)
    
    return 0


if __name__ == '__main__':
    exit(main())