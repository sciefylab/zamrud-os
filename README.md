# Zamrud OS

Simple OS in Zig. Run: `scripts\setup-limine.bat` then `zig build run`

python scripts/tools/project_tree.py

## 1. Reorganisasi proyek (dry run dulu)

python scripts/tools/reorganize.py

## 2. Eksekusi reorganisasi

python scripts/tools/reorganize.py --execute

zamrud-os/
├── src/
│   └── kernel/
│       ├── main.zig          # Entry point kernel
│       ├── vga.zig           # VGA framebuffer driver
│       ├── serial.zig        # Serial port untuk debugging
│       ├── limine.zig        # Limine protocol definitions
│       └── font.bin          # Bitmap font 8x16
├── scripts/
    tools
       |--dump_phdr.py
│   ├── setup-limine.bat      # Download Limine bootloader
│   ├── build-iso.bat         # Buat ISO image
│   ├── run-qemu.bat          # Jalankan di QEMU
│   └── run-debug.bat         # Debug dengan GDB
├── build.zig                 # Konfigurasi build Zig
├── linker.ld                 # Linker script
├── limine.cfg                # Konfigurasi bootloader
├── .gitignore
└── README.md

## Mode UI (default)

zig build kernel

## Mode Server (tanpa UI)

zig build kernel -Dwith_ui=false

## Mode UI (default) RUN

zig build run -Dwith_ui=true

## Mode Server (tanpa UI) RUN

zig build run -Dwith_ui=false

