with open("src/kernel/drivers/input/keyboard.zig", "r") as f:
    content = f.read()

# Save to a text file you can attach
with open("keyboard_dump.txt", "w") as f:
    f.write(content)

print(f"Saved {len(content)} bytes to keyboard_dump.txt")