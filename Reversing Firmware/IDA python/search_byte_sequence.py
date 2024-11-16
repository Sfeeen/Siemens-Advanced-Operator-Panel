import idaapi
import idautils
import idc

# Define the pattern to search for the short address representation of SSR2
pattern = b'\x8C'  # 0x8C is the lower byte for SSR2 in short addressing

# RAM region where short addressing would apply for I/O registers
search_region = (0xFF8000, 0xFFFFFF)

# Search for instructions using 0x8C as the lower byte for SSR2
print("Searching for references to SSR2 (0xFFFF8C) in short addressing mode...")
found_count = 0

for ea in range(search_region[0], search_region[1]):
    # Read bytes at the current address to check for the pattern
    data = idc.get_bytes(ea, 2)  # Get 2 bytes, enough to match short addressing opcodes

    # Check if the data contains 0x8C in the appropriate position
    if data and data.endswith(pattern):
        # Disassemble the instruction and check if it matches the usage of SSR2
        disasm = idc.GetDisasm(ea)
        if "SSR2" in disasm or "@H'FF8C" in disasm:
            print(f"SSR2 found at address: 0x{ea:X} -> {disasm}")
            found_count += 1

if found_count == 0:
    print("No references to SSR2 found in the short addressing mode within the I/O region.")
else:
    print(f"Total occurrences of SSR2 in short addressing mode: {found_count}")
