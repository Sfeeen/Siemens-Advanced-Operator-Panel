import idaapi
import idc

# Define memory map with start and end addresses, and corresponding names
memory_map = [
    (0x000000, 0x03FFFF, "ROM"),
    (0x040000, 0xFFAFFF, "EXT"),
    (0xFFB000, 0xFFEFBF, "RAM"),
    (0xFFEFC0, 0xFFF7FF, "EXT"),
    (0xFFF800, 0xFFFF3F, "I/O"),
    (0xFFFF40, 0xFFFF5F, "EXT2"),
    (0xFFFF60, 0xFFFFBF, "I/O2"),
    (0xFFFFC0, 0xFFFFFF, "RAM2")
]

# Function to create segments based on the memory map
def create_segments():
    for start, end, name in memory_map:
        # Check if a segment already exists at the start address
        if idaapi.get_segm_by_name(name) is None:
            # Add a new segment
            idaapi.add_segm(0, start, end, name, "DATA")
            print(f"Created segment '{name}' from 0x{start:X} to 0x{end:X}")

# Prepend segment name to unnamed addresses
def rename_unnamed_addresses():
    for start, end, name in memory_map:
        for addr in range(start, end + 1):
            current_name = idc.get_name(addr)
            if not current_name:  # Check if the address is unnamed
                new_name = f"{name}_{addr:X}"
                idc.set_name(addr, new_name, idaapi.SN_NOCHECK)
                print(f"Renamed address 0x{addr:X} to '{new_name}'")

# Create segments and rename unnamed addresses
create_segments()
rename_unnamed_addresses()

print("Memory map segments created, and unnamed addresses renamed based on their sections.")
