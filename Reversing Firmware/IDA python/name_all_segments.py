import idaapi
import idc

# Define the byte pattern to search for
pattern = b'\xFF\xC0\x00'  # 0xFFC000 in hexadecimal byte format

# Define the RAM regions
ram_regions = [
    (0xFFB000, 0xFFEFBF),
    (0xFFFFC0, 0xFFFFFF)
]

# Search for the pattern within each RAM region
print("Searching for pattern 0xFFC000 in RAM regions...")
found_count = 0
pattern_length = len(pattern)

for start, end in ram_regions:
    current_address = start
    while current_address <= end:
        # Read bytes at the current address
        data = idc.get_bytes(current_address, pattern_length)

        # Check if the data matches the pattern
        if data == pattern:
            print(f"Pattern found at address: 0x{current_address:X}")
            found_count += 1
            # Move to the next byte after the found pattern to continue searching
            current_address += pattern_length
        else:
            # Move to the next byte if no match is found
            current_address += 1

if found_count == 0:
    print("Pattern not found in the RAM regions.")
else:
    print(f"Total occurrences found in RAM regions: {found_count}")
