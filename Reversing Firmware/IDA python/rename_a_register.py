import ida_segment
import ida_name
import idc

# Define addresses and names
addresses = {
    0xFFFFFF74: "TCSR",
    0xFFFFFF76: "RSTCSR",
    0xFFFFA8: "FLMCR1",
    0xFFFFAA: "EBR1",
    0xFFFFAB: "EBR2"
}

# Process each address
for address, new_name in addresses.items():
    # Check if the address is already in a segment
    if idc.get_segm_name(address):
        print(f"Address 0x{address:X} is already in segment: {idc.get_segm_name(address)}")
    else:
        # Create a segment for the specific address
        seg_start = address
        seg_end = address + 1  # End address is exclusive, so it only includes the single address

        # Add the segment
        if ida_segment.add_segm(0, seg_start, seg_end, "CustomSegment", "DATA"):
            print(f"Created segment for address 0x{address:X}")
        else:
            print(f"Failed to create segment for address 0x{address:X}")

    # Rename the address
    if ida_name.set_name(address, new_name, ida_name.SN_FORCE):
        print(f"Renamed 0x{address:X} to {new_name}")
    else:
        print(f"Failed to rename 0x{address:X}")
