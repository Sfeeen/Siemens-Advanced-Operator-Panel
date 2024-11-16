import idaapi
import idc
import ida_name
import re

# Specify the path to your register definitions file
# input_file = "C:\Program Files\IDA Professional 9.0\cfg\h8.cfg"  # Update this path
input_file = r"C:\Users\Sven Onderbeke\Desktop\Siemens Advanced Operator Panel\Reversing Firmware\IDA python\register_names.txt"  # Update this path

# Define the start and end address for the register memory region
REGISTER_SEGMENT_START = 0xFFFFFDAC  # Adjust as needed
REGISTER_SEGMENT_END = 0xFFFFFFBF    # Adjust as needed

# Create a memory segment for registers
if not idaapi.get_segm_by_name("REGISTERS"):
    idaapi.add_segm(0, REGISTER_SEGMENT_START, REGISTER_SEGMENT_END, "REGISTERS", "DATA")

# Regular expression to match register name and address
pattern = re.compile(r"^(\w+)\s+0x([0-9A-Fa-f]+)")

with open(input_file, "r") as f:
    for line in f:
        match = pattern.match(line)
        if match:
            reg_name = match.group(1)
            reg_addr = int(match.group(2), 16)

            # Check if the address is within the segment
            if REGISTER_SEGMENT_START <= reg_addr <= REGISTER_SEGMENT_END:
                ida_name.set_name(reg_addr, reg_name, ida_name.SN_FORCE)
                print(f"Applied name '{reg_name}' to address 0x{reg_addr:X}")

print("Register names applied within the segment successfully.")