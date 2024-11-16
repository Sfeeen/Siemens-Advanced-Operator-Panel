import idaapi
import idautils
import idc

# Specify output file for function names
output_file = "function_names.txt"

with open(output_file, "w") as f:
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        f.write(f"{func_ea:x},{func_name}\n")

print(f"Function names exported to {output_file}")
