import idaapi
import idc

# Specify the file with function names to import
input_file = "function_names.txt"

with open(input_file, "r") as f:
    for line in f:
        addr_str, func_name = line.strip().split(",")
        func_ea = int(addr_str, 16)
        idc.set_name(func_ea, func_name, idc.SN_CHECK)

print("Function names imported successfully")
