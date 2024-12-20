def create_symbol_file(library_path, symbol_name, pins):
    """
    Create a symbol file (.kicad_sym) and add pins.
    Args:
        library_path (str): Path to the library file.
        symbol_name (str): Name of the symbol.
        pins (list): List of pin dictionaries with "name", "number", and "position".
    """
    with open(library_path, "w") as f:
        # Write the symbol header
        f.write(f"(kicad_symbol_lib (version 20211014) (generator KiCad))\n")
        f.write(f"  (symbol \"{symbol_name}\" (pin_names (offset 1.27)) (pin_numbers (offset 1.27)))\n")

        # Add pins
        for pin in pins:
            pin_number = pin["number"]
            pin_name = pin["name"]
            x, y = pin["position"]
            f.write(f"    (pin \"{pin_name}\" {pin_number} (pos {x} {y}) (length 2.54))\n")
        f.write("  )\n")


# Define symbol and pins
library_path = "my_library.kicad_sym"
symbol_name = "GeneratedSymbol"
pins = [
    {"number": "1", "name": "GND", "position": (0, 0)},
    {"number": "2", "name": "VCC", "position": (0, 2.54)},
    {"number": "3", "name": "RESET", "position": (0, 5.08)},
]

# Create the symbol file
create_symbol_file(library_path, symbol_name, pins)
print(f"Symbol library saved to {library_path}")

if __name__ == '__main__':
    pass