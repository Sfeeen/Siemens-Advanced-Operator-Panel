def compare_bin_files(file1_path, file2_path):
    with open(file1_path, 'rb') as file1, open(file2_path, 'rb') as file2:
        address = 0
        while True:
            byte1 = file1.read(1)
            byte2 = file2.read(1)

            # Break if we reach the end of either file
            if not byte1 or not byte2:
                break

            # Convert bytes to integers for comparison
            byte1_val = ord(byte1)
            byte2_val = ord(byte2)

            # Check if bytes are different
            if byte1_val != byte2_val:
                print(f"Address: {address:08X}, File1: {byte1_val:02X}, File2: {byte2_val:02X}")

            address += 1


if __name__ == '__main__':
    # Example usage:
    compare_bin_files('kernel/2633_micro_kernel/uGen2633_patched_spitout_content.cde', 'kernel/2633_micro_kernel/uGen2633_original.cde')
