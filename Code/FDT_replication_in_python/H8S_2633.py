import serial
import time
import serial.tools.list_ports

# Configure the serial connection
def configure_serial_connection(baud_rate, port='COM24'):
    ser = serial.Serial(
        port=port,  # COM port defined as COM3
        baudrate=baud_rate,  # Baud rate for communication
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=1  # Timeout for reading
    )
    return ser

# Function for bit rate matching
def bit_rate_matching(ser):
    zero_byte = bytes([0x00])
    max_attempts = 50
    attempts = 0

    while attempts < max_attempts:
        # Send zero byte for bit rate matching
        ser.write(zero_byte)
        # print(f"Attempt {attempts + 1}: Sent 0x00")
        time.sleep(0.1)

        # Check for response
        if ser.in_waiting > 0:
            response = ser.read(1)
            # print(f"Received: {response.hex()}")
            if response == zero_byte:
                # print("Bit rate matching successful!")
                return True

        attempts += 1

    print("Bit rate matching failed.")
    return False

def auto_bit_rate_matching(port, close=True, arduino_port=None):
    # Bit rate matching and initial communication at 9600 bps
    baud_rates = [9600, 4800, 1200]

    # print(port)
    for baud_rate in baud_rates:
        # print(f"Trying bit rate matching at {baud_rate} bps...")
        ser = configure_serial_connection(baud_rate, port)

        # Perform bit rate matching
        if bit_rate_matching(ser):
            return ser
        else:
            if close:
                ser.close()
                raise Exception("Auto bit rate matching failed...")
            else:
                reset_2633(arduino_port)
                time.sleep(0.1)
                return auto_bit_rate_matching(port, close=close, arduino_port=arduino_port)


def send_and_receive_data(ser, data_to_send, expected_response_length):
    # Send data
    ser.write(data_to_send)
    # print(f"Sent: {data_to_send.hex()}")

    # Receive data
    time.sleep(1)  # Small delay to give time for the microcontroller to respond
    received_data = ser.read(expected_response_length)
    # print(f"Received: {received_data.hex()}")

    return received_data

def download_kernel(ser, kernel_path, echo):
    print(f"Downloading kernel: {kernel_path}")

    # Step (c): Send number of bytes in the write control program
    with open(kernel_path, "rb") as program_file:
        program_data = program_file.read()

    program_size = len(program_data)
    print(f"Program size: {program_size} bytes")

    if echo:
        # Send the high and low bytes of the program size
        high_byte = (program_size >> 8) & 0xFF
        low_byte = program_size & 0xFF
        print(f"Sending high byte: {high_byte:02X}, low byte: {low_byte:02X}")

        # Send high byte
        rdata = send_and_receive_data(ser, bytes([high_byte]), 1)
        if echo and rdata != bytes([high_byte]):
            raise Exception("Failed to receive verification for high byte.")

        if not echo and rdata != ACK:
            raise Exception("Failed to receive verification for high byte.")

        # Send low byte
        rdata = send_and_receive_data(ser, bytes([low_byte]), 1)
        if echo and rdata != bytes([low_byte]):
            raise Exception("Failed to receive verification for low byte.")

        if not echo and rdata != ACK:
            raise Exception("Failed to receive verification for low byte.")
    else:
        rdata = send_and_receive_data(ser, bytes([0x06]), 1)
        rdata = send_and_receive_data(ser, bytes([0x40]), 1)

    # Step (e): Send the actual write control program
    print("Sending write control program data...")
    response_lenght = len(program_data) if echo else 1
    rdata = send_and_receive_data(ser, program_data, response_lenght)

    if (echo and (rdata != program_data)) or (not echo and (rdata != ACK)):
        print("Program verification failed")
        # raise Exception("Program verification failed")


def write_control_program_transfer(ser, write_control_program_path):
    # Step (a): Send start code for write control program transfer
    start_code = bytes([0x55])
    print("Sending start code H55...")
    rdata = send_and_receive_data(ser, start_code, 1)

    # Step (b): Expect HAA after sending start code
    if rdata != b'\xaa':
        return f"Write control program aborted received: {rdata}"
        # raise Exception("Failed to receive expected HAA after sending start code.")

    download_kernel(ser, write_control_program_path, echo=True)

    time.sleep(1)  # Small delay to give time for the microcontroller to respond
    rdata = ser.read(1)
    print(rdata)

    return "Write control program transfer completed successfully."

def main_program_transfer(ser, main_program_path):

    download_kernel(ser, main_program_path, echo=False)

    print("main program transfer completed successfully.")
    return "main program transfer completed successfully."

ACK = bytes([6])

def send_line_size_inquiry(ser):
    line_size_inquiry = bytes([0x27])
    rdata = send_and_receive_data(ser, line_size_inquiry, 5)
    print(f"Line size response: {str(rdata)}")
    return f"Line size response: {str(rdata)}"

def select_device(ser):
    select_device = bytes([0x10, 0x04, 0x30, 0x32, 0x30, 0x33, 0x27])
    rdata = send_and_receive_data(ser, select_device, 1)
    if rdata != ACK:
        print(f"Failed to select device:{str(rdata)}")
        return f"Failed to select device:{str(rdata)}"
        # raise Exception(f"Failed to select device:{str(rdata)}")

    print(f"Device selected!")
    return f"Device selected!"


def select_clock_mode(ser):
    select_clock_mode = bytes([0x11, 0x01, 0x00, 0xEE])
    rdata = send_and_receive_data(ser, select_clock_mode, 1)
    if rdata != ACK:
        print(f"Failed to select clockmode:{str(rdata)}")
        return f"Failed to select clockmode:{str(rdata)}"
        # raise Exception(f"Failed to select clockmode:{str(rdata)}")

    print(f"Clock mode selected!")
    return f"Clock mode selected!"

def select_baudrate(ser):
    select_baudrate = bytes([0x3F, 0x06, 0x02, 0x40, 0x09, 0x60, 0x01, 0x01, 0x0e])
    rdata = send_and_receive_data(ser, select_baudrate, 1)
    if rdata != ACK:
        print(f"Failed to select baudrate:{str(rdata)}")
        return f"Failed to select baudrate:{str(rdata)}"
        # raise Exception(f"Failed to select baudrate:{str(rdata)}")
    print(f"Baudrate selected!")
    return f"Baudrate selected!"

def perform_configuration(ser):
    output = ""
    output += send_line_size_inquiry(ser) + "\n"
    output += select_device(ser)+ "\n"
    output += select_clock_mode(ser)+ "\n"
    output += select_baudrate(ser)+ "\n"
    return output

def boot_program_status_inquiry(ser, readamount=5):
    inquiry = bytes([0x4F])
    rdata = send_and_receive_data(ser, inquiry, readamount)
    print(f"boot_program_status_inquiry response: {str(rdata)}")
    return f"boot_program_status_inquiry response: {str(rdata)}"

def user_MAT_blank_check(ser):
    inquiry = bytes([0x4D])
    rdata = send_and_receive_data(ser, inquiry, 1)
    if rdata != ACK:
        print(f"user MAT not blank {str(rdata)}!!!")

def upload_page(ser):
    inquiry = bytes([0x52, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xA0])

    ser.write(inquiry)

    # Receive data
    time.sleep(1)  # Small delay to give time for the microcontroller to respond
    received_data = ser.read(5)
    # print(f"Received: {received_data.hex()}")


    # Check how many bytes are available to read
    available_bytes = ser.in_waiting
    print(f"Bytes available to read: {available_bytes}")

    # If there are enough bytes, read them
    if available_bytes > 0:
        received_data = ser.read(available_bytes)
        print(f"Received: {received_data.hex()}")
    else:
        print("No data available to read.")

def communicate_with_device(port):
    # ser = configure_serial_connection(9600)
    ser = auto_bit_rate_matching(port)

    # write_control_program_transfer(ser, "kernel/2633_micro_kernel/uGen2633_patched_4F.cde")
    write_control_program_transfer(ser, "kernel/2633_micro_kernel/uGen2633_patched_spitout_from_RAMSTART.cde")

    ser.write([0x4F])

    # Send a command to the microcontroller (e.g., 0x4F)
    # ser.write([0x4F])



    # Wait for the response
    time.sleep(1)  # Delay to give time for the microcontroller to respond
    #
    # Open file in append mode (binary mode to handle raw bytes)
    with open("received_bytes_from_address_0x00000000.bin", "ab") as f:  # 'ab' mode opens the file for appending in binary
        # Read available data and append byte by byte
        while True:
            if ser.in_waiting:  # Check if data is available
                byte = ser.read(1)  # Read one byte
                print(f"Received byte: {byte.hex()}")  # Print byte in hex format
                # f.write(byte)  # Append the byte to the file
                # f.flush()  # Ensure the data is written to disk immediately
            # boot_program_status_inquiry(ser, readamount=0xFFFFFF)  # Continuously check status

    #
    # # Read available data and print byte by byte
    # while True:
    #     if ser.in_waiting:  # Check if data is available
    #         byte = ser.read(1)  # Read one byte
    #         print(f"Received byte: {byte.hex()}")  # Print byte in hex format

    # # Receive data
    # time.sleep(1)  # Small delay to give time for the microcontroller to respond
    # received_data = ser.read(expected_response_length)
    # print(f"Received: {received_data.hex()}")
    # while 1:
    #     boot_program_status_inquiry(ser, readamount=0xFFFFFF)
    # boot_program_status_inquiry(ser, readamount=7)
    # boot_program_status_inquiry(ser, readamount=7)
    # new_baud = 57600
    # perform_configuration(ser)
    #
    # ser.baudrate = new_baud
    #
    # # main_program_transfer(ser, "kernel/2633_main_kernel/communicated_main_kernel_patched_4F.bin")
    # main_program_transfer(ser, "kernel/2633_main_kernel/communicated_main_kernel.bin")
    #
    # boot_program_status_inquiry(ser, readamount=7)
    # boot_program_status_inquiry(ser, readamount=7)
    # boot_program_status_inquiry(ser, readamount=7)

    # user_MAT_blank_check(ser)
    #
    # boot_program_status_inquiry(ser)
    #
    # upload_page(ser)
    time.sleep(10)

    ser.close()


def combine_files(first_file, second_file, output_file):
    # Load the first and second files
    with open(first_file, 'rb') as f1:
        first_data = f1.read()
    with open(second_file, 'rb') as f2:
        second_data = f2.read()

    # Define the target offsets
    first_offset = 0xFFC000
    second_offset = 0xFFC800
    offset_difference = second_offset - first_offset

    # Check the size of the first file and pad it if necessary
    first_data_size = len(first_data)
    if first_data_size < offset_difference:
        padding_size = offset_difference - first_data_size
        padding = b'\x00' * padding_size
        first_data += padding

    # Combine the files
    combined_data = first_data + second_data

    # Write the combined data to the output file
    with open(output_file, 'wb') as output:
        output.write(combined_data)

    print(f"Combined file created: {output_file}")


def get_com_port():
    available_ports = serial.tools.list_ports.comports()

    ch340_found = False  # Flag to check if CH340 port is found

    if available_ports:
        # Add each port to the dropdown with its description
        for port in available_ports:

            if 'CH340' in port.description:
                return port.device


def find_next_different_byte(file_path, start_address):
    try:
        with open(file_path, "rb") as f:
            # Seek to the starting address
            f.seek(start_address)

            # Read the byte at the start address
            initial_byte = f.read(1)
            if not initial_byte:
                return f"Start address {hex(start_address)} is out of file range."

            # Now iterate byte by byte
            current_address = start_address + 1
            while True:
                f.seek(current_address)
                current_byte = f.read(1)
                if not current_byte:  # EOF
                    return "End of file reached without finding a different byte."

                if current_byte != initial_byte:
                    return f"Different byte found at address {hex(current_address)}: {current_byte.hex()}"

                current_address += 1

    except FileNotFoundError:
        return f"File not found: {file_path}"
    except Exception as e:
        return f"An error occurred: {str(e)}"


def download_nano_kernel(port, start_address_long_hex=f"00FFB000"):

    ser = auto_bit_rate_matching(port)

    import os
    import struct
    import time
    from shutil import copyfile

    def hex_to_bytes(hex_str):
        # Convert the hex string to a byte array
        return bytes.fromhex(hex_str)

    # Paths for original and modified nanokernel files
    original_kernel_path = "kernel/2633_nano_kernel/nanokernel.bin"
    modified_kernel_path = f"kernel/2633_nano_kernel/nanokernel_{start_address_long_hex}.bin"

    # Copy the original file to create a modifiable copy
    copyfile(original_kernel_path, modified_kernel_path)

    # Modify the nanokernel file
    start_address_bytes = hex_to_bytes(start_address_long_hex)
    if len(start_address_bytes) != 4:
        raise ValueError("start_address_long_hex must be 8 hex characters long (4 bytes).")

    with open(modified_kernel_path, "r+b") as f:
        # Read the file data
        data = f.read()
        if len(data) >= 8:  # Ensure the file is large enough to modify
            f.seek(6)  # Move to the 3rd byte (index 2, 0-based indexing)
            f.write(start_address_bytes)  # Overwrite the next 4 bytes with the address
        else:
            raise ValueError("Nanokernel file is too small to modify the specified bits.")

    print(f"Modified nanokernel file saved at: {modified_kernel_path}")

    write_control_program_transfer(ser, modified_kernel_path)

    # Ensure the dump_receives directory exists
    os.makedirs("dump_receives", exist_ok=True)

    # Open the file and receive data
    received_filepath = f"dump_receives/{time.time()}_start_address_{start_address_long_hex}.bin"

    with open(received_filepath, "ab") as f:
        while True:
            if ser.in_waiting:  # Check if data is available
                byte = ser.read(1)  # Read one byte
                print(f"Received byte: {byte.hex()}")  # Print byte in hex format
                f.write(byte)  # Append the byte to the file
                f.flush()  # Ensure the data is written to disk immediately

    print(f"Received data saved at: {received_filepath}")



def fuzz_prekernel(port, arduino_ser):
    # reset_2633(arduino_port)
    # time.sleep(1)

    # try different handshake start codes
    try:
        for start_handschake_value in range(0, 255):
            # print(f"Handshake value: ", start_handschake_value)

            time.sleep(0.1)
            ser = auto_bit_rate_matching(port, close=False, arduino_port=arduino_ser)

            start_code = bytes([start_handschake_value])
            rdata = send_and_receive_data(ser, start_code, 1)

            print(start_handschake_value, rdata)
            if len(rdata) > 0:
                print("JAAAAAAAAAAAAAAAaaaaa")
            ser.close()

            reset_2633(arduino_ser)
            time.sleep(1)

    except Exception as e:
        print(str(e))
        reset_2633(arduino_ser)


def reset_2633(arduino):
    try:
        if arduino.is_open:

            # Character to send
            character = 'S'  # Replace with any character you want to send
            # print(f"Sending character: {character}")

            # Send the character
            arduino.write(character.encode())

            # Read and print the response from the Arduino
            time.sleep(0.1)  # Allow time for Arduino to respond
            # Read the entire line from the Arduino
            response = arduino.readline().decode('utf-8', errors='replace').strip()
            # print(f"{response}")
        else:
            print("Arduino is not connected.")

    except serial.SerialException as e:
        print(f"Error connecting to Arduino: {e}")
    except KeyboardInterrupt:
        print("\nExiting program.")

# Main function to start the communication process
if __name__ == "__main__":
    # Example usage:

    # file_path = "received_bytes_from_address_0x00000000.bin"
    # start_address = 0x000
    # result = find_next_different_byte(file_path, start_address)
    # print(result)

    arduino_ser = serial.Serial('COM18', 9600, timeout=1)
    time.sleep(2)


    reset_2633(arduino_ser)
    cp = get_com_port()
    fuzz_prekernel(cp, arduino_ser)

    # # Usage
    # # combine_files('kernel/2633_micro_kernel/uGen2633_original.cde', 'kernel/2633_main_kernel/Genm2633.cde', 'kernel/2633_both_kernels/combined_kernels')
    #

    # cp = get_com_port()
    # download_nano_kernel(cp)

    # communicate_with_device(cp)
    #
    # # with open("kernel/2633_main_kernel/communicated_main_kernel.bin", "rb") as program_file:
    # #     program_data = program_file.read()
    # #
    # # print(len(program_data))


