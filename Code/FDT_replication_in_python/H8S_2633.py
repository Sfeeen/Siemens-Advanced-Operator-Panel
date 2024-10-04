import serial
import time


# Configure the serial connection
def configure_serial_connection(baud_rate):
    ser = serial.Serial(
        port='COM9',  # COM port defined as COM3
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
        print(f"Attempt {attempts + 1}: Sent 0x00")
        time.sleep(0.1)

        # Check for response
        if ser.in_waiting > 0:
            response = ser.read(1)
            print(f"Received: {response.hex()}")
            if response == zero_byte:
                print("Bit rate matching successful!")
                return True

        attempts += 1

    print("Bit rate matching failed.")
    return False

def auto_bit_rate_matching():
    # Bit rate matching and initial communication at 9600 bps
    baud_rates = [9600, 4800, 1200]

    for baud_rate in baud_rates:
        print(f"Trying bit rate matching at {baud_rate} bps...")
        ser = configure_serial_connection(baud_rate)

        # Perform bit rate matching
        if bit_rate_matching(ser):
            return ser
        else:
            ser.close()
            raise Exception("Auto bit rate matching failed...")


def send_and_receive_data(ser, data_to_send, expected_response_length):
    # Send data
    ser.write(data_to_send)
    print(f"Sent: {data_to_send.hex()}")

    # Receive data
    time.sleep(1)  # Small delay to give time for the microcontroller to respond
    received_data = ser.read(expected_response_length)
    print(f"Received: {received_data.hex()}")

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
        raise Exception("Program verification failed")


def write_control_program_transfer(ser, write_control_program_path):
    # Step (a): Send start code for write control program transfer
    start_code = bytes([0x55])
    print("Sending start code H55...")
    rdata = send_and_receive_data(ser, start_code, 1)

    # Step (b): Expect HAA after sending start code
    if rdata != b'\xaa':
        raise Exception("Failed to receive expected HAA after sending start code.")

    download_kernel(ser, write_control_program_path, echo=True)

    time.sleep(1)  # Small delay to give time for the microcontroller to respond
    rdata = ser.read(1)
    print(rdata)

    print("Write control program transfer completed successfully.")

def main_program_transfer(ser, main_program_path):

    download_kernel(ser, main_program_path, echo=False)

    print("main program transfer completed successfully.")

ACK = bytes([6])
def perform_configuration(ser, new_baud):
    line_size_inquiry = bytes([0x27])
    rdata = send_and_receive_data(ser, line_size_inquiry, 5)
    print(f"Line size response: {str(rdata)}")

    select_device = bytes([0x10, 0x04, 0x30, 0x32, 0x30, 0x33, 0x27])
    rdata = send_and_receive_data(ser, select_device, 1)
    if rdata != ACK:
        raise Exception(f"Failed to select device:{str(rdata)}")

    select_clock_mode = bytes([0x11, 0x01, 0x00, 0xEE])
    rdata = send_and_receive_data(ser, select_clock_mode, 1)
    if rdata != ACK:
        raise Exception(f"Failed to select clockmode:{str(rdata)}")

    select_baudrate = bytes([0x3F, 0x06, 0x02, 0x40, 0x09, 0x60, 0x01, 0x01, 0x0e])
    rdata = send_and_receive_data(ser, select_baudrate, 1)
    if rdata != ACK:
        raise Exception(f"Failed to select baudrate:{str(rdata)}")


def boot_program_status_inquiry(ser):
    inquiry = bytes([0x4F])
    rdata = send_and_receive_data(ser, inquiry, 5)
    print(f"boot_program_status_inquiry response: {str(rdata)}")

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
    print(f"Received: {received_data.hex()}")


    # Check how many bytes are available to read
    available_bytes = ser.in_waiting
    print(f"Bytes available to read: {available_bytes}")

    # If there are enough bytes, read them
    if available_bytes > 0:
        received_data = ser.read(available_bytes)
        print(f"Received: {received_data.hex()}")
    else:
        print("No data available to read.")

def communicate_with_device():
    # ser = configure_serial_connection(9600)
    ser = auto_bit_rate_matching()

    write_control_program_transfer(ser, "kernel/2633_micro_kernel/uGen2633.cde")

    new_baud = 57600
    perform_configuration(ser, new_baud)

    ser.baudrate = new_baud

    main_program_transfer(ser, "kernel/2633_main_kernel/communicated_main_kernel.bin")

    boot_program_status_inquiry(ser)

    user_MAT_blank_check(ser)

    boot_program_status_inquiry(ser)

    upload_page(ser)

    ser.close()


# Main function to start the communication process
if __name__ == "__main__":
    communicate_with_device()

    # with open("kernel/2633_main_kernel/communicated_main_kernel.bin", "rb") as program_file:
    #     program_data = program_file.read()
    #
    # print(len(program_data))


