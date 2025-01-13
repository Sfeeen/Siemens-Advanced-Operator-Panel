import chipwhisperer as cw
import time
import matplotlib.pyplot as plt

# Connect to the ChipWhisperer hardware
import serial

import serial.tools.list_ports

print(serial.tools.list_ports.comports)

scope = cw.scope()
target = cw.target(scope)

renesas_COM_port = "COMX"

def configure_glitch_module():
    """Configure the glitch module for voltage glitching."""

    ### Clock
    scope.clock.clkgen_src = "extclk"
    scope.clock.freq_ctr_src = "extclk"
    scope.clock.adc_src = "extclk_dir"

    # scope.clock.clkgen_freq = 24000000
    # scope.clock.clkgen_freq = 48000000
    # scope.clock.clkgen_freq = 96000000
    print(scope.clock.clkgen_freq)
    print(scope.clock.adc_freq)

    ### GLITCH

    scope.glitch.clk_src = "target"
    scope.glitch.output = "clock_or"
    scope.glitch.output = "glitch_only"
    scope.glitch.output = "enable_only"
    scope.glitch.trigger_src = "manual"
    scope.glitch.trigger_src = "manual"
    # scope.glitch.trigger_src = "continuous"
    scope.glitch.repeat = 1 # Number of glitch pulses
    # scope.glitch.ext_offset = 0  # Number of glitch pulses

    scope.glitch.offset = 10
    scope.glitch.width = 40

    ### IO
    # Enable both low-power and high-power glitch outputs
    scope.io.glitch_lp = True
    scope.io.glitch_hp = True


    # Configure IO1 as high impedance to read success signal
    scope.io.tio1 = "high_z"
    scope.io.tio3 = "gpio_high"  # Set IO3 as GPIO to reset the MCU
    # scope.io.hs2 = "clkgen"

def configure_glitch_module2():
    """Configure the glitch module for voltage glitching."""

    # 4 Mhz sws crash 1 repeat

    scope.clock.clkgen_freq = 4E6
    scope.glitch.clk_src = "clkgen"  # set glitch input clock


    scope.glitch.output = "glitch_only"  # glitch_out = clk ^ glitch
    scope.glitch.trigger_src = "manual"  # glitch only after scope.arm() called


    scope.glitch.offset = -48
    scope.glitch.width = 44

    scope.glitch.ext_offset = 7

    scope.glitch.repeat = 1

    ### IO
    # Enable both low-power and high-power glitch outputs
    scope.io.glitch_lp = True
    scope.io.glitch_hp = True


    # Configure IO1 as high impedance to read success signal
    scope.io.tio1 = "high_z"
    scope.io.tio3 = "gpio_high"  # Set IO3 as GPIO to reset the MCU
    # scope.io.hs2 = "clkgen"

def reset_mcu():
    """Reset the microcontroller by toggling IO3 low."""
    # print(".", end="")
    scope.io.tio3 = "gpio_low"  # Set IO3 as GPIO to reset the MCU
    time.sleep(0.01)  # Wait for 10ms
    scope.io.tio3 = "gpio_high"  # Set IO3 as GPIO to reset the MCU
    time.sleep(0.01)  # Wait for 10ms


def find_best_glitch_offset():

    # scope.glitch.ext_offset = 2000
    for repeat in range(6, 9):
        scope.glitch.repeat = repeat
        print(f"Repeat: {repeat}")
        for _ in range(100):
            port = wait_till_receiving_S()
            # time.sleep(2)
            if port and port.is_open:
                print(".", end="")
                scope.arm()
                time.sleep(0.1)
                print_data_from_serial_port(port)
                # if glitch_worked():
                #     print("Worked")

                port.close()  # Close the port
                del port
        # time.sleep(1)


def printblue(text, end='\n', flush=False):
    """
    Prints the given text in blue using ANSI escape codes.
    Parameters:
        text (str): The text to print.
        end (str): The string appended after the last character. Default is a newline.
        flush (bool): Whether to forcibly flush the output stream. Default is False.
    """
    print(f"\033[94m{text}\033[0m", end=end, flush=flush)

def print_data_from_serial_port(port):
    worked = False
    try:
        while port.in_waiting > 0:
            raw_data = port.read()
            data = raw_data.decode('utf-8', errors='ignore')  # Read and decode the data



            if data != 'S' and data != 'R':
                worked = True
                printblue(data, end='', flush=True)  # Print data char by char, excluding 'S'
                printblue(raw_data)  # Convert to ASCII and then to hex

        if worked:
            pass
            # input("Check above")
    except Exception as e:
        print(f"Error while reading data: {e}")

def get_com_port():
    global renesas_COM_port
    available_ports = serial.tools.list_ports.comports()

    ch340_found = False  # Flag to check if CH340 port is found

    if available_ports:
        # Add each port to the dropdown with its description
        for port in available_ports:

            if 'CH340' in port.description:
                ch340_found = True
                renesas_COM_port = port.device

    if not ch340_found:
        print("Renesas device not found, retrying...")
        time.sleep(1)
        return get_com_port()

def wait_till_receiving_S():


    def rerun():
        print("RE")
        return wait_till_receiving_S()

    reset_mcu()
    time.sleep(0.1)

    # Initialize serial port
    try:
        get_com_port()
        ser = serial.Serial(renesas_COM_port, 9600, timeout=1)
        ser.flush()
        # print("Listening on COM3...")
    except serial.SerialException as e:
        print(f"Error: {e}")
        return rerun()
        # return None

    consecutive_s_count = 0

    try:
        start_time = time.time()
        while True:
            if time.time() - start_time > 1:  # Timeout after 1 second
                print("T")
                ser.close()
                return rerun()

            if ser.in_waiting > 0:
                data = ser.read().decode('utf-8', errors='ignore')  # Read and decode the data

                if data == 'S':
                    consecutive_s_count += 1
                    # print(f"Received 'S' ({consecutive_s_count}/5)")
                else:
                    consecutive_s_count = 0  # Reset count if a different character is received

                if consecutive_s_count >= 5:
                    # print("Received 5 consecutive 'S' characters!")
                    return ser
    except KeyboardInterrupt:
        print("Exiting program.")
    except Exception as e:
        print(f"Error: {e}")
        return rerun()

def glitch_worked():
    """Check if the glitch worked by reading IO1 state."""
    worked = scope.io.tio_states[0]  # Assuming IO1 corresponds to index 1
    return worked
def try_gli():
    while True:
        scope.arm()
        time.sleep(0.1)



def main():
    # get_com_port()
    try:
        configure_glitch_module2()
        # find_best_glitch_offset()
        try_gli()

    except KeyboardInterrupt:

        print("Interrupted by user.")
    finally:
        # Clean up and disconnect
        scope.dis()
        target.dis()

if __name__ == "__main__":
    main()
