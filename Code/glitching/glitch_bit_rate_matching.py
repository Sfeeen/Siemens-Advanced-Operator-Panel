import chipwhisperer as cw
import time

# Connect to the ChipWhisperer hardware
import numpy as np

scope = cw.scope()
target = cw.target(scope)

target.baud = 9600

# GLITCH
scope.glitch.clk_src = "clkgen"
scope.glitch.output = "enable_only"
# scope.glitch.output = "glitch_only"
scope.glitch.trigger_src = "manual"
scope.glitch.trigger_src = "ext_continuous"
# scope.glitch.repeat = 8000
# scope.glitch.ext_offset = 1000

# CLOCK
# scope.clock.clkgen_freq = 32E6 # Overclocking can make glitching better, max freq: 81Mhz
scope.clock.clkgen_freq = 96E6

# IO
scope.io.glitch_lp = True
scope.io.glitch_hp = True
scope.io.tio1 = "serial_tx"  # Read pin from Renesas to see if glitch worked
scope.io.tio2 = "serial_rx"  # Can be used to receive serial
scope.io.tio3 = "gpio_high"  # To /RESET pin
# scope.io.tio4 = "serial_tx"
# scope.io.hs2 = "clkgen"  # Attach to clockinput Renesas chip EXTAL
# scope.io.hs2 = "glitch"  # Attach to clockinput Renesas chip EXTAL

# TRIGGER
scope.trigger.triggers = "tio1"

print(scope.trigger)


def reset_mcu():
    """Reset the microcontroller by toggling IO3 low."""
    scope.io.tio3 = "gpio_low"  # Set IO3 as GPIO to reset the MCU
    time.sleep(0.001)  # Wait for 10ms
    scope.io.tio3 = "gpio_high"  # Set IO3 as GPIO to reset the MCU
    time.sleep(0.001)  # Wait for 10ms


def home_made_flush():
    if target.in_waiting():
        data = target.readbytes()


def keep_reading_untill_stops(data, filename):
    full_data = data
    keep_going = True

    time.sleep(0.01)
    print("start reading")
    while target.in_waiting() and keep_going:
        print('.', end="")
        new_data = target.readbytes()
        full_data += new_data
        if len(full_data) > 16776000:
            if b'SVEN' in new_data:
                print("SVEN found second time")
                keep_going = False
        if len(full_data) > 17777216:
            print("certainly enough data retrieved...")
            keep_going = False
        time.sleep(0.01)

    print("done reading:", full_data)

    total_bytes = len(full_data)

    # Save the full data to a binary file
    with open(f"glitch_dumps_boot_mode/BYTES_{str(total_bytes)}_{filename}_.bin", 'wb') as bin_file:
        bin_file.write(full_data)

    return total_bytes


def do_bit_rate_matching():
    glitch_succesfull = False
    count = 0

    home_made_flush()

    scope.glitch.manual_trigger()
    target.write([0x00, 0x00, 0x00])  # Three is minimum
    # scope.glitch.manual_trigger()

    time.sleep(0.001)  # required

    if target.in_waiting():
        data = target.readbytes()

        if len(data) == 0:
            print("F", end="")
        else:
            if len(data) == 1 and data == b'\x00':
                print("N", end="")
            else:
                if len(data) > 1:
                    print("GOOD!")
                    glitch_succesfull = True
                    count = keep_reading_untill_stops(data,
                                                      filename=f"REP_{str(scope.glitch.repeat)}_OFFSET{str(scope.glitch.ext_offset)}")
                    print(count)
                else:
                    print("Bad response:", data)

        # if len(data) > 0:
        #     print(data)
        #
        # if data == b'\x00':
        #     print("Bit rate matched!")
    else:
        print("F", end="")

    return glitch_succesfull, count


gc = cw.GlitchController(groups=["success", "reset", "normal", "bigsuccess"],
                         parameters=["ext_offset", "repeat", "tries"])

# scope.glitch.repeat = 100
# scope.glitch.ext_offset = 16000

num_tries = 1  # increase to get better glitch stats
gc.set_range("tries", 1, num_tries)
#
# gc.set_range("ext_offset", 1, 16000)
gc.set_range("ext_offset", 6000, 10000)
gc.set_range("repeat", 1, 100)

gc.set_global_step(1)
#
gc.set_step("tries", 1)
gc.set_step("ext_offset", 20)
gc.set_step("repeat", 1)
#
import matplotlib.pyplot as plt

cw.set_all_log_levels(cw.logging.CRITICAL)

highest_byte_count = -1
best_parameter_value = -1
#
resultss = [1]  # To store the success counts for each repeat value
parameter_values = [1]
byte_counts = [1]

print("Script will start!")

for glitch_setting in gc.glitch_values():
    scope.glitch.ext_offset = glitch_setting[0]
    scope.glitch.repeat = glitch_setting[1]
    try_counter = glitch_setting[2]

    reset_mcu()
    success, count = do_bit_rate_matching()
    if success:
        parameter_values.append(glitch_setting[1])
        resultss.append(glitch_setting[0])
        byte_counts.append(count)

        if count > highest_byte_count:
            highest_byte_count = count
            best_parameter_value = glitch_setting[0]

        had_success = True

        print(
            f"SUCCES: glitch ext offset: {glitch_setting[0]} repeat: {glitch_setting[1]} bytes: {count} | best so far: {highest_byte_count} bytes at setting {best_parameter_value}")

print("Best", highest_byte_count, num_tries, best_parameter_value)
print("Done glitching")

# Normalize the third_dimension for color mapping (optional but recommended)
normalized_third_dim = np.array(byte_counts) / max(byte_counts)

# Scatter plot with color mapping
plt.scatter(parameter_values, resultss, c=normalized_third_dim, cmap='Reds', label='Data Points',alpha=0.6)

# Add labels, title, legend, and grid
plt.xlabel("Repeat Value")
plt.ylabel("ext_offset")
plt.title("Glitch Parameters with Color Intensity")
plt.colorbar(label='Amount bytes (higher = redder)')  # Add color bar for reference
plt.legend()
plt.grid()

# Show the plot
plt.show()
#
# enable logging
cw.set_all_log_levels(cw.logging.WARNING)

scope.dis()
target.dis()

if __name__ == '__main__':
    pass
