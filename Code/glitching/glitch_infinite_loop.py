import chipwhisperer as cw
import time
import matplotlib.pyplot as plt

# Connect to the ChipWhisperer hardware
scope = cw.scope()
target = cw.target(scope)

def configure_glitch_module():
    """Configure the glitch module for voltage glitching."""
    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = "clock_or"
    scope.glitch.output = "glitch_only"
    scope.glitch.output = "enable_only"
    # scope.glitch.output = "clock_only"
    scope.glitch.trigger_src = "manual"
    # scope.glitch.trigger_src = "continuous"
    scope.glitch.repeat = 1  # Number of glitch pulses
    scope.glitch.ext_offset = 0  # Number of glitch pulses

    scope.glitch.offset = 10
    scope.glitch.width = 1

    # Enable both low-power and high-power glitch outputs
    scope.io.glitch_lp = True
    scope.io.glitch_hp = True

    # scope.clock.clkgen_freq = 24000000
    # scope.clock.clkgen_freq = 48000000
    # scope.clock.clkgen_freq = 96000000

    # Configure IO1 as high impedance to read success signal
    scope.io.tio1 = "high_z"
    scope.io.tio3 = "gpio_high"  # Set IO3 as GPIO to reset the MCU
    # scope.io.hs2 = "clkgen"

def reset_mcu():
    """Reset the microcontroller by toggling IO3 low."""
    print(".", end="")
    scope.io.tio3 = "gpio_low"  # Set IO3 as GPIO to reset the MCU
    time.sleep(0.01)  # Wait for 10ms
    scope.io.tio3 = "gpio_high"  # Set IO3 as GPIO to reset the MCU
    time.sleep(0.01)  # Wait for 10ms

def find_best_glitch_duration():
    """Test multiple glitch durations to find the best one."""
    best_duration = None
    max_success = 0

    for duration in range(20, 50, 4):  # Test durations from 1 to 100 (adjust range as needed)
        # scope.glitch.width = duration
        scope.glitch.repeat = duration
        print(f"Testing glitch duration: {duration}")

        success_count = 0

        for _ in range(100):  # Send exactly 200 glitches per duration
            scope.arm()
            time.sleep(0.01)  # Short delay between glitches

            if glitch_worked():
                success_count += 1
                reset_mcu()  # Reset the MCU if a glitch is successful
            else:
                pass
                # print("didnt")

        print(f"Glitch duration {duration}: {success_count} successful glitches")

        if success_count > max_success:
            max_success = success_count
            best_duration = duration

    print(f"Best glitch duration: {best_duration} with {max_success} successful glitches")
    return best_duration

def find_best_glitch_repeats():
    """Test multiple glitch repeats to find the best one and plot the results."""
    best_repeat = None
    max_success = 0
    results = []  # To store the success counts for each repeat value
    repeat_values = []

    amount_glitches_per_try = 1000

    for repeat in range(43, 50, 1):  # Test repeat values from 1 to 100
        scope.glitch.repeat = repeat
        repeat_values.append(repeat)
        reset_mcu()
        print(f"Testing glitch repeat: {repeat}")

        success_count = 0

        for _ in range(amount_glitches_per_try):  # Send exactly 100 glitches per repeat value
            scope.arm()
            time.sleep(0.01)  # Short delay between glitches

            if glitch_worked():
                success_count += 1
                reset_mcu()  # Reset the MCU if a glitch is successful

        success_percent = success_count * 100 / amount_glitches_per_try
        results.append(round(success_percent, 2))  # Append success count for each repeat value
        print(f"Glitch repeat {repeat}: {success_count} successful glitches")

        if success_count > max_success:
            max_success = success_count
            best_repeat = repeat

    # Plot the results
    x_axis = repeat_values
    plt.figure()
    plt.plot(x_axis, results, marker='o')
    plt.title("Glitch Success Count vs Repeat Value")
    plt.xlabel("Repeat Value")
    plt.ylabel("Success Count")
    plt.grid()
    plt.show()

    print(f"Best glitch repeat: {best_repeat} with {max_success} successful glitches")
    return best_repeat

def glitch_worked():
    """Check if the glitch worked by reading IO1 state."""
    worked = scope.io.tio_states[0]  # Assuming IO1 corresponds to index 1
    return worked

def try_glitches():
    print("Testing manual glitch trigger...")
    for num in range(1000):  # Adjust the range for more tests
        # scope.arm()
        scope.glitch.manual_trigger()
        time.sleep(0.01)  # Observe one glitch at a time
        print(f"Trigger {num + 1} sent.")


def main():
    try:
        configure_glitch_module()
        # try_glitches()
        # best_duration = find_best_glitch_duration()
        # print(f"Optimal glitch duration found: {best_duration}")
        find_best_glitch_repeats()
    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        # Clean up and disconnect
        scope.dis()
        target.dis()

if __name__ == "__main__":
    main()
