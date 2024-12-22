import chipwhisperer as cw
import time

# Connect to the ChipWhisperer hardware
scope = cw.scope()
target = cw.target(scope)

def configure_glitch_module():
    """Configure the glitch module for voltage glitching."""
    scope.glitch.clk_src = "clkgen"
    scope.glitch.output = "glitch_only"
    scope.glitch.trigger_src = "continuous"
    scope.glitch.repeat = 1  # Number of glitch pulses

    # Set glitch width and offset. Adjust these values for your target.
    scope.glitch.width = 10  # Width of the glitch pulse (adjust as needed)
    scope.glitch.offset = -10  # Offset of the glitch pulse (adjust as needed)

    # Enable both low-power and high-power glitch outputs
    scope.io.glitch_lp = True
    scope.io.glitch_hp = True

    # Configure IO1 as high impedance to read success signal
    scope.io.tio1 = "high_z"

def glitch_microcontroller():
    """Attempt to glitch the microcontroller and check for success via IO1 pin."""
    print("Starting continuous glitching...")
    scope.arm()
    try:
        while True:
            # Check the state of IO1 to determine if the glitch was successful
            success = scope.io.tio_states == "high"
            if success:
                print("Glitch successful! IO1 pin is HIGH.")
                break
            else:
                print("Glitching in progress. IO1 pin is LOW.")
            # time.sleep(0.1)  # Add a short delay between glitch attempts
    except KeyboardInterrupt:
        print("Continuous glitching interrupted by user.")


def print_IO_state():
    while True:

        print(scope.io.tio_states[0])
        time.sleep(0.5)
def main():
    try:
        configure_glitch_module()
        # glitch_microcontroller()
        print_IO_state()
    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        # Clean up and disconnect
        scope.dis()
        target.dis()

if __name__ == "__main__":
    main()
