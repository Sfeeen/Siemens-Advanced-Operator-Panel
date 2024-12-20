import serial
import time


def send_character():
    # Configure the serial connection
    try:
        arduino = serial.Serial(port='COM18', baudrate=9600, timeout=1)
        time.sleep(2)  # Wait for the serial connection to initialize

        # Character to send
        character = 'S'  # Replace with any character you want to send
        print(f"Sending character: {character}")

        # Send the character
        arduino.write(character.encode())

        # Read and print the response from the Arduino
        time.sleep(0.1)  # Allow time for Arduino to respond
        while arduino.in_waiting > 0:
            response = arduino.read().decode('utf-8', errors='replace').strip()
            print(f"Response: {response}")

    except serial.SerialException as e:
        print(f"Error: {e}")
    finally:
        # Close the serial connection
        if 'arduino' in locals() and arduino.is_open:
            arduino.close()
            print("Serial port closed.")


if __name__ == "__main__":
    send_character()
