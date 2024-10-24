import sys
import serial
import time
from PyQt5 import QtWidgets, uic
import serial.tools.list_ports
from H8S_2633 import *

class MyMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(MyMainWindow, self).__init__()
        uic.loadUi('layout.ui', self)  # Load the .ui file

        # Initialize port_selected as None or empty string
        self.port_selected = None

        # Connect buttons to functions
        self.pushButton_autobitratematching.clicked.connect(self.auto_bit_rate_matching)
        self.pushButton_write_microkernel.clicked.connect(self.write_microkernel)
        self.pushButton_linesizeinquiry.clicked.connect(self.line_size_inquiry)
        self.pushButton_select_device.clicked.connect(self.select_device)
        self.pushButton_select_clockmode.clicked.connect(self.select_clock_mode)
        self.pushButton_select_baudrate.clicked.connect(self.select_baud_rate)
        self.pushButton_write_main_kernel.clicked.connect(self.write_main_kernel)
        self.pushButton_boot_program_status_inquiry.clicked.connect(self.boot_program_status_inquiry)
        self.pushButton_upload_page.clicked.connect(self.upload_page)
        self.btn_refresh_ports.clicked.connect(self.refresh_ports)
        self.pushButton.clicked.connect(self.perform_configuration)

        # Connect dropdown change event to a function
        self.dropdown_comports.currentIndexChanged.connect(self.update_port_selection)

        self.refresh_ports()

        self.ser = False


    def update_port_selection(self):
        # Get the selected item from the dropdown
        selected_item = self.dropdown_comports.currentText()

        # If the dropdown is not empty, split the selected item to get the port
        if selected_item:
            self.port_selected = selected_item.split(" - ")[0]
            self.plainTextEdit_debugoutput.appendPlainText(f"Port selected: {self.port_selected}")
        else:
            # If no item is selected, reset the port_selected
            self.port_selected = None

    def auto_bit_rate_matching(self):
        if not self.port_selected:
            self.plainTextEdit_debugoutput.appendPlainText(f"No com port selected")
        try:
            self.ser = auto_bit_rate_matching(self.port_selected)
            self.plainTextEdit_debugoutput.appendPlainText(f"Bit rate matched on {self.ser.port}")
        except Exception as e:
            self.plainTextEdit_debugoutput.appendPlainText(f"Auto bit rate matching failed: {str(e)}")

    def write_microkernel(self):
        if self.ser:
            # output = write_control_program_transfer(self.ser, "kernel/2633_micro_kernel/uGen2633_patched_inquiry_2.cde")
            output = write_control_program_transfer(self.ser, "kernel/2633_micro_kernel/uGen2633_patched_sven.cde")
            self.plainTextEdit_debugoutput.appendPlainText(output)

    def line_size_inquiry(self):
        if self.ser:
            output = send_line_size_inquiry(self.ser)
            self.plainTextEdit_debugoutput.appendPlainText(output)

    def select_device(self):
        if self.ser:
            output = select_device(self.ser)
            self.plainTextEdit_debugoutput.appendPlainText(output)


    def select_clock_mode(self):
        if self.ser:
            output = select_clock_mode(self.ser)
            self.plainTextEdit_debugoutput.appendPlainText(output)


    def select_baud_rate(self):
        if self.ser:
            output = select_baudrate(self.ser)
            self.plainTextEdit_debugoutput.appendPlainText(output)

    def write_main_kernel(self):
        if self.ser:
            output = main_program_transfer(self.ser, "kernel/2633_main_kernel/communicated_main_kernel.bin")
            self.plainTextEdit_debugoutput.appendPlainText(output)

    def boot_program_status_inquiry(self):
        if self.ser:
            output = boot_program_status_inquiry(self.ser)
            self.plainTextEdit_debugoutput.appendPlainText(output)

    def upload_page(self):
        if self.ser:
            output = upload_page(self.ser)
            self.plainTextEdit_debugoutput.appendPlainText(output)


    def refresh_ports(self):
        # Clear the dropdown menu
        self.dropdown_comports.clear()

        # Get the list of available COM ports
        available_ports = serial.tools.list_ports.comports()

        ch340_found = False  # Flag to check if CH340 port is found

        if available_ports:
            # Add each port to the dropdown with its description
            for port in available_ports:
                port_text = f"{port.device} - {port.description}"
                self.dropdown_comports.addItem(port_text)

                # Automatically select the port with 'CH340' in the description
                if 'CH340' in port.description:
                    ch340_found = True
                    index = self.dropdown_comports.findText(port_text)
                    self.dropdown_comports.setCurrentIndex(index)

            # If no CH340 is found, set the first port as the default selection
            if not ch340_found:
                self.dropdown_comports.setCurrentIndex(0)
        else:
            # If no ports are available, send a message to the debug output
            self.plainTextEdit_debugoutput.appendPlainText("No COM ports available")

    def perform_configuration(self):
        if self.ser:
            output = perform_configuration(self.ser)
            self.plainTextEdit_debugoutput.appendPlainText(output)

# Entry point of the application
def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MyMainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
