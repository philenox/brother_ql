# AirPrint Server for Brother QL-600

This is a simple AirPrint server implementation for the Brother QL-600 label printer. It uses Flask for the web server and zeroconf for service discovery.

## Setup

1. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Update the printer configuration in `app.py`:
- Set `PRINTER_IDENTIFIER` to match your printer's USB identifier
- Adjust `LABEL_SIZE` if using a different label size

4. Set up USB permissions (choose one method):

   Method 1 - Run with sudo (quick but less secure):
   ```bash
   sudo python app.py
   ```

   Method 2 - Add udev rules (recommended, more secure):
   ```bash
   # Create udev rules file
   sudo nano /etc/udev/rules.d/99-brother-ql.rules
   
   # Add this line:
   SUBSYSTEM=="usb", ATTRS{idVendor}=="04f9", ATTRS{idProduct}=="20c0", MODE="0666", GROUP="plugdev"
   
   # Reload udev rules
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   
   # Add your user to the plugdev group
   sudo usermod -a -G plugdev $USER
   ```
   After adding udev rules, log out and back in for the group changes to take effect.

## Running the Server

1. Start the server:
```bash
# If using Method 1 (sudo):
sudo python app.py

# If using Method 2 (udev rules):
python app.py
```

The server will:
- Start on port 631 (standard IPP port)
- Advertise the printer on the local network using zeroconf
- Accept print jobs via HTTP POST requests

## Testing

1. Health check:
```bash
curl http://localhost:631/health
```

2. Print a test image:
```bash
curl -X POST -F "file=@test_print.png" http://localhost:631/ipp/print
```

## iOS Integration

The printer should automatically appear in the iOS print dialog when:
1. Your iOS device is on the same network as the Raspberry Pi
2. The AirPrint server is running
3. The printer is connected and powered on

## Troubleshooting

1. Check the logs for any error messages
2. Verify the printer identifier is correct
3. Ensure the Raspberry Pi and iOS device are on the same network
4. Check if port 631 is available and not blocked by firewall
5. If you get permission errors:
   - Make sure you're using either sudo or the udev rules method
   - Check if the printer is properly connected
   - Verify your user is in the plugdev group (if using udev rules)
   - Try unplugging and replugging the printer 