#!/usr/bin/env python3

import os
import sys
import time
import uuid
from flask import Flask, request, jsonify
from zeroconf import ServiceInfo, Zeroconf
import socket
from brother_ql.raster import BrotherQLRaster
from brother_ql.conversion import convert
from brother_ql.backends.helpers import send
from PIL import Image
import io
import logging
import usb.core
import usb.util

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Printer configuration
PRINTER_MODEL = 'QL-600'
PRINTER_IDENTIFIER = 'usb://0x04f9:0x20c0'  # Update this with your printer's identifier
LABEL_SIZE = '62'  # 62mm label

def check_usb_permissions():
    """Check if we have permission to access the USB printer"""
    try:
        # Try to find the printer
        printer = usb.core.find(idVendor=0x04f9, idProduct=0x20c0)
        if printer is None:
            logger.error("Printer not found. Please check if it's connected.")
            return False
        
        # Try to access the printer
        try:
            # First try to detach any kernel driver that might be using the device
            for cfg in printer:
                for intf in range(cfg.bNumInterfaces):
                    if printer.is_kernel_driver_active(intf):
                        try:
                            logger.info(f"Detaching kernel driver from interface {intf}")
                            printer.detach_kernel_driver(intf)
                        except usb.core.USBError as e:
                            logger.warning(f"Could not detach kernel driver: {e}")
            
            # Now try to set the configuration
            printer.set_configuration()
            return True
        except usb.core.USBError as e:
            if e.errno == 13:  # Permission denied
                logger.error("Permission denied accessing USB printer. Try running with sudo or add udev rules.")
                return False
            elif e.errno == 16:  # Resource busy
                logger.error("USB device is busy. Another process might be using it.")
                logger.error("Try stopping CUPS: sudo systemctl stop cups")
                logger.error("Or try unplugging and replugging the printer.")
                return False
            else:
                logger.error(f"USB error: {str(e)}")
                return False
    except Exception as e:
        logger.error(f"Error checking USB permissions: {str(e)}")
        return False

def get_ip_address():
    """Get the primary IP address of the machine"""
    try:
        # Get all network interfaces
        import netifaces
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            if interface.startswith(('en', 'eth', 'wlan')):  # Common network interface names
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith('127.'):  # Skip localhost
                            return ip
    except ImportError:
        # Fallback method
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))  # Doesn't actually send any packets
            ip = s.getsockname()[0]
        except:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip
    return '127.0.0.1'

class AirPrintService:
    def __init__(self):
        self.zeroconf = Zeroconf()
        self.service_info = None
        self.setup_service()

    def setup_service(self):
        # Force using the network IP address
        local_ip = '192.168.178.27'  # Explicitly set the IP
        logger.info(f"Using IP address: {local_ip}")
        
        # Generate a unique UUID for the printer
        printer_uuid = str(uuid.uuid4())
        
        # Create AirPrint service info with specific interface binding
        self.service_info = ServiceInfo(
            "_ipp._tcp.local.",
            "Brother QL-600._ipp._tcp.local.",
            addresses=[socket.inet_aton(local_ip)],
            port=631,
            properties={
                'rp': '/ipp/print',
                'ty': 'Brother QL-600',
                'product': '(Brother QL-600)',
                'pdl': 'application/pdf,image/jpeg,image/png,application/octet-stream',
                'URF': 'none',
                'UUID': printer_uuid,
                'note': 'Brother QL-600 Label Printer',
                'priority': '50',
                'qtotal': '1',
                'kind': 'label,photo',
                'Transparent': 'T',
                'Color': 'F',
                'Duplex': 'F',
                'usb_MDL': 'QL-600',
                'usb_MFG': 'Brother',
                'air': 'true',
                'mopria-certified': '1.3',
                'TLS': '1.2',
                'txtvers': '1',
                'adminurl': f'http://{local_ip}:631/admin',
                'cs': 'online',
                'type': 'printer',
                'id': '',
                'url': f'http://{local_ip}:631/ipp/print'
            }
        )

    def start(self):
        logger.info("Starting AirPrint service...")
        try:
            # Stop avahi-daemon to avoid port conflicts
            os.system('sudo systemctl stop avahi-daemon.service')
            time.sleep(1)  # Give it time to fully stop
            
            # Configure zeroconf to only use the wireless interface
            self.zeroconf = Zeroconf(interfaces=['192.168.178.27'])
            
            # Start our service
            self.zeroconf.register_service(self.service_info)
            logger.info("AirPrint service started")
        except Exception as e:
            logger.error(f"Error starting AirPrint service: {str(e)}")
            # Restart avahi-daemon in case of error
            os.system('sudo systemctl start avahi-daemon.service')
            raise

    def stop(self):
        logger.info("Stopping AirPrint service...")
        try:
            self.zeroconf.unregister_service(self.service_info)
            self.zeroconf.close()
            # Restart avahi-daemon
            os.system('sudo systemctl start avahi-daemon.service')
            logger.info("AirPrint service stopped")
        except Exception as e:
            logger.error(f"Error stopping AirPrint service: {str(e)}")
            raise

# Initialize AirPrint service
airprint_service = AirPrintService()

@app.route('/ipp/print', methods=['POST'])
def print_job():
    try:
        # Check USB permissions before attempting to print
        if not check_usb_permissions():
            return jsonify({'error': 'Cannot access printer. Check permissions.'}), 403
        
        # Get the print job data
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        logger.info(f"Received file: {file.filename}")
        
        # Read the image
        try:
            image_data = file.read()
            logger.info(f"Read {len(image_data)} bytes from file")
            image = Image.open(io.BytesIO(image_data))
            logger.info(f"Opened image: {image.format}, {image.size}, {image.mode}")
        except Exception as e:
            logger.error(f"Error reading image: {str(e)}")
            return jsonify({'error': f'Error reading image: {str(e)}'}), 400
        
        # Create printer instance
        try:
            qlr = BrotherQLRaster(PRINTER_MODEL)
            qlr.exception_on_warning = True
            logger.info(f"Created BrotherQLRaster instance for model {PRINTER_MODEL}")
        except Exception as e:
            logger.error(f"Error creating printer instance: {str(e)}")
            return jsonify({'error': f'Error creating printer instance: {str(e)}'}), 500
        
        # Convert image to printer instructions
        try:
            instructions = convert(
                qlr=qlr,
                images=[image],
                label=LABEL_SIZE,
                rotate='auto',
                threshold=70.0,
                dither=False,
                compress=True,
                cut=True
            )
            logger.info(f"Converted image to printer instructions: {len(instructions)} bytes")
        except Exception as e:
            logger.error(f"Error converting image: {str(e)}")
            return jsonify({'error': f'Error converting image: {str(e)}'}), 500
        
        # Send to printer
        try:
            send(
                instructions=instructions,
                printer_identifier=PRINTER_IDENTIFIER,
                backend_identifier='pyusb',
                blocking=True
            )
            logger.info("Successfully sent instructions to printer")
        except Exception as e:
            logger.error(f"Error sending to printer: {str(e)}")
            return jsonify({'error': f'Error sending to printer: {str(e)}'}), 500
        
        return jsonify({'status': 'success', 'message': 'Print job completed'})
    
    except Exception as e:
        logger.error(f"Error processing print job: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    try:
        # Check USB permissions before starting
        if not check_usb_permissions():
            logger.error("Cannot start server without USB printer access.")
            logger.error("Try running with sudo or add udev rules:")
            logger.error("1. Create file: /etc/udev/rules.d/99-brother-ql.rules")
            logger.error("2. Add line: SUBSYSTEM==\"usb\", ATTRS{idVendor}==\"04f9\", ATTRS{idProduct}==\"20c0\", MODE=\"0666\", GROUP=\"plugdev\"")
            logger.error("3. Run: sudo udevadm control --reload-rules && sudo udevadm trigger")
            sys.exit(1)
        
        # Start AirPrint service
        airprint_service = AirPrintService()
        airprint_service.start()
        
        # Start Flask server on wireless interface only
        app.run(host='192.168.178.27', port=631)
    except KeyboardInterrupt:
        print("\nShutting down...")
        airprint_service.stop() 