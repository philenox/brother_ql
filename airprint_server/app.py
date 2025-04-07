#!/usr/bin/env python3

import os
import sys
import time
import uuid
from flask import Flask, request, jsonify, Response
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
import tempfile
from io import BytesIO

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

@app.route('/ipp', methods=['GET', 'POST'])
def ipp_root():
    """Handle root IPP requests"""
    return ipp_print()

@app.route('/ipp/print', methods=['POST', 'GET'])
def ipp_print():
    """Handle IPP print requests"""
    try:
        logger.info("=== START IPP REQUEST HANDLING ===")
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request headers: {dict(request.headers)}")
        
        # Get the raw request data
        raw_data = request.get_data()
        logger.info(f"Raw request data length: {len(raw_data)} bytes")
        logger.info(f"Raw request data hex: {raw_data.hex()}")
        
        # Check if this is an IPP request
        content_type = request.headers.get('Content-Type')
        logger.info(f"Content-Type: {content_type}")
        
        if content_type == 'application/ipp':
            logger.info("Processing as IPP request")
            
            # Parse IPP request
            if len(raw_data) >= 8:
                version_major = raw_data[0]
                version_minor = raw_data[1]
                operation = int.from_bytes(raw_data[2:4], byteorder='big')
                request_id = int.from_bytes(raw_data[4:8], byteorder='big')
                
                logger.info(f"IPP Version: {version_major}.{version_minor}")
                logger.info(f"IPP Operation ID: 0x{operation:04x}")
                logger.info(f"IPP Request ID: {request_id}")
                
                # Log the rest of the request data
                attributes_data = raw_data[8:]
                logger.info(f"Attributes data hex: {attributes_data.hex()}")
                
                # Handle Get-Printer-Attributes operation (0x000B)
                if operation == 0x000B:
                    logger.info("Handling Get-Printer-Attributes operation")
                    try:
                        # Create IPP response
                        response = BytesIO()
                        
                        # Write response header
                        logger.info("Writing IPP response header")
                        response.write(bytes([version_major, version_minor]))  # Version
                        response.write((0).to_bytes(2, 'big'))  # Status code: successful-ok
                        response.write(request_id.to_bytes(4, 'big'))  # Request ID
                        
                        # Operation attributes
                        response.write(b'\x01')  # operation-attributes-tag
                        
                        # Required operation attributes
                        def write_attribute(tag, name, value, group_tag=None):
                            try:
                                if group_tag:
                                    logger.info(f"Writing group tag: 0x{group_tag:02x}")
                                    response.write(bytes([group_tag]))
                                
                                logger.info(f"Writing attribute: {name} = {value} (tag: 0x{tag:02x})")
                                response.write(bytes([tag]))  # Value tag
                                
                                # Name
                                name_bytes = name.encode('utf-8')
                                response.write(len(name_bytes).to_bytes(2, 'big'))
                                response.write(name_bytes)
                                
                                # Value
                                if isinstance(value, str):
                                    value_bytes = value.encode('utf-8')
                                    response.write(len(value_bytes).to_bytes(2, 'big'))
                                    response.write(value_bytes)
                                elif isinstance(value, int):
                                    if tag == 0x22:  # boolean tag
                                        response.write((1).to_bytes(2, 'big'))  # Length 1 for boolean
                                        response.write(bytes([1 if value else 0]))
                                        logger.info(f"Wrote boolean value: {1 if value else 0}")
                                    else:
                                        response.write((4).to_bytes(2, 'big'))  # Length 4 for integers
                                        response.write(value.to_bytes(4, 'big'))
                                elif isinstance(value, bool):
                                    response.write((1).to_bytes(2, 'big'))  # Length 1 for boolean
                                    response.write(bytes([1 if value else 0]))
                                    logger.info(f"Wrote boolean value: {1 if value else 0}")
                                    
                                logger.info(f"Successfully wrote attribute {name}")
                            except Exception as e:
                                logger.error(f"Error writing attribute {name}: {str(e)}")
                                raise
                        
                        # Operation attributes
                        write_attribute(0x47, 'attributes-charset', 'utf-8')
                        write_attribute(0x48, 'attributes-natural-language', 'en')
                        
                        # Printer attributes
                        write_attribute(0x47, 'printer-uri-supported', f'ipp://192.168.178.27:631/ipp/print', 0x02)  # printer-attributes-tag
                        write_attribute(0x42, 'printer-name', 'Brother QL-600')  # nameWithoutLanguage
                        write_attribute(0x23, 'printer-state', 3)  # enum (idle)
                        write_attribute(0x47, 'printer-state-reasons', 'none')
                        write_attribute(0x42, 'printer-make-and-model', 'Brother QL-600')  # nameWithoutLanguage
                        write_attribute(0x42, 'printer-location', '')  # nameWithoutLanguage
                        write_attribute(0x42, 'printer-info', 'Brother QL-600 Label Printer')  # nameWithoutLanguage
                        write_attribute(0x42, 'printer-type', 'label')  # nameWithoutLanguage
                        write_attribute(0x22, 'printer-is-accepting-jobs', 1)  # boolean (1 = true)
                        write_attribute(0x47, 'pdl-data-stream-format-supported', 'application/octet-stream')
                        write_attribute(0x47, 'printer-resolution-supported', '300dpi')
                        write_attribute(0x47, 'printer-media-supported', '62mm')
                        write_attribute(0x22, 'printer-color-supported', 0)  # boolean (0 = false)
                        write_attribute(0x47, 'printer-sides-supported', 'one-sided')
                        
                        # Add missing required attributes
                        write_attribute(0x47, 'charset-configured', 'utf-8')
                        write_attribute(0x47, 'charset-supported', 'utf-8')
                        write_attribute(0x47, 'compression-supported', 'none')
                        write_attribute(0x47, 'document-format-default', 'application/pdf')
                        write_attribute(0x47, 'document-format-supported', 'application/pdf,image/jpeg,image/png')
                        write_attribute(0x48, 'generated-natural-language-supported', 'en')
                        write_attribute(0x47, 'ipp-versions-supported', '1.1')
                        write_attribute(0x48, 'natural-language-configured', 'en')
                        write_attribute(0x23, 'operations-supported', 0x000B)  # Get-Printer-Attributes
                        write_attribute(0x22, 'pdl-override-supported', 0)  # boolean (0 = false)
                        write_attribute(0x21, 'printer-up-time', int(time.time()))  # integer
                        write_attribute(0x21, 'queued-job-count', 0)  # integer
                        write_attribute(0x47, 'uri-authentication-supported', 'none')
                        write_attribute(0x47, 'uri-security-supported', 'none')
                        
                        # End of attributes
                        response.write(b'\x03')  # end-of-attributes-tag
                        
                        # Get the complete response
                        response_data = response.getvalue()
                        logger.info(f"Complete response length: {len(response_data)} bytes")
                        logger.info(f"Complete response hex: {response_data.hex()}")
                        
                        # Send response
                        return Response(
                            response_data,
                            status=200,
                            headers={
                                'Content-Type': 'application/ipp',
                                'Content-Length': str(len(response_data))
                            }
                        )
                    except Exception as e:
                        logger.error(f"Error creating IPP response: {str(e)}")
                        raise
            else:
                logger.error("IPP request too short")
                return Response(status=400)
        
        logger.info("=== END IPP REQUEST HANDLING ===")
        
        # Handle regular print job submission
        if request.method == 'POST' and 'file' in request.files:
            logger.info("Processing as regular print job")
            file = request.files['file']
            if file.filename == '':
                logger.error("No file selected")
                return jsonify({'error': 'No file selected'}), 400
            
            # Save the file temporarily
            temp_path = os.path.join(tempfile.gettempdir(), file.filename)
            file.save(temp_path)
            logger.info(f"Saved file to {temp_path}")
            
            try:
                # Create printer instance
                printer = BrotherQLRaster('QL-600')
                
                # Convert image to printer format
                image = Image.open(temp_path)
                # Auto-rotate image if needed
                if image.width > image.height:
                    image = image.rotate(90, expand=True)
                # Convert to RGB if needed
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                # Convert to printer format
                data = printer.convert(
                    qlr=image,
                    label='62',
                    rotate='auto',
                    threshold=70.0,
                    dither=False,
                    compress=False
                )
                
                # Send to printer
                printer.write(data)
                logger.info("Print job completed successfully")
                
                # Create IPP response
                response = BytesIO()
                response.write(b'\x01\x01')  # Version 1.1
                response.write(b'\x00\x0B')  # Get-Printer-Attributes operation
                response.write(b'\x00\x00\x00\x01')  # Request ID
                response.write(b'\x00\x00')  # Status code: successful-ok
                response.write(b'\x03')  # End-of-attributes-tag
                
                return Response(
                    response.getvalue(),
                    status=200,
                    headers={'Content-Type': 'application/ipp'}
                )
                
            except Exception as e:
                logger.error(f"Error processing print job: {str(e)}")
                return jsonify({'error': str(e)}), 500
            finally:
                # Clean up temporary file
                try:
                    os.remove(temp_path)
                except:
                    pass
        
        return jsonify({'error': 'Invalid request method'}), 405
        
    except Exception as e:
        logger.error(f"Error in IPP request: {str(e)}")
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