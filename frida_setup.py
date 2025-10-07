"""
Frida setup and connection module for Android VirtualBox
"""

import frida
import sys
import time
from colorama import Fore, Style, init
import config

init(autoreset=True)


class FridaSetup:
    def __init__(self):
        self.device = None
        self.session = None
        self.script = None
        
    def connect_device(self):
        """Connect to Android device via Frida"""
        try:
            print(f"{Fore.CYAN}[*] Connecting to Android device...")
            
            # Get device - USB or remote
            if config.DEVICE_ID:
                self.device = frida.get_device(config.DEVICE_ID)
            else:
                # Try USB first
                try:
                    self.device = frida.get_usb_device(timeout=5)
                    print(f"{Fore.GREEN}[+] Connected via USB")
                except:
                    # Try remote device
                    self.device = frida.get_remote_device()
                    print(f"{Fore.GREEN}[+] Connected via remote")
            
            print(f"{Fore.GREEN}[+] Device: {self.device.name}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to connect to device: {e}")
            return False
    
    def check_frida_server(self):
        """Check if Frida server is running on device"""
        try:
            print(f"{Fore.CYAN}[*] Checking Frida server...")
            processes = self.device.enumerate_processes()
            print(f"{Fore.GREEN}[+] Frida server is running")
            print(f"{Fore.GREEN}[+] Found {len(processes)} processes")
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Frida server check failed: {e}")
            print(f"{Fore.YELLOW}[!] Make sure frida-server is running on the device")
            return False
    
    def attach_to_app(self):
        """Attach to Rise of Kingdoms application"""
        try:
            print(f"{Fore.CYAN}[*] Attaching to {config.PACKAGE_NAME}...")
            
            # Check if app is running
            try:
                self.session = self.device.attach(config.PACKAGE_NAME)
                print(f"{Fore.GREEN}[+] Attached to running application")
                return True
            except frida.ProcessNotFoundError:
                print(f"{Fore.YELLOW}[!] Application not running, attempting to spawn...")
                
                # Spawn the application
                pid = self.device.spawn([config.PACKAGE_NAME])
                self.session = self.device.attach(pid)
                self.device.resume(pid)
                print(f"{Fore.GREEN}[+] Application spawned and attached (PID: {pid})")
                return True
                
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to attach to application: {e}")
            return False
    
    def load_script(self, script_code):
        """Load and execute Frida script"""
        try:
            print(f"{Fore.CYAN}[*] Loading Frida script...")
            self.script = self.session.create_script(script_code)
            self.script.on('message', self.on_message)
            self.script.load()
            print(f"{Fore.GREEN}[+] Script loaded successfully")
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to load script: {e}")
            return False
    
    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message.get('payload', '')
            print(f"{Fore.YELLOW}[Frida] {payload}")
        elif message['type'] == 'error':
            print(f"{Fore.RED}[Error] {message['stack']}")
    
    def detach(self):
        """Detach from application and cleanup"""
        try:
            if self.script:
                self.script.unload()
            if self.session:
                self.session.detach()
            print(f"{Fore.GREEN}[+] Detached successfully")
        except Exception as e:
            print(f"{Fore.RED}[-] Error during detach: {e}")


def test_connection():
    """Test Frida connection to device"""
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Frida Setup Test for Rise of Kingdoms Bot")
    print(f"{Fore.CYAN}Frida Version: {config.FRIDA_VERSION}")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    setup = FridaSetup()
    
    # Connect to device
    if not setup.connect_device():
        return False
    
    # Check Frida server
    if not setup.check_frida_server():
        return False
    
    print(f"\n{Fore.GREEN}[+] All checks passed!")
    print(f"{Fore.YELLOW}[!] Make sure Rise of Kingdoms is installed before running the bot")
    
    return True


if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)
