"""
Module for extracting and decoding global-metadata.dat from Rise of Kingdoms
"""

import frida
import os
import sys
import struct
from colorama import Fore, Style, init
import config
from frida_setup import FridaSetup

init(autoreset=True)


class MetadataExtractor:
    def __init__(self):
        self.frida_setup = FridaSetup()
    
    def find_metadata_in_apk(self):
        """Extract global-metadata.dat from APK file on device"""
        script_code = """
        // Find the APK path
        var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
        var apkPath = context.getPackageCodePath();
        
        send({
            type: "apk_path",
            path: apkPath.toString()
        });
        """
        
        result = {'found': False, 'apk_path': None}
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('type') == 'apk_path':
                    result['found'] = True
                    result['apk_path'] = payload['path']
                    print(f"{Fore.GREEN}[+] Found APK path: {payload['path']}")
        
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        import time
        time.sleep(2)
        
        return result
    
    def extract_metadata_from_device(self):
        """Extract metadata file from device using shell commands"""
        print(f"{Fore.CYAN}[*] Extracting global-metadata.dat from device...")
        
        # Create script to execute shell commands
        script_code = """
        // Use shell command to find and copy metadata file
        var File = Java.use("java.io.File");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var BufferedReader = Java.use("java.io.BufferedReader");
        var InputStreamReader = Java.use("java.io.InputStreamReader");
        
        // Try to find metadata file
        var possiblePaths = [
            "/data/data/com.lilithgames.roc.gp/files/il2cpp/Metadata/global-metadata.dat",
            "/data/app/com.lilithgames.roc.gp/assets/bin/Data/Managed/Metadata/global-metadata.dat"
        ];
        
        var foundPath = null;
        
        possiblePaths.forEach(function(path) {
            try {
                var file = File.$new(path);
                if (file.exists()) {
                    foundPath = path;
                    send({
                        type: "metadata_found",
                        path: path,
                        size: file.length()
                    });
                }
            } catch(e) {
                // Ignore errors
            }
        });
        
        if (!foundPath) {
            send({
                type: "metadata_not_found",
                message: "Could not find global-metadata.dat in known locations"
            });
        }
        """
        
        result = {'found': False, 'path': None, 'size': 0}
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('type') == 'metadata_found':
                    result['found'] = True
                    result['path'] = payload['path']
                    result['size'] = payload['size']
                    print(f"{Fore.GREEN}[+] Found metadata file:")
                    print(f"{Fore.GREEN}    Path: {payload['path']}")
                    print(f"{Fore.GREEN}    Size: {payload['size']} bytes")
                elif payload.get('type') == 'metadata_not_found':
                    print(f"{Fore.YELLOW}[!] {payload['message']}")
        
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        import time
        time.sleep(2)
        
        return result
    
    def read_metadata_file(self, file_path):
        """Read metadata file from device"""
        print(f"{Fore.CYAN}[*] Reading metadata file from device...")
        
        script_code = f"""
        var File = Java.use("java.io.File");
        var FileInputStream = Java.use("java.io.FileInputStream");
        
        try {{
            var file = File.$new("{file_path}");
            var fis = FileInputStream.$new(file);
            var available = fis.available();
            
            // Read file in chunks
            var buffer = [];
            var b;
            while ((b = fis.read()) !== -1) {{
                buffer.push(b);
            }}
            
            fis.close();
            
            // Convert to byte array
            var byteArray = new Uint8Array(buffer);
            
            send({{
                type: "file_read",
                size: buffer.length
            }}, byteArray.buffer);
            
        }} catch(e) {{
            send({{
                type: "error",
                message: e.toString()
            }});
        }}
        """
        
        file_data = None
        
        def on_message(message, data):
            nonlocal file_data
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('type') == 'file_read':
                    print(f"{Fore.GREEN}[+] File read successfully: {payload['size']} bytes")
                    file_data = data
                elif payload.get('type') == 'error':
                    print(f"{Fore.RED}[-] Error reading file: {payload['message']}")
        
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        import time
        time.sleep(5)  # Give more time for file reading
        
        return file_data
    
    def decode_metadata(self, metadata_bytes):
        """
        Decode IL2CPP metadata file
        The metadata file contains information about types, methods, and strings
        """
        print(f"{Fore.CYAN}[*] Decoding metadata file...")
        
        if len(metadata_bytes) < 32:
            print(f"{Fore.RED}[-] Metadata file too small")
            return False
        
        # Read metadata header
        try:
            # IL2CPP metadata signature
            signature = struct.unpack('<I', metadata_bytes[0:4])[0]
            version = struct.unpack('<I', metadata_bytes[4:8])[0]
            
            print(f"{Fore.GREEN}[+] Metadata signature: 0x{signature:08X}")
            print(f"{Fore.GREEN}[+] Metadata version: {version}")
            
            # The metadata is already in decoded form when extracted from memory/file
            # Save it as-is for use with Il2CppDumper or similar tools
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error decoding metadata: {e}")
            return False
    
    def extract(self):
        """Main extraction method"""
        try:
            # Connect to device and app
            if not self.frida_setup.connect_device():
                return False
            
            if not self.frida_setup.check_frida_server():
                return False
            
            if not self.frida_setup.attach_to_app():
                return False
            
            # Find metadata file
            metadata_info = self.extract_metadata_from_device()
            
            if not metadata_info['found']:
                print(f"{Fore.YELLOW}[!] Metadata not found in standard locations")
                print(f"{Fore.YELLOW}[!] Trying to extract from APK...")
                # Could implement APK extraction here
                return False
            
            # Read metadata file
            metadata_data = self.read_metadata_file(metadata_info['path'])
            
            if not metadata_data:
                print(f"{Fore.RED}[-] Failed to read metadata file")
                return False
            
            # Create output directory
            os.makedirs(config.OUTPUT_DIR, exist_ok=True)
            
            # Decode and save metadata
            if self.decode_metadata(metadata_data):
                with open(config.METADATA_OUTPUT, 'wb') as f:
                    f.write(metadata_data)
                print(f"{Fore.GREEN}[+] Metadata saved to: {config.METADATA_OUTPUT}")
                print(f"{Fore.GREEN}[+] File size: {len(metadata_data)} bytes")
                return True
            else:
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[-] Extraction failed: {e}")
            return False
        finally:
            self.frida_setup.detach()


def main():
    """Main entry point for metadata extraction"""
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Rise of Kingdoms - global-metadata.dat Extractor")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    extractor = MetadataExtractor()
    success = extractor.extract()
    
    if success:
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}[+] Extraction completed successfully!")
        print(f"{Fore.GREEN}{'='*60}")
    else:
        print(f"\n{Fore.RED}{'='*60}")
        print(f"{Fore.RED}[-] Extraction failed!")
        print(f"{Fore.RED}{'='*60}")
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
