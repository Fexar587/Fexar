"""
Module for extracting libil2cpp.so from Rise of Kingdoms
"""

import frida
import os
import sys
from colorama import Fore, Style, init
import config
from frida_setup import FridaSetup

init(autoreset=True)


class IL2CPPExtractor:
    def __init__(self):
        self.frida_setup = FridaSetup()
        
    def find_libil2cpp_path(self):
        """Find the actual path to libil2cpp.so on device"""
        script_code = """
        // Find libil2cpp.so module
        var modules = Process.enumerateModules();
        var il2cpp_module = null;
        
        modules.forEach(function(module) {
            if (module.name.indexOf("libil2cpp.so") !== -1) {
                il2cpp_module = module;
            }
        });
        
        if (il2cpp_module) {
            send({
                type: "module_found",
                name: il2cpp_module.name,
                base: il2cpp_module.base.toString(),
                size: il2cpp_module.size,
                path: il2cpp_module.path
            });
        } else {
            send({
                type: "module_not_found",
                message: "libil2cpp.so not found in process memory"
            });
        }
        """
        
        result = {'found': False, 'path': None, 'base': None, 'size': None}
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('type') == 'module_found':
                    result['found'] = True
                    result['path'] = payload['path']
                    result['base'] = payload['base']
                    result['size'] = payload['size']
                    print(f"{Fore.GREEN}[+] Found libil2cpp.so:")
                    print(f"{Fore.GREEN}    Path: {payload['path']}")
                    print(f"{Fore.GREEN}    Base: {payload['base']}")
                    print(f"{Fore.GREEN}    Size: {payload['size']} bytes")
                elif payload.get('type') == 'module_not_found':
                    print(f"{Fore.RED}[-] {payload['message']}")
        
        self.frida_setup.script.on('message', on_message)
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        import time
        time.sleep(2)  # Wait for script to execute
        
        return result
    
    def dump_libil2cpp(self):
        """Dump libil2cpp.so from memory to file"""
        print(f"{Fore.CYAN}[*] Starting libil2cpp.so extraction...")
        
        # Connect to device and app
        if not self.frida_setup.connect_device():
            return False
        
        if not self.frida_setup.check_frida_server():
            return False
        
        if not self.frida_setup.attach_to_app():
            return False
        
        # Find libil2cpp.so
        module_info = self.find_libil2cpp_path()
        
        if not module_info['found']:
            print(f"{Fore.RED}[-] Failed to find libil2cpp.so")
            return False
        
        # Create output directory
        os.makedirs(config.OUTPUT_DIR, exist_ok=True)
        
        # Dump the library from memory
        script_code = f"""
        var il2cpp_base = ptr("{module_info['base']}");
        var il2cpp_size = {module_info['size']};
        
        send({{type: "dumping", message: "Starting memory dump..."}});
        
        try {{
            var buffer = Memory.readByteArray(il2cpp_base, il2cpp_size);
            send({{type: "dump_complete", size: il2cpp_size}}, buffer);
        }} catch(e) {{
            send({{type: "error", message: e.toString()}});
        }}
        """
        
        dump_data = None
        
        def on_dump_message(message, data):
            nonlocal dump_data
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('type') == 'dumping':
                    print(f"{Fore.YELLOW}[*] {payload['message']}")
                elif payload.get('type') == 'dump_complete':
                    print(f"{Fore.GREEN}[+] Memory dump complete: {payload['size']} bytes")
                    dump_data = data
                elif payload.get('type') == 'error':
                    print(f"{Fore.RED}[-] Error: {payload['message']}")
        
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_dump_message)
        script.load()
        
        import time
        time.sleep(3)  # Wait for dump to complete
        
        if dump_data:
            # Write to file
            with open(config.LIBIL2CPP_OUTPUT, 'wb') as f:
                f.write(dump_data)
            print(f"{Fore.GREEN}[+] libil2cpp.so saved to: {config.LIBIL2CPP_OUTPUT}")
            print(f"{Fore.GREEN}[+] File size: {len(dump_data)} bytes")
            return True
        else:
            print(f"{Fore.RED}[-] Failed to dump libil2cpp.so")
            return False
    
    def extract(self):
        """Main extraction method"""
        try:
            success = self.dump_libil2cpp()
            return success
        except Exception as e:
            print(f"{Fore.RED}[-] Extraction failed: {e}")
            return False
        finally:
            self.frida_setup.detach()


def main():
    """Main entry point for IL2CPP extraction"""
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Rise of Kingdoms - libil2cpp.so Extractor")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    extractor = IL2CPPExtractor()
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
