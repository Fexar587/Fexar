"""
Memory reader bot for Rise of Kingdoms
Reads RAM memory using Frida to extract game data
"""

import frida
import sys
import time
import json
from colorama import Fore, Style, init
import config
from frida_setup import FridaSetup

init(autoreset=True)


class MemoryReader:
    def __init__(self):
        self.frida_setup = FridaSetup()
        self.running = False
    
    def get_module_info(self):
        """Get information about loaded modules"""
        script_code = """
        var modules = Process.enumerateModules();
        var result = [];
        
        modules.forEach(function(module) {
            result.push({
                name: module.name,
                base: module.base.toString(),
                size: module.size,
                path: module.path
            });
        });
        
        send({type: "modules", data: result});
        """
        
        modules_data = []
        
        def on_message(message, data):
            nonlocal modules_data
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('type') == 'modules':
                    modules_data = payload['data']
        
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        time.sleep(2)
        
        return modules_data
    
    def find_il2cpp_functions(self):
        """Find common IL2CPP functions for memory manipulation"""
        script_code = """
        // Find IL2CPP module
        var il2cpp = null;
        Process.enumerateModules().forEach(function(module) {
            if (module.name.indexOf("libil2cpp.so") !== -1) {
                il2cpp = module;
            }
        });
        
        if (!il2cpp) {
            send({type: "error", message: "IL2CPP module not found"});
            return;
        }
        
        // Export common IL2CPP functions
        var functions = {};
        
        var exports = il2cpp.enumerateExports();
        exports.forEach(function(exp) {
            // Look for useful IL2CPP API functions
            if (exp.name.indexOf("il2cpp_") === 0 || 
                exp.name.indexOf("Il2Cpp") !== -1) {
                functions[exp.name] = exp.address.toString();
            }
        });
        
        send({
            type: "il2cpp_functions",
            module_base: il2cpp.base.toString(),
            module_size: il2cpp.size,
            functions: functions
        });
        """
        
        result = {}
        
        def on_message(message, data):
            nonlocal result
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('type') == 'il2cpp_functions':
                    result = payload
                    print(f"{Fore.GREEN}[+] Found IL2CPP module:")
                    print(f"{Fore.GREEN}    Base: {payload['module_base']}")
                    print(f"{Fore.GREEN}    Size: {payload['module_size']}")
                    print(f"{Fore.GREEN}    Functions found: {len(payload['functions'])}")
                elif payload.get('type') == 'error':
                    print(f"{Fore.RED}[-] {payload['message']}")
        
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        time.sleep(2)
        
        return result
    
    def scan_memory_region(self, base_address, size, pattern=None):
        """Scan a memory region for specific patterns"""
        script_code = f"""
        var base = ptr("{base_address}");
        var size = {size};
        
        try {{
            // Read memory region
            var buffer = Memory.readByteArray(base, Math.min(size, 1024 * 1024)); // Max 1MB at a time
            
            send({{
                type: "memory_read",
                base: base.toString(),
                size: buffer.byteLength
            }}, buffer);
            
        }} catch(e) {{
            send({{
                type: "error",
                message: "Failed to read memory: " + e.toString()
            }});
        }}
        """
        
        memory_data = None
        
        def on_message(message, data):
            nonlocal memory_data
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('type') == 'memory_read':
                    memory_data = data
                    print(f"{Fore.GREEN}[+] Read {payload['size']} bytes from {payload['base']}")
                elif payload.get('type') == 'error':
                    print(f"{Fore.RED}[-] {payload['message']}")
        
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        time.sleep(1)
        
        return memory_data
    
    def hook_memory_functions(self):
        """Hook common memory allocation and access functions"""
        script_code = """
        // Hook malloc to track memory allocations
        var mallocPtr = Module.findExportByName(null, 'malloc');
        var freePtr = Module.findExportByName(null, 'free');
        
        if (mallocPtr) {
            Interceptor.attach(mallocPtr, {
                onEnter: function(args) {
                    this.size = args[0].toInt32();
                },
                onLeave: function(retval) {
                    if (this.size > 1024) { // Only log large allocations
                        send({
                            type: "malloc",
                            address: retval.toString(),
                            size: this.size
                        });
                    }
                }
            });
        }
        
        // Hook IL2CPP domain functions if available
        var il2cppDomain = Module.findExportByName("libil2cpp.so", "il2cpp_domain_get");
        if (il2cppDomain) {
            Interceptor.attach(il2cppDomain, {
                onLeave: function(retval) {
                    send({
                        type: "il2cpp_domain",
                        domain: retval.toString()
                    });
                }
            });
        }
        
        send({type: "hooks_installed", message: "Memory hooks installed successfully"});
        """
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                msg_type = payload.get('type', '')
                
                if msg_type == 'hooks_installed':
                    print(f"{Fore.GREEN}[+] {payload['message']}")
                elif msg_type == 'malloc':
                    print(f"{Fore.YELLOW}[Malloc] Address: {payload['address']}, Size: {payload['size']}")
                elif msg_type == 'il2cpp_domain':
                    print(f"{Fore.YELLOW}[IL2CPP] Domain: {payload['domain']}")
        
        script = self.frida_setup.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        return script
    
    def start_monitoring(self):
        """Start continuous memory monitoring"""
        print(f"{Fore.CYAN}[*] Starting memory monitoring...")
        
        # Connect to device and app
        if not self.frida_setup.connect_device():
            return False
        
        if not self.frida_setup.check_frida_server():
            return False
        
        if not self.frida_setup.attach_to_app():
            return False
        
        # Get module information
        print(f"\n{Fore.CYAN}[*] Enumerating modules...")
        modules = self.get_module_info()
        
        # Filter for interesting modules
        interesting_modules = [m for m in modules if 'libil2cpp' in m['name'] or 
                                                      'libunity' in m['name'] or
                                                      'roc.gp' in m['path']]
        
        print(f"{Fore.GREEN}[+] Found {len(interesting_modules)} interesting modules:")
        for mod in interesting_modules:
            print(f"{Fore.GREEN}    - {mod['name']} at {mod['base']}")
        
        # Find IL2CPP functions
        print(f"\n{Fore.CYAN}[*] Searching for IL2CPP functions...")
        il2cpp_info = self.find_il2cpp_functions()
        
        # Install memory hooks
        print(f"\n{Fore.CYAN}[*] Installing memory hooks...")
        hook_script = self.hook_memory_functions()
        
        # Keep running
        print(f"\n{Fore.GREEN}[+] Memory monitoring active!")
        print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop...")
        
        self.running = True
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Stopping memory monitoring...")
            self.running = False
        
        return True
    
    def stop_monitoring(self):
        """Stop memory monitoring"""
        self.running = False
        self.frida_setup.detach()


def main():
    """Main entry point for memory reader"""
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Rise of Kingdoms - Memory Reader Bot")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    reader = MemoryReader()
    
    try:
        reader.start_monitoring()
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}")
    finally:
        reader.stop_monitoring()
        print(f"\n{Fore.GREEN}[+] Memory reader stopped")


if __name__ == "__main__":
    main()
