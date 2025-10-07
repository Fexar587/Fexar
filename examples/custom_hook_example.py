#!/usr/bin/env python3
"""
Example: Custom Frida Hook for Rise of Kingdoms

This example shows how to create a custom hook to monitor
specific game functions.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import frida
from frida_setup import FridaSetup

# Custom Frida script
HOOK_SCRIPT = """
console.log("[*] Custom Hook Script Started");

// Find IL2CPP module
var il2cpp = Process.findModuleByName("libil2cpp.so");
if (!il2cpp) {
    console.log("[-] IL2CPP module not found");
} else {
    console.log("[+] IL2CPP base: " + il2cpp.base);
    console.log("[+] IL2CPP size: " + il2cpp.size);
}

// Example 1: Hook malloc to track memory allocations
var mallocPtr = Module.findExportByName(null, 'malloc');
if (mallocPtr) {
    Interceptor.attach(mallocPtr, {
        onEnter: function(args) {
            this.size = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (this.size > 10000) { // Only log large allocations
                send({
                    type: "malloc",
                    address: retval.toString(),
                    size: this.size
                });
            }
        }
    });
    console.log("[+] Hooked malloc");
}

// Example 2: Find and hook IL2CPP functions
// You can add specific function names after analyzing with Il2CppDumper
var functionNames = [
    "il2cpp_string_new",
    "il2cpp_object_new",
    "il2cpp_thread_attach"
];

functionNames.forEach(function(name) {
    var funcPtr = Module.findExportByName("libil2cpp.so", name);
    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                send({
                    type: "function_call",
                    function: name,
                    args: Array.prototype.slice.call(arguments)
                });
            }
        });
        console.log("[+] Hooked: " + name);
    }
});

// Example 3: Memory scanning for patterns
function scanMemory(pattern) {
    console.log("[*] Scanning memory for pattern: " + pattern);
    
    Process.enumerateRanges('r--').forEach(function(range) {
        try {
            var matches = Memory.scanSync(range.base, range.size, pattern);
            if (matches.length > 0) {
                send({
                    type: "pattern_found",
                    pattern: pattern,
                    matches: matches.length,
                    range: range.base.toString()
                });
            }
        } catch(e) {
            // Ignore errors
        }
    });
}

// Example 4: Monitor specific memory address
function monitorAddress(address, size) {
    var addr = ptr(address);
    
    // Read initial value
    var initialValue = Memory.readByteArray(addr, size);
    send({
        type: "memory_snapshot",
        address: address,
        size: size,
        data: Array.from(new Uint8Array(initialValue))
    });
    
    // Set up memory access monitoring
    Memory.protect(addr, size, 'rw-');
    
    // Note: For continuous monitoring, you would need to use
    // MemoryAccessMonitor which requires specific conditions
}

console.log("[*] Custom hooks installed successfully");
console.log("[*] Monitoring started...");
"""


def on_message(message, data):
    """Handle messages from Frida script"""
    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', '')
        
        if msg_type == 'malloc':
            print(f"[Malloc] Address: {payload['address']}, Size: {payload['size']} bytes")
        
        elif msg_type == 'function_call':
            print(f"[Function] {payload['function']} called")
        
        elif msg_type == 'pattern_found':
            print(f"[Pattern] Found '{payload['pattern']}' - {payload['matches']} matches at {payload['range']}")
        
        elif msg_type == 'memory_snapshot':
            print(f"[Memory] Snapshot at {payload['address']}: {payload['size']} bytes")
            print(f"         Data: {payload['data'][:16]}...")  # Show first 16 bytes
        
        else:
            print(f"[Message] {payload}")
    
    elif message['type'] == 'error':
        print(f"[Error] {message['stack']}")


def main():
    print("=" * 60)
    print("Custom Hook Example for Rise of Kingdoms")
    print("=" * 60)
    print()
    
    # Setup Frida
    setup = FridaSetup()
    
    if not setup.connect_device():
        print("Failed to connect to device")
        return
    
    if not setup.check_frida_server():
        print("Frida server not running")
        return
    
    if not setup.attach_to_app():
        print("Failed to attach to app")
        return
    
    # Load custom script
    print("\n[*] Loading custom hook script...")
    script = setup.session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    print("[+] Custom hooks active!")
    
    print("\n[*] Monitoring game... Press Ctrl+C to stop")
    print()
    
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    finally:
        setup.detach()
        print("[+] Done")


if __name__ == "__main__":
    main()
