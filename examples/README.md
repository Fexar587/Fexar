# Examples

This directory contains example scripts showing how to use the Rise of Kingdoms bot framework.

## Available Examples

### custom_hook_example.py

Shows how to create custom Frida hooks for:
- Memory allocation monitoring (malloc tracking)
- IL2CPP function hooking
- Memory pattern scanning
- Memory address monitoring

**Usage:**
```bash
python examples/custom_hook_example.py
```

## Creating Your Own Examples

Use these examples as templates for your own custom scripts:

1. Import the necessary modules
2. Create your Frida script
3. Set up message handlers
4. Connect and attach to the game
5. Load your script and monitor

### Template

```python
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frida_setup import FridaSetup

CUSTOM_SCRIPT = """
// Your Frida JavaScript code here
console.log("[*] Script started");
"""

def on_message(message, data):
    # Handle messages from Frida
    if message['type'] == 'send':
        print(message['payload'])

def main():
    setup = FridaSetup()
    
    if setup.connect_device() and setup.check_frida_server() and setup.attach_to_app():
        script = setup.session.create_script(CUSTOM_SCRIPT)
        script.on('message', on_message)
        script.load()
        
        # Keep running
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            setup.detach()

if __name__ == "__main__":
    main()
```

## Tips

- Always test your hooks on a development device first
- Use try-catch blocks in your Frida scripts to handle errors
- Start with simple hooks and gradually add complexity
- Use `console.log()` liberally for debugging
- Check the Frida documentation for advanced features

## Resources

- [Frida Documentation](https://frida.re/docs/)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [IL2CPP Reverse Engineering Guide](https://katyscode.wordpress.com/2021/02/23/il2cpp-finding-obfuscated-global-metadata/)

## Support

For help with examples:
1. Check the main README.md
2. Consult ChatGPT 5
3. Open an issue on GitHub
