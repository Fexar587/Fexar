# Fexar - Rise of Kingdoms Memory Bot

A powerful memory reading bot for Rise of Kingdoms using Frida 17.3.2 on Android (VirtualBox).

## Features

- 🔍 Extract `libil2cpp.so` from game memory
- 📦 Extract and decode `global-metadata.dat` 
- 💾 Real-time RAM memory reading
- 🎯 IL2CPP function hooking
- 📊 Memory allocation monitoring

## Prerequisites

### Android Device Setup (VirtualBox)
1. VirtualBox with Android x86/ARM image
2. Android device with **root access**
3. USB debugging enabled
4. Rise of Kingdoms installed

### Frida Server Setup
1. Download Frida Server 17.3.2 for your Android architecture:
   ```bash
   # For ARM64
   wget https://github.com/frida/frida/releases/download/17.3.2/frida-server-17.3.2-android-arm64.xz
   
   # For x86_64
   wget https://github.com/frida/frida/releases/download/17.3.2/frida-server-17.3.2-android-x86_64.xz
   ```

2. Extract and push to device:
   ```bash
   unxz frida-server-*.xz
   adb push frida-server-17.3.2-android-* /data/local/tmp/frida-server
   adb shell "chmod 755 /data/local/tmp/frida-server"
   ```

3. Run Frida server on device:
   ```bash
   adb shell "su -c /data/local/tmp/frida-server &"
   ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Fexar587/Fexar.git
   cd Fexar
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Verify Frida connection:
   ```bash
   frida-ps -U
   ```

## Usage

### Quick Start

Run the main menu interface:
```bash
python main.py
```

### Menu Options

1. **Test Frida Connection** - Verify device connection and Frida server
2. **Extract libil2cpp.so** - Dump IL2CPP library from memory
3. **Extract global-metadata.dat** - Extract metadata file from game
4. **Extract Both** - Extract both files automatically
5. **Start Memory Reader Bot** - Monitor memory in real-time
6. **Show Extracted Files** - View extracted file information

### Individual Scripts

#### Test Frida Setup
```bash
python frida_setup.py
```

#### Extract libil2cpp.so
```bash
python extract_il2cpp.py
```

#### Extract global-metadata.dat
```bash
python extract_metadata.py
```

#### Start Memory Reader
```bash
python memory_reader.py
```

## Configuration

Edit `config.py` to customize:

```python
# Package name
PACKAGE_NAME = "com.lilithgames.roc.gp"

# Output directory
OUTPUT_DIR = "extracted"

# Memory scan interval
MEMORY_SCAN_INTERVAL = 0.1
```

## Extracted Files Usage

Once you have extracted `libil2cpp.so` and `global-metadata.dat`, you can analyze them with:

### Il2CppDumper
```bash
# Download Il2CppDumper
git clone https://github.com/Perfare/Il2CppDumper.git

# Run dumper
Il2CppDumper.exe libil2cpp.so global-metadata.dat output_dir
```

### Il2CppInspector
```bash
# Install Il2CppInspector
git clone https://github.com/djkaty/Il2CppInspector.git

# Analyze files
Il2CppInspector -i libil2cpp.so -m global-metadata.dat -o output
```

### Ghidra
1. Load `libil2cpp.so` in Ghidra
2. Use IL2CPP analyzer script
3. Import symbols from metadata

## Project Structure

```
Fexar/
├── main.py                 # Main menu interface
├── config.py              # Configuration settings
├── frida_setup.py         # Frida connection and setup
├── extract_il2cpp.py      # IL2CPP library extractor
├── extract_metadata.py    # Metadata file extractor
├── memory_reader.py       # Memory reading bot
├── requirements.txt       # Python dependencies
├── .gitignore            # Git ignore rules
└── extracted/            # Output directory (auto-created)
    ├── libil2cpp.so      # Extracted IL2CPP library
    └── global-metadata.dat  # Extracted metadata
```

## Features in Detail

### Memory Reading Bot
- Enumerates all loaded modules
- Finds IL2CPP exported functions
- Hooks memory allocation functions (malloc/free)
- Monitors IL2CPP domain operations
- Scans memory regions for patterns

### IL2CPP Extractor
- Automatically locates libil2cpp.so in memory
- Dumps entire library from process memory
- Preserves original file structure
- Validates extracted file integrity

### Metadata Extractor
- Locates metadata file in APK assets
- Reads and extracts encoded metadata
- Decodes IL2CPP metadata format
- Exports ready-to-use metadata file

## Troubleshooting

### Frida Server Not Found
```bash
# Check if frida-server is running
adb shell "ps | grep frida"

# Restart frida-server
adb shell "su -c 'killall frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

### App Not Found
```bash
# Check if Rise of Kingdoms is installed
adb shell "pm list packages | grep lilithgames"

# Launch the app manually
adb shell "am start -n com.lilithgames.roc.gp/.MainActivity"
```

### Connection Timeout
```bash
# Check ADB connection
adb devices

# Forward Frida port
adb forward tcp:27042 tcp:27042
```

### Permission Denied
```bash
# Ensure root access
adb shell "su -c 'id'"

# Set SELinux to permissive (if needed)
adb shell "su -c 'setenforce 0'"
```

## Advanced Usage

### Custom Memory Patterns
Edit `memory_reader.py` to add custom memory scanning patterns:

```python
# Scan for specific pattern
pattern = b"\x00\x01\x02\x03"
result = reader.scan_memory_region(base_address, size, pattern)
```

### Hook Custom Functions
Add custom hooks in `memory_reader.py`:

```python
# Hook specific IL2CPP function
script_code = """
var funcAddress = Module.findExportByName("libil2cpp.so", "your_function");
Interceptor.attach(funcAddress, {
    onEnter: function(args) {
        console.log("Function called!");
    }
});
"""
```

## Security & Legal Notice

⚠️ **Important**: This tool is for educational and research purposes only.

- Only use on games you own or have permission to analyze
- Reverse engineering may violate Terms of Service
- Use at your own risk
- Do not distribute extracted game files
- Respect intellectual property rights

## ChatGPT 5 Integration

This bot is designed to work with ChatGPT 5 for:
- Analyzing extracted IL2CPP structures
- Understanding game memory layouts
- Generating custom Frida scripts
- Debugging memory reading issues
- Interpreting metadata information

Share extracted files with ChatGPT to get:
- Class structure analysis
- Method signature interpretation
- Memory offset calculations
- Hook script generation

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is for educational purposes only.

## Acknowledgments

- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) - IL2CPP analysis tool
- Rise of Kingdoms - Game by Lilith Games

## Support

For issues and questions:
- Open an issue on GitHub
- Consult ChatGPT 5 for assistance
- Check Frida documentation

---

**Version**: 1.0.0  
**Frida**: 17.3.2  
**Target**: Rise of Kingdoms (com.lilithgames.roc.gp)
