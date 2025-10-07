"""
Configuration file for Rise of Kingdoms memory bot
"""

# Frida configuration
FRIDA_VERSION = "17.3.2"
FRIDA_SERVER_PORT = 27042

# Android device configuration
DEVICE_ID = None  # None for USB device, or specify device ID
PACKAGE_NAME = "com.lilithgames.roc.gp"  # Rise of Kingdoms package name

# IL2CPP configuration
LIBIL2CPP_PATH = "/data/app/~~*/com.lilithgames.roc.gp-*/lib/arm64/libil2cpp.so"
METADATA_PATH = "/data/app/~~*/com.lilithgames.roc.gp-*/assets/bin/Data/Managed/Metadata/global-metadata.dat"

# Output paths
OUTPUT_DIR = "extracted"
LIBIL2CPP_OUTPUT = "extracted/libil2cpp.so"
METADATA_OUTPUT = "extracted/global-metadata.dat"

# Memory reading configuration
MEMORY_SCAN_INTERVAL = 0.1  # seconds
MAX_RETRIES = 3
