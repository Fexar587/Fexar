#!/bin/bash
# Script to setup Frida Server 17.3.2 on Android device

set -e

echo "=========================================="
echo "Frida Server 17.3.2 Setup Script"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if adb is available
if ! command -v adb &> /dev/null; then
    echo -e "${RED}[-] ADB not found. Please install Android Platform Tools.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] ADB found${NC}"

# Check device connection
echo -e "${YELLOW}[*] Checking device connection...${NC}"
DEVICE=$(adb devices | grep -w "device" | head -1)
if [ -z "$DEVICE" ]; then
    echo -e "${RED}[-] No device connected. Please connect your Android device or VM.${NC}"
    echo -e "${YELLOW}[!] For VirtualBox VM, use: adb connect 127.0.0.1:5555${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Device connected${NC}"

# Detect architecture
echo -e "${YELLOW}[*] Detecting device architecture...${NC}"
ARCH=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
echo -e "${GREEN}[+] Architecture: $ARCH${NC}"

# Determine Frida binary name
case $ARCH in
    arm64-v8a)
        FRIDA_BINARY="frida-server-17.3.2-android-arm64"
        ;;
    armeabi-v7a)
        FRIDA_BINARY="frida-server-17.3.2-android-arm"
        ;;
    x86_64)
        FRIDA_BINARY="frida-server-17.3.2-android-x86_64"
        ;;
    x86)
        FRIDA_BINARY="frida-server-17.3.2-android-x86"
        ;;
    *)
        echo -e "${RED}[-] Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

FRIDA_URL="https://github.com/frida/frida/releases/download/17.3.2/${FRIDA_BINARY}.xz"

# Download Frida if not exists
if [ ! -f "$FRIDA_BINARY" ]; then
    echo -e "${YELLOW}[*] Downloading Frida Server 17.3.2 for $ARCH...${NC}"
    
    if command -v wget &> /dev/null; then
        wget -O "${FRIDA_BINARY}.xz" "$FRIDA_URL"
    elif command -v curl &> /dev/null; then
        curl -L -o "${FRIDA_BINARY}.xz" "$FRIDA_URL"
    else
        echo -e "${RED}[-] Neither wget nor curl found. Please install one of them.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}[*] Extracting...${NC}"
    unxz "${FRIDA_BINARY}.xz"
    
    echo -e "${GREEN}[+] Downloaded and extracted${NC}"
else
    echo -e "${GREEN}[+] Frida binary already exists${NC}"
fi

# Check root access
echo -e "${YELLOW}[*] Checking root access...${NC}"
ROOT_CHECK=$(adb shell "su -c id" 2>&1 || echo "FAIL")
if [[ "$ROOT_CHECK" == *"FAIL"* ]] || [[ "$ROOT_CHECK" == *"not found"* ]]; then
    echo -e "${RED}[-] Root access not available. Please root your device.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Root access confirmed${NC}"

# Stop existing frida-server
echo -e "${YELLOW}[*] Stopping existing frida-server instances...${NC}"
adb shell "su -c 'killall frida-server 2>/dev/null'" 2>/dev/null || true

# Push frida-server to device
echo -e "${YELLOW}[*] Pushing frida-server to device...${NC}"
adb push "$FRIDA_BINARY" /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start frida-server
echo -e "${YELLOW}[*] Starting frida-server...${NC}"
adb shell "su -c '/data/local/tmp/frida-server &'" &
sleep 2

# Verify frida-server is running
echo -e "${YELLOW}[*] Verifying frida-server...${NC}"
FRIDA_PS=$(adb shell "ps | grep frida-server" || echo "")
if [ -z "$FRIDA_PS" ]; then
    echo -e "${RED}[-] Frida server failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Frida server is running!${NC}"

# Test with frida-ps if available
if command -v frida-ps &> /dev/null; then
    echo -e "${YELLOW}[*] Testing Frida connection...${NC}"
    sleep 2
    if frida-ps -U &> /dev/null; then
        echo -e "${GREEN}[+] Frida connection successful!${NC}"
    else
        echo -e "${YELLOW}[!] frida-ps test failed, but frida-server is running${NC}"
    fi
fi

echo ""
echo -e "${GREEN}=========================================="
echo -e "Setup Complete!"
echo -e "==========================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Make sure Rise of Kingdoms is installed"
echo "2. Run: python frida_setup.py"
echo "3. Run: python main.py"
echo ""
