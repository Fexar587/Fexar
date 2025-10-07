#!/bin/bash
# Script to install Rise of Kingdoms on Android device

echo "=========================================="
echo "Rise of Kingdoms Installer"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check adb
if ! command -v adb &> /dev/null; then
    echo -e "${RED}[-] ADB not found${NC}"
    exit 1
fi

# Check device
echo -e "${YELLOW}[*] Checking device connection...${NC}"
DEVICE=$(adb devices | grep -w "device" | head -1)
if [ -z "$DEVICE" ]; then
    echo -e "${RED}[-] No device connected${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Device connected${NC}"

# Check if APK file is provided
if [ -z "$1" ]; then
    echo -e "${YELLOW}[*] No APK file provided${NC}"
    echo -e "${YELLOW}[!] Usage: $0 <path_to_rok_apk>${NC}"
    echo ""
    echo -e "${YELLOW}[*] Checking if Rise of Kingdoms is already installed...${NC}"
    
    INSTALLED=$(adb shell pm list packages | grep com.lilithgames.roc.gp || echo "")
    if [ -z "$INSTALLED" ]; then
        echo -e "${RED}[-] Rise of Kingdoms not installed${NC}"
        echo ""
        echo "Download APK from:"
        echo "  https://apkpure.com/rise-of-kingdoms/com.lilithgames.roc.gp"
        echo ""
        echo "Then run: $0 <path_to_rok.apk>"
        exit 1
    else
        echo -e "${GREEN}[+] Rise of Kingdoms is already installed${NC}"
        
        # Get version
        VERSION=$(adb shell dumpsys package com.lilithgames.roc.gp | grep versionName | head -1)
        echo -e "${GREEN}    $VERSION${NC}"
        exit 0
    fi
fi

APK_PATH="$1"

# Check if APK exists
if [ ! -f "$APK_PATH" ]; then
    echo -e "${RED}[-] APK file not found: $APK_PATH${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Installing Rise of Kingdoms...${NC}"
echo -e "${YELLOW}    APK: $APK_PATH${NC}"

# Install APK
adb install -r "$APK_PATH"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Installation successful!${NC}"
    
    # Verify installation
    INSTALLED=$(adb shell pm list packages | grep com.lilithgames.roc.gp || echo "")
    if [ ! -z "$INSTALLED" ]; then
        echo -e "${GREEN}[+] Verified: Rise of Kingdoms is installed${NC}"
        
        # Get version
        VERSION=$(adb shell dumpsys package com.lilithgames.roc.gp | grep versionName | head -1)
        echo -e "${GREEN}    $VERSION${NC}"
    fi
else
    echo -e "${RED}[-] Installation failed${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}You can now launch the game and run the bot${NC}"
echo ""
