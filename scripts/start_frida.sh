#!/bin/bash
# Quick script to start Frida server on Android device

echo "Starting Frida Server 17.3.2..."

# Check adb
if ! command -v adb &> /dev/null; then
    echo "Error: ADB not found"
    exit 1
fi

# Check device
DEVICE=$(adb devices | grep -w "device" | head -1)
if [ -z "$DEVICE" ]; then
    echo "Error: No device connected"
    echo "For VirtualBox VM, use: adb connect 127.0.0.1:5555"
    exit 1
fi

# Kill existing frida-server
echo "Stopping existing frida-server instances..."
adb shell "su -c 'killall frida-server 2>/dev/null'" 2>/dev/null || true

# Start frida-server
echo "Starting frida-server..."
adb shell "su -c '/data/local/tmp/frida-server &'" &

sleep 2

# Verify
FRIDA_PS=$(adb shell "ps | grep frida-server" || echo "")
if [ -z "$FRIDA_PS" ]; then
    echo "Error: Frida server failed to start"
    echo ""
    echo "Make sure frida-server is installed:"
    echo "  ./setup_frida.sh"
    exit 1
fi

echo "Success! Frida server is running"

# Test with frida-ps
if command -v frida-ps &> /dev/null; then
    echo ""
    echo "Testing connection with frida-ps..."
    frida-ps -U | head -10
fi
