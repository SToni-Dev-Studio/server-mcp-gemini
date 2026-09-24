#!/bin/bash
# fix-kernel-139-network.sh
# Fixes r8169 ethernet driver issues on kernel 6.8.0-139-generic
# by updating firmware and rebuilding the initramfs for that kernel.
#
# Run this while booted into 6.8.0-138-generic (which has working internet).
# After running, reboot and select 6.8.0-139-generic from GRUB.

set -e

echo "=== Kernel 139 Network Fix ==="
echo "Current kernel: $(uname -r)"
echo ""

# Check we have internet
if ! ping -c1 -W3 8.8.8.8 &>/dev/null; then
    echo "ERROR: No internet access. Boot into 6.8.0-138-generic first."
    exit 1
fi

# Check kernel 139 is installed
if [ ! -f /boot/vmlinuz-6.8.0-139-generic ]; then
    echo "ERROR: 6.8.0-139-generic not found in /boot"
    exit 1
fi

echo "Step 1: Update linux-firmware package..."
sudo apt-get update -qq
sudo apt-get install -y linux-firmware
echo "✅ firmware updated"

echo ""
echo "Step 2: Rebuild initramfs for 6.8.0-139-generic..."
sudo update-initramfs -u -k 6.8.0-139-generic
echo "✅ initramfs rebuilt"

echo ""
echo "Step 3: Verify r8169 firmware is present..."
if find /lib/firmware -name "rtl*" 2>/dev/null | grep -q rtl; then
    echo "✅ Realtek firmware found:"
    find /lib/firmware -name "rtl8168*" -o -name "rtl8169*" 2>/dev/null | head -5
else
    echo "⚠️  No Realtek firmware found - may still work via kernel built-in"
fi

echo ""
echo "Step 4: Set GRUB default to kernel 139..."
sudo sed -i 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=0/' /etc/default/grub
sudo update-grub
echo "✅ GRUB updated - kernel 139 will be default on next boot"

echo ""
echo "=== Done! ==="
echo "Reboot and verify with: uname -r && ping 8.8.8.8"
echo "If network still fails on 139, run: journalctl -k -b 0 | grep -i r8169"
