#!/bin/sh
# OpenBSD development setup

echo "Setting up OpenSec development environment..."

# Check for required packages
if ! pkg_info -Q gcc > /dev/null 2>&1; then
    echo "Installing gcc..."
    doas pkg_add gcc
fi

# Create directories
mkdir -p bin obj/core obj/utils obj/modules

echo "✅ Environment ready!"
echo "   - GCC: $(gcc --version | head -1)"
