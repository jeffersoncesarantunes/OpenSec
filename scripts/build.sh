#!/bin/sh
# OpenSec build script

echo "Building OpenSec..."
make clean && make

if [ $? -eq 0 ]; then
    echo "✅ Build successful! Binary at bin/opensec"
    ls -la bin/
else
    echo "❌ Build failed!"
    exit 1
fi
