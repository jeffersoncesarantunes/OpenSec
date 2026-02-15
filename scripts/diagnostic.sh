#!/bin/sh
# OpenSec diagnostic tool

echo "OpenSec Diagnostic Tool"
echo "========================"

echo "Checking source files..."
find src -name "*.c" | wc -l

echo "Checking headers..."
find include -name "*.h" | wc -l

echo "System information:"
sysctl kern.version | head -1
