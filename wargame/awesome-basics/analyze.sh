#!/bin/bash

echo "=== GDB Analysis Script ==="

# GDB 스크립트로 주요 정보 추출
gdb -batch -ex "file ./chall" \
           -ex "info functions" \
           -ex "disassemble main" \
           -ex "x/20i main" \
           -ex "info proc mappings" \
           -ex "quit" 2>/dev/null || echo "Some GDB commands failed"

echo ""
echo "=== Binary Analysis ==="
file ./chall
echo ""

echo "=== Objdump Analysis ==="
objdump -d chall | grep -A 20 -B 5 "main>:"
echo ""

echo "=== ROPgadget Analysis ==="
ROPgadget --binary chall | grep -E "(pop rdi|ret)" | head -10 || echo "ROPgadget not available"
echo ""

echo "=== Strings Analysis ==="
strings chall | head -10
