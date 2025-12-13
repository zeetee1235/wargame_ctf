#!/bin/bash

flags=(
    "runa2025{MZ_e_lfanew_F8_checksum_0CFA0BC7}"
    "runa2025{dos_sig_MZ_pe_offset_F8_checksum}"
    "runa2025{276a8e2006207310413960c74705b1e1}"
)

for flag in "${flags[@]}"; do
    echo "Testing: $flag"
    echo "$flag" | wine prob_fixed3.exe 2>&1 | grep -E "Input flag:|Correct|Wrong" | tail -2
    echo
done
