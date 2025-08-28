#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo ""
echo -e "${RED}█▀▀ █▀█ ▄▀█ █▄█ █▄▄ █▄█ ▀█▀ █▀▀   █▀ █░█ █▀ ▄▄ █ █▀█   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█\n█▄█ █▀▄ █▀█ ░█░ █▄█ ░█░ ░█░ ██▄   ▄█ █▄█ ▄█ ░░ █ █▀▀   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄${NC}"
echo ""
echo -e "${YELLOW}# Description: This tool groups network connections by application to detect suspicious activity, such as password stealers.${NC}"
echo -e "${YELLOW}# It uses 'ss' to list connections, including process name, PID, executable path, command-line arguments, and connection details.${NC}"
echo -e "${YELLOW}# The output is saved to a text file named 'date-month-year-gray-susip.txt' (e.g., 29-Aug-2025-gray-susip.txt).${NC}"
echo ""
echo "====================================================================="
echo -e "${BLUE}# Usage:${NC}"
echo ""
echo -e "${BLUE}#   1. Save this script as 'sus_ip_scanner.sh'.${NC}"
echo -e "${BLUE}#   2. Make it executable: chmod +x sus_ip_scanner.sh${NC}"
echo -e "${BLUE}#   3. Run the script: ./sus_ip_scanner.sh${NC}"
echo -e "${BLUE}#   4. Check the generated text file for grouped connection details.${NC}"
echo ""
echo "====================================================================="
echo ""
echo -e "${PURPLE}# Prerequisites:${NC}"
echo ""
echo -e "${PURPLE}#   - Requires 'ss' (part of iproute2 package).${NC}"
echo -e "${PURPLE}#   - If 'ss' is not installed, install it on Arch-based systems (e.g., Garuda Linux):${NC}"
echo -e "${PURPLE}#     sudo pacman -S iproute2${NC}"
echo -e "${PURPLE}#   - On other Linux distributions:${NC}"
echo -e "${PURPLE}#     - Debian/Ubuntu: sudo apt-get install iproute2${NC}"
echo -e "${PURPLE}#     - Fedora: sudo dnf install iproute${NC}"
echo ""
echo "====================================================================="
echo ""
echo -e "${CYAN}Step 1: Generating output file name...${NC}"
output_file="$(date +%d-%b-%Y)-gray-susip.txt"

echo -e "${RED}Step 2: Checking for 'ss' command...${NC}"
if ! command -v ss &> /dev/null; then
    echo -e "${YELLOW}Error: 'ss' command not found. Please install iproute2.${NC}"
    echo -e "${YELLOW}On Arch-based systems: sudo pacman -S iproute2${NC}"
    echo -e "${YELLOW}On Debian/Ubuntu: sudo apt-get install iproute2${NC}"
    echo -e "${YELLOW}On Fedora: sudo dnf install iproute${NC}"
    exit 1
fi

echo -e "${GREEN}Step 3: Creating temporary file for processing...${NC}"
temp_file=$(mktemp)

echo -e "${BLUE}Step 4: Collecting network connection details...${NC}"
ss -tunap | grep -v '^$' | while read -r line; do
    netid=$(echo "$line" | awk '{print $1}')
    state=$(echo "$line" | awk '{print $2}')
    local_addr=$(echo "$line" | awk '{print $5}')
    peer_addr=$(echo "$line" | awk '{print $6}')
    pid=$(echo "$line" | grep -o 'pid=[0-9]*' | cut -d= -f2)
    proc_name=$(echo "$line" | grep -o 'users:(("\w*",pid=[0-9]*,fd=[0-9]*))' | cut -d'"' -f2)

    exe_path=""
    if [ -n "$pid" ] && [ -r "/proc/$pid/exe" ]; then
        exe_path=$(ls -l "/proc/$pid/exe" 2>/dev/null | awk '{print $NF}' || echo "N/A")
    else
        exe_path="N/A"
    fi

    cmdline=""
    if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
        cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "N/A")
    else
        cmdline="N/A"
    fi

    if [ -n "$pid" ]; then
        printf "%s|%s|%s|%s|%s|%s|%s\n" \
            "$proc_name" "$pid" "$exe_path" "$cmdline" "$netid" "$state" "$local_addr|$peer_addr" >> "$temp_file"
    fi
done

echo -e "${PURPLE}Step 5: Writing grouped connections to $output_file...${NC}"
{
    echo -e "𝙂𝙍𝘼𝙔𝘽𝙔𝙏𝙀 𝙎𝙐𝙎-𝙄𝙋 𝙎𝘾𝘼𝙉𝙉𝙀𝙍 𝘿𝙀𝘼𝙄𝙇𝙏𝙀𝘿 𝙇𝙊𝙂"
    echo ""
    echo "====================================================================="
    echo "Generated on: $(date)"
    echo "Description: Grouped network connections by application to detect suspicious activity."
    echo "====================================================================="

    last_proc=""
    sort -t'|' -k1 "$temp_file" | while read -r line; do
        proc_name=$(echo "$line" | cut -d'|' -f1)
        pid=$(echo "$line" | cut -d'|' -f2)
        exe_path=$(echo "$line" | cut -d'|' -f3)
        cmdline=$(echo "$line" | cut -d'|' -f4)
        netid=$(echo "$line" | cut -d'|' -f5)
        state=$(echo "$line" | cut -d'|' -f6)
        addr=$(echo "$line" | cut -d'|' -f7)
        local_addr=$(echo "$addr" | cut -d'|' -f1)
        peer_addr=$(echo "$addr" | cut -d'|' -f2)

        if [ "$proc_name" != "$last_proc" ]; then
            if [ -n "$last_proc" ]; then
                echo ""
            fi
            echo ""
            echo "Application Name : $proc_name"
            echo "====================================================================="
            echo "PID: $pid"
            echo "Executable Path: $exe_path"
            echo "Command Line: $cmdline"
            echo ""
            echo "Netid | State      | Local Address:Port       | Peer Address:Port"
            echo "------|------------|--------------------------|-------------------"
            last_proc="$proc_name"
        fi

        printf "%-6s|%-12s|%-25s|%-s\n" "$netid" "$state" "$local_addr" "$peer_addr"
    done
    echo ""
    echo "DO NOT FORGET TO SAY FUCK PAPPU !!!"
} > "$output_file"

echo -e "${CYAN}Step 6: Cleaning up temporary file...${NC}"
rm "$temp_file"

echo -e "${RED}Step 7: Scan complete!${NC}"
echo -e "${GREEN}Find Detailed Log Here: $(pwd)/$output_file${NC}"
echo ""
echo -e "${RED}DO NOT FORGET TO SAY FUCK PAPPU !!!${NC}"
