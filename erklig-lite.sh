#!/bin/bash

#  ███████╗██████╗ ██╗  ██╗██╗     ██╗ ██████╗ 
#  ██╔════╝██╔══██╗██║ ██╔╝██║     ██║██╔════╝ 
#  █████╗  ██████╔╝█████╔╝ ██║     ██║██║  ███╗
#  ██╔══╝  ██╔══██╗██╔═██╗ ██║     ██║██║   ██║
#  ███████╗██║  ██║██║  ██╗███████╗██║╚██████╔╝
#  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ 
#
#  ERKLIG - Mighty Backdoor Analysis Engine
#  "Inspired by Erlik Khan, the powerful deity of Turkish mythology"
#
#  Author: Can TURK
#  Website: https://iamcanturk.dev
#  GitHub: https://github.com/iamcanturk/erklig
#  Twitter: https://twitter.com/iamcanturk
#  License: MIT
#
#  This is a 100% open source project. Contributions are welcome!

# =============================================================================
# COLOR DEFINITIONS
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# =============================================================================
# SYSTEM CONFIGURATION
# =============================================================================
SYSTEM_NAME="ERKLIG BACKDOOR ANALYSIS SYSTEM"
VERSION="v1.3.0"
CODENAME="Mighty Engine"
OUTPUT_FILE="erklig_threat_report.txt"
TEMP_LIST="erklig_temp_scan.tmp"

# =============================================================================
# MALWARE SIGNATURES (Regex patterns for known threats)
# =============================================================================
# Categories:
#   - Command Execution: shell_exec, passthru, system, popen, proc_open, pcntl_exec
#   - Code Evaluation: eval, assert, preg_replace with /e modifier
#   - Encoding/Obfuscation: base64_decode, gzinflate, gzuncompress, str_rot13
#   - Known Webshells: FilesMan, WSO, c99, r57
#   - Network Functions: fsockopen, socket_accept, curl_exec
#   - Filesystem Abuse: symlink, chmod, chown
# =============================================================================
PATTERN="shell_exec|passthru|system\s*\(|phpinfo\s*\(|base64_decode|popen|proc_open|pcntl_exec|python_eval|eval\s*\(|assert\s*\(|preg_replace\s*\(.*/e|curlexec|FilesMan|wso_version|c99shell|r57shell|symlink|socket_accept|fsockopen|gzinflate|gzuncompress|str_rot13"

# =============================================================================
# WHITELIST - Known safe directories to reduce false positives
# =============================================================================
# These directories are commonly found in CMS and frameworks
# and typically contain legitimate code with "dangerous" functions
# =============================================================================
WHITELIST_DIRS=(
    "./vendor/"
    "./node_modules/"
    "./.git/"
    "./wp-includes/"
    "./wp-admin/"
    "./libraries/"
    "./core/"
    "./framework/"
)

# File extensions to scan (web files only for performance)
WEB_EXTENSIONS="php|phtml|php3|php4|php5|php7|phps|inc|asp|aspx|jsp|js|py|pl|cgi"

# =============================================================================
# FUNCTIONS
# =============================================================================

# Draw the header with ASCII art logo
draw_header() {
    clear
    echo -e "${CYAN}"
    echo "  ███████╗██████╗ ██╗  ██╗██╗     ██╗ ██████╗ "
    echo "  ██╔════╝██╔══██╗██║ ██╔╝██║     ██║██╔════╝ "
    echo "  █████╗  ██████╔╝█████╔╝ ██║     ██║██║  ███╗"
    echo "  ██╔══╝  ██╔══██╗██╔═██╗ ██║     ██║██║   ██║"
    echo "  ███████╗██║  ██║██║  ██╗███████╗██║╚██████╔╝"
    echo "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ "
    echo -e "${NC}"
    echo -e "${MAGENTA}  ⚔️  $SYSTEM_NAME ⚔️${NC}"
    echo -e "${YELLOW}      $VERSION - $CODENAME${NC}"
    echo -e "${DIM}      by Can TURK | https://iamcanturk.dev${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Build whitelist exclusion pattern for grep
build_whitelist_exclude() {
    local exclude_pattern=""
    for dir in "${WHITELIST_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            exclude_pattern="$exclude_pattern --exclude-dir=${dir#./}"
        fi
    done
    echo "$exclude_pattern"
}

# Display progress bar
show_progress() {
    local current=$1
    local total=$2
    local width=40
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r${CYAN}[${NC}"
    printf "%0.s█" $(seq 1 $filled 2>/dev/null) 
    printf "%0.s░" $(seq 1 $empty 2>/dev/null)
    printf "${CYAN}]${NC} ${YELLOW}%3d%%${NC} (%d/%d)" "$percentage" "$current" "$total"
}

# Check if a file viewer with syntax highlighting is available
get_file_viewer() {
    if command -v bat &> /dev/null; then
        echo "bat --style=numbers,grid --paging=always"
    elif command -v batcat &> /dev/null; then
        echo "batcat --style=numbers,grid --paging=always"
    else
        echo "less -N"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

draw_header
echo -e "${YELLOW}[INFO] Initializing system...${NC}"
echo -e "${YELLOW}[INFO] Target directory: ${BOLD}$(pwd)${NC}"
echo -e "${YELLOW}[INFO] Building whitelist exclusions...${NC}"
sleep 1

# Initialize output files
> "$TEMP_LIST"
> "$OUTPUT_FILE"

# Build exclusion pattern from whitelist
EXCLUDE_PATTERN=$(build_whitelist_exclude)

# =============================================================================
# PHASE 1: Signature-based scanning
# =============================================================================
echo ""
echo -e "${BLUE}[PHASE 1/3] Running signature-based code analysis...${NC}"

# Scan only web file extensions, exclude whitelist directories
eval "grep -rIlE '$PATTERN' . \
    --include='*.php' --include='*.phtml' --include='*.php5' \
    --include='*.inc' --include='*.asp' --include='*.aspx' \
    --include='*.js' --include='*.py' --include='*.pl' --include='*.cgi' \
    --exclude='erklig.sh' --exclude='$TEMP_LIST' --exclude='$OUTPUT_FILE' \
    $EXCLUDE_PATTERN 2>/dev/null" >> "$TEMP_LIST"

# =============================================================================
# PHASE 2: Anomaly detection (suspicious file extensions)
# =============================================================================
echo -e "${BLUE}[PHASE 2/3] Scanning for file extension anomalies...${NC}"

# Double extensions (common obfuscation technique)
find . -type f \( \
    -name "*.php.*" -o \
    -name "*.jpg.php" -o \
    -name "*.png.php" -o \
    -name "*.gif.php" -o \
    -name "*.txt.php" -o \
    -name "*.php.suspected" \
\) 2>/dev/null >> "$TEMP_LIST"

# =============================================================================
# PHASE 3: Permission anomaly check (optional, Linux/macOS)
# =============================================================================
echo -e "${BLUE}[PHASE 3/3] Checking for permission anomalies...${NC}"

# Find files with overly permissive permissions (777, 666)
find . -type f \( -perm 777 -o -perm 666 \) \
    \( -name "*.php" -o -name "*.phtml" -o -name "*.inc" \) \
    2>/dev/null >> "$TEMP_LIST"

# Remove duplicates and sort
sort -u "$TEMP_LIST" -o "$TEMP_LIST"

TOTAL_FILES=$(wc -l < "$TEMP_LIST" | tr -d ' ')
COUNTER=0

# =============================================================================
# RESULTS EVALUATION
# =============================================================================
echo ""
if [ "$TOTAL_FILES" -eq 0 ]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ SYSTEM CLEAN - No potential threats detected              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    rm -f "$TEMP_LIST"
    exit 0
fi

echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  ⚠ ALERT: $TOTAL_FILES potential threat(s) detected                       ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Entering interactive analysis mode...${NC}"
sleep 2

# Get the best available file viewer
FILE_VIEWER=$(get_file_viewer)

# =============================================================================
# INTERACTIVE ANALYSIS MODULE
# =============================================================================
# Note: Using 'read -u 3' to separate keyboard input from file reading
# =============================================================================
while IFS= read -r -u 3 file; do
    COUNTER=$((COUNTER+1))
    
    while true; do
        draw_header
        
        # Show progress
        show_progress "$COUNTER" "$TOTAL_FILES"
        echo ""
        echo ""
        
        echo -e "${YELLOW}>> ANALYZING FILE [$COUNTER / $TOTAL_FILES]${NC}"
        echo -e "${BLUE}FILE PATH:${NC} $file"
        
        # Show file metadata
        if [ -f "$file" ]; then
            FILE_SIZE=$(ls -lh "$file" 2>/dev/null | awk '{print $5}')
            FILE_DATE=$(ls -l "$file" 2>/dev/null | awk '{print $6, $7, $8}')
            FILE_PERMS=$(ls -l "$file" 2>/dev/null | awk '{print $1}')
            echo -e "${DIM}Size: $FILE_SIZE | Modified: $FILE_DATE | Perms: $FILE_PERMS${NC}"
        fi
        
        echo "──────────────────────────────────────────────────────────────"
        
        # Show detected suspicious code snippets
        echo -e "${RED}>> DETECTED SUSPICIOUS CODE PATTERNS:${NC}"
        grep -nE --color=always "$PATTERN" -- "$file" 2>/dev/null | head -n 8
        echo -e "${DIM}...(more lines may be hidden)...${NC}"
        
        echo "──────────────────────────────────────────────────────────────"
        echo -e "${BOLD}COMMAND PANEL:${NC}"
        echo -e "  [${RED}T${NC}]hreat  -> Mark as THREAT (Add to report)"
        echo -e "  [${GREEN}S${NC}]afe    -> Mark as SAFE (Skip)"
        echo -e "  [${BLUE}V${NC}]iew    -> View full source code"
        echo -e "  [${YELLOW}Q${NC}]uit    -> Exit analysis"
        echo "──────────────────────────────────────────────────────────────"
        
        read -p "Enter command (t/s/v/q): " choice

        case $choice in
            [Tt]* ) 
                echo "$file" >> "$OUTPUT_FILE"
                echo -e "${RED}>> File added to threat report.${NC}"
                sleep 0.5
                break
                ;;
            [Ss]* ) 
                echo -e "${GREEN}>> File marked as safe.${NC}"
                sleep 0.5
                break
                ;;
            [Vv]* ) 
                eval "$FILE_VIEWER '$file'"
                ;;
            [Qq]* )
                echo -e "${YELLOW}>> Analysis interrupted by user.${NC}"
                rm -f "$TEMP_LIST"
                exit 0
                ;;
            * ) 
                echo -e "${RED}Invalid command. Please try again.${NC}"
                sleep 1
                ;;
        esac
    done

done 3< "$TEMP_LIST"

# =============================================================================
# FINAL REPORT
# =============================================================================
rm -f "$TEMP_LIST"
draw_header

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              📊 ANALYSIS COMPLETE                            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ -s "$OUTPUT_FILE" ]; then
    THREAT_COUNT=$(wc -l < "$OUTPUT_FILE" | tr -d ' ')
    echo -e "${RED}⚠ CRITICAL: $THREAT_COUNT file(s) confirmed as threats.${NC}"
    echo -e "${YELLOW}Report file: ${BOLD}$OUTPUT_FILE${NC}"
    echo ""
    echo "──────────────────────────────────────────────────────────────"
    echo -e "${BOLD}THREAT LIST:${NC}"
    cat "$OUTPUT_FILE" | while read line; do
        echo -e "  ${RED}•${NC} $line"
    done
    echo "──────────────────────────────────────────────────────────────"
    echo ""
    echo -e "${YELLOW}RECOMMENDED CLEANUP COMMAND:${NC}"
    echo -e "${DIM}(Review the files before executing!)${NC}"
    echo ""
    echo -e "${BLUE}  xargs rm -i < $OUTPUT_FILE${NC}"
    echo ""
    echo "──────────────────────────────────────────────────────────────"
else
    echo -e "${GREEN}✓ No threats confirmed. System appears clean.${NC}"
fi

echo ""
echo -e "${DIM}Thank you for using ERKLIG! - https://github.com/iamcanturk/erklig${NC}"
echo ""
