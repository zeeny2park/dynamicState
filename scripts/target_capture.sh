#!/bin/sh
# dynamicState — Embedded Linux Target Memory Capture Script
# Zero-Python Dependency: Runs using standard POSIX/BusyBox shell tools (sh, dd, awk, grep)
#
# Usage on Embedded Target:
#   sh target_capture.sh <PID> [OUTPUT_DIR] [MAX_MB]
#
# Output:
#   A directory containing memory regions and metadata ready for transfer to Host PC:
#   <OUTPUT_DIR>/
#     ├── metadata.json
#     ├── manifest.json
#     ├── maps.txt
#     └── memory/
#           ├── region_000001.bin
#           └── ...

set -e

PID="$1"
OUT_DIR="${2:-raw_snapshot_${PID}}"
MAX_MB="${3:-32}"
MAX_BYTES=$((MAX_MB * 1024 * 1024))

if [ -z "$PID" ]; then
    echo "Usage: $0 <PID> [OUTPUT_DIR] [MAX_MB]" >&2
    exit 1
fi

if [ ! -d "/proc/$PID" ]; then
    echo "ERROR: Process $PID does not exist in /proc" >&2
    exit 1
fi

if [ ! -r "/proc/$PID/maps" ] || [ ! -r "/proc/$PID/mem" ]; then
    echo "ERROR: Cannot read /proc/$PID/maps or /proc/$PID/mem (check permissions / root)" >&2
    exit 1
fi

EXE_LINK=$(readlink "/proc/$PID/exe" 2>/dev/null || echo "unknown")
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)

mkdir -p "$OUT_DIR/memory"
cp "/proc/$PID/maps" "$OUT_DIR/maps.txt"

TOTAL_CAPTURED=0
REGION_COUNT=0

echo "[dynamicState] Capturing memory for PID $PID ($EXE_LINK)..."
echo "[dynamicState] Max capture limit: ${MAX_MB}MB"

# Parse /proc/$PID/maps
# Format: address           perms offset  dev   inode   pathname
# 00400000-00452000 r-xp 00000000 08:02 173521  /bin/app
while IFS= read -r line; do
    if [ $TOTAL_CAPTURED -ge $MAX_BYTES ]; then
        echo "[dynamicState] Reached max byte limit ($MAX_MB MB). Stopping capture."
        break
    fi

    ADDR_RANGE=$(echo "$line" | awk '{print $1}')
    PERMS=$(echo "$line" | awk '{print $2}')
    PATHNAME=$(echo "$line" | awk '{$1=$2=$3=$4=$5=""; print $0}' | sed 's/^[ \t]*//')

    # Only read readable regions ('r') and skip kernel special mappings if needed
    READABLE=$(echo "$PERMS" | cut -c 1)
    if [ "$READABLE" != "r" ]; then
        continue
    fi
    case "$PATHNAME" in
        "[vvar]"|"[vdso]"|"[vsyscall]") continue ;;
    esac

    START_HEX=$(echo "$ADDR_RANGE" | cut -d'-' -f1)
    END_HEX=$(echo "$ADDR_RANGE" | cut -d'-' -f2)

    # Convert hex to decimal using printf/awk
    START_DEC=$(printf "%d" "0x$START_HEX" 2>/dev/null || awk -v h="0x$START_HEX" 'BEGIN { printf "%.0f", h }')
    END_DEC=$(printf "%d" "0x$END_HEX" 2>/dev/null || awk -v h="0x$END_HEX" 'BEGIN { printf "%.0f", h }')
    REGION_SIZE=$((END_DEC - START_DEC))

    if [ "$REGION_SIZE" -le 0 ]; then
        continue
    fi

    # Enforce limit per region
    BYTES_TO_READ=$REGION_SIZE
    REMAINING=$((MAX_BYTES - TOTAL_CAPTURED))
    if [ "$BYTES_TO_READ" -gt "$REMAINING" ]; then
        BYTES_TO_READ=$REMAINING
    fi

    REGION_COUNT=$((REGION_COUNT + 1))
    REGION_FILE=$(printf "region_%06d.bin" "$REGION_COUNT")
    REGION_PATH="$OUT_DIR/memory/$REGION_FILE"

    # Dump memory chunk using dd if available
    # bs=4096 or bs=1 with skip
    if dd if="/proc/$PID/mem" of="$REGION_PATH" bs=4096 skip=$((START_DEC / 4096)) count=$(( (BYTES_TO_READ + 4095) / 4096 )) 2>/dev/null; then
        ACTUAL_SIZE=$(wc -c < "$REGION_PATH" 2>/dev/null || ls -l "$REGION_PATH" | awk '{print $5}')
        TOTAL_CAPTURED=$((TOTAL_CAPTURED + ACTUAL_SIZE))
    else
        # Remove empty or failed file
        rm -f "$REGION_PATH"
        continue
    fi
done < "$OUT_DIR/maps.txt"

# Write metadata.json
ARCH=$(uname -m 2>/dev/null || echo "unknown")
cat <<EOF > "$OUT_DIR/metadata.json"
{
  "snapshot_id": "RAW_$(date +%s 2>/dev/null || echo $$)",
  "pid": $PID,
  "binary": "$EXE_LINK",
  "created_at": "$START_TIME",
  "architecture": "$ARCH",
  "capture_mode": "LOW_IMPACT_ZERO_PYTHON",
  "regions_captured": $REGION_COUNT,
  "bytes_captured": $TOTAL_CAPTURED,
  "status": "COMPLETE"
}
EOF

echo "[dynamicState] Capture complete: $REGION_COUNT regions ($TOTAL_CAPTURED bytes) saved to $OUT_DIR"
echo "[dynamicState] Transfer '$OUT_DIR' to Host PC and run:"
echo "  dynamic-state analyze-memory --snapshot $OUT_DIR --debug-image <path_to_debug_image>"
