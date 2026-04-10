#!/bin/bash
set -e

# Use $SNAP_USER_COMMON for configuration and data directory instead of ~/.microclaw
export MICROCLAW_CONFIG="$SNAP_USER_COMMON/microclaw.config.yaml"

# If config does not exist, initialize it to set the data_dir to $SNAP_USER_COMMON
if [ ! -f "$MICROCLAW_CONFIG" ]; then
    echo "data_dir: \"$SNAP_USER_COMMON\"" > "$MICROCLAW_CONFIG"
fi

exec "$SNAP/bin/microclaw" "$@"
