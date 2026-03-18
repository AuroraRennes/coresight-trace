#!/bin/sh
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR/coresight-decoder" || exit 1
git apply "$SCRIPT_DIR/patch_decoder.diff"