#!/bin/bash
# Populate deps/ with the third-party runtime binaries CyberConsole injects.
# These are NOT committed to git (FridaGadget is ~57 MB). They are bundled into the
# release .dmg at package time.
#
# Primary path: copy from a known-good local Cyberpunk 2077 install (if present).
# Otherwise, download from upstream (see URLs below) and place the files in deps/.
set -e
cd "$(dirname "$0")/.."
mkdir -p deps
GAME="${CP2077_DIR:-$HOME/Library/Application Support/Steam/steamapps/common/Cyberpunk 2077}/red4ext"

copy_if() { if [ -f "$1" ]; then cp "$1" "deps/$(basename "$1")" && echo "  got $(basename "$1")"; fi; }   # a missing source must not trip set -e

echo "Fetching runtime deps into deps/ ..."
if [ -d "$GAME" ]; then
  echo "Found local install - copying from: $GAME"
  copy_if "$GAME/RED4ext.dylib"
  copy_if "$GAME/FridaGadget.dylib"
  copy_if "$GAME/plugins/TweakXL/TweakXL.dylib"       # TweakXL creator engine (RED4ext plugin)
  copy_if "$GAME/plugins/ArchiveXL/ArchiveXL.dylib"   # ArchiveXL content engine (RED4ext plugin) - REQUIRED for mods
  copy_if "$GAME/config.ini"                          # RED4ext config ([plugins] enabled=true) - without it no plugins load
  copy_if "$GAME/cyberpunk2077_addresses.json"        # RED4ext AddressLib
fi

# redscript compiler (jac3km4/redscript macOS arm64 release) - bundled so the app can compile .reds
# script mods into r6/cache/final.redscripts before every launch. Canonical copy lives in the
# cybermodman repo (extracted redscript-v0.5.31-macos.zip); fall back to the game's deployed copy.
SCC_SRC="$HOME/cybermodman/redscript/engine/tools"
[ -f "$SCC_SRC/scc" ] || SCC_SRC="${CP2077_DIR:-$HOME/Library/Application Support/Steam/steamapps/common/Cyberpunk 2077}/engine/tools"
copy_if "$SCC_SRC/scc"
copy_if "$SCC_SRC/libscc_lib.dylib"

MISSING=0
for f in RED4ext.dylib FridaGadget.dylib TweakXL.dylib ArchiveXL.dylib config.ini scc libscc_lib.dylib; do
  [ -f "deps/$f" ] || { echo "  MISSING: deps/$f"; MISSING=1; }
done

if [ "$MISSING" = "1" ]; then
  cat <<'EOF'

Some deps are missing. Obtain them from upstream and drop into deps/:
  - FridaGadget.dylib : frida-gadget (macOS arm64) from https://github.com/frida/frida/releases
                        (download frida-gadget-<ver>-macos-arm64.dylib.gz, gunzip, rename to FridaGadget.dylib)
  - RED4ext.dylib     : RED4ext macOS port release
Then re-run this script (or just place the files and continue).
EOF
  exit 1
fi
echo "deps ready."
