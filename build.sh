#!/usr/bin/env bash
# Builds the desktop app and both CLI tools into build/bin, then stages the
# WinDivert driver files beside them. The .sys has to sit next to the DLL on
# disk: the DLL installs it as a kernel service and looks for it there.
set -euo pipefail

cd "$(dirname "$0")"
export PATH="$PATH:$(go env GOPATH)/bin"

echo "==> tests"
go test ./internal/... -count=1

echo "==> desktop app"
wails build

echo "==> cli tools"
go build -o build/bin/sniproxy.exe ./cmd/sniproxy
go build -o build/bin/spooftest.exe ./cmd/spooftest

echo "==> WinDivert"
DRIVER_SRC="${WINDIVERT_DIR:-}"
if [[ -z "$DRIVER_SRC" ]]; then
  # pydivert ships a matching WinDivert 2.x pair; use it if it is installed.
  DRIVER_SRC=$(python -c "import os,pydivert;print(os.path.join(os.path.dirname(pydivert.__file__),'windivert_dll'))" 2>/dev/null || true)
fi
if [[ -n "$DRIVER_SRC" && -f "$DRIVER_SRC/WinDivert64.dll" ]]; then
  cp "$DRIVER_SRC/WinDivert64.dll" build/bin/WinDivert.dll
  cp "$DRIVER_SRC/WinDivert64.sys" build/bin/WinDivert64.sys
  echo "    staged from $DRIVER_SRC"
else
  echo "    SKIPPED: set WINDIVERT_DIR to a folder holding WinDivert64.dll and WinDivert64.sys"
fi

echo
echo "Done. build/bin:"
ls -1 build/bin
