#!/usr/bin/env bash
# Bootstrap: install dependencies via vcpkg, configure and build docktrace.
# Usage: ./bootstrap.sh [--debug|--release] [--ebpf]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
BUILD_TYPE="Debug"
ENABLE_EBPF="OFF"

for arg in "$@"; do
    case "$arg" in
        --release) BUILD_TYPE="Release" ;;
        --ebpf)    ENABLE_EBPF="ON" ;;
    esac
done

# Locate vcpkg
VCPKG="${VCPKG_ROOT:-$HOME/vcpkg}/vcpkg"
if [ ! -x "$VCPKG" ]; then
    echo "vcpkg not found at $HOME/vcpkg. Set VCPKG_ROOT or install vcpkg:"
    echo "  git clone https://github.com/microsoft/vcpkg.git ~/vcpkg"
    echo "  ~/vcpkg/bootstrap-vcpkg.sh -disableMetrics"
    exit 1
fi

INSTALL_DIR="$ROOT/.vcpkg/installed"

echo "=== docktrace bootstrap v0.1.0 ==="
echo "Build:  $BUILD_TYPE"
echo "eBPF:   $ENABLE_EBPF"
echo "vcpkg:  $VCPKG"
echo ""

echo "[1/3] Installing C++ dependencies..."
"$VCPKG" install \
    --triplet x64-linux \
    --x-manifest-root "$ROOT" \
    --x-install-root "$INSTALL_DIR"

echo "[2/3] Configuring CMake..."
cmake -B "$ROOT/build" -S "$ROOT" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_PREFIX_PATH="$INSTALL_DIR/x64-linux" \
    -DDOCKTRACE_ENABLE_TESTS=ON \
    -DDOCKTRACE_ENABLE_EBPF="$ENABLE_EBPF"

echo "[3/3] Building..."
cmake --build "$ROOT/build" --parallel "$(nproc)"

echo ""
echo "=== Build complete ==="
echo ""
echo "Tests:   ./build/tests/docktrace_tests"
echo ""
echo "Commands:"
echo "  ./build/docktrace doctor"
echo "  ./build/docktrace report  --input examples/sample-report.json"
echo "  ./build/docktrace profile --input examples/sample-report.json --format yaml"
echo "  ./build/docktrace profile --input examples/sample-report.json --format oci-seccomp"
echo "  ./build/docktrace validate --input <profile.yaml>"
echo "  ./build/docktrace diff    --baseline baseline.json --current current.json"
echo ""
echo "Observe (proc, no root needed):"
echo "  ./build/docktrace observe --pid \$(pgrep -n bash) --duration 5s"
echo ""
echo "Observe with Docker:"
echo "  ./build/docktrace inspect  --container <name>"
echo "  sudo ./build/docktrace observe --container <name> --duration 60s -o report.json"
echo "  sudo ./build/docktrace baseline create --container <name> --duration 60s"
echo "  sudo ./build/docktrace baseline check  --container <name> --baseline baseline.json"
echo ""
if [ "$ENABLE_EBPF" = "OFF" ]; then
    echo "To enable real eBPF collection (needs clang + libbpf-dev):"
    echo "  sudo apt install clang libbpf-dev libelf-dev"
    echo "  ./bootstrap.sh --ebpf"
fi
