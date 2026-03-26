#!/bin/bash
#
# ARM GCC Toolchain Download Script
# Downloads ARM GNU Toolchain 15.2.rel1 for the current platform
#
# Supported platforms:
#   - Linux x86_64
#   - Linux aarch64
#   - macOS (Apple Silicon / arm64)
#   - Windows x86_64
#

set -e

TOOLCHAIN_VERSION="15.2.rel1"
TOOLCHAIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/toolchain"

# Detect platform
detect_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "${os}" in
        linux)
            case "${arch}" in
                x86_64)
                    echo "x86_64-linux-gnu"
                    ;;
                aarch64|arm64)
                    echo "aarch64-linux-gnu"
                    ;;
                *)
                    echo "Error: Unsupported Linux architecture: ${arch}" >&2
                    exit 1
                    ;;
            esac
            ;;
        darwin)
            case "${arch}" in
                arm64)
                    echo "darwin-arm64"
                    ;;
                *)
                    echo "Error: Unsupported macOS architecture: ${arch}" >&2
                    exit 1
                    ;;
            esac
            ;;
        mingw*|msys*|cygwin*)
            case "${arch}" in
                x86_64)
                    echo "mingw-w64-x86_64"
                    ;;
                *)
                    echo "Error: Unsupported Windows architecture: ${arch}" >&2
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "Error: Unsupported operating system: ${os}" >&2
            exit 1
            ;;
    esac
}

# Download the toolchain
download_toolchain() {
    local platform="$1"
    local filename url
    local temp_dir="$(mktemp -d)"

    case "${platform}" in
        x86_64-linux-gnu)
            filename="arm-gnu-toolchain-${TOOLCHAIN_VERSION}-x86_64-arm-none-eabi.tar.xz"
            url="https://developer.arm.com/-/media/Files/downloads/gnu/${TOOLCHAIN_VERSION}/binrel/${filename}"
            ;;
        aarch64-linux-gnu)
            filename="arm-gnu-toolchain-${TOOLCHAIN_VERSION}-aarch64-arm-none-eabi.tar.xz"
            url="https://developer.arm.com/-/media/Files/downloads/gnu/${TOOLCHAIN_VERSION}/binrel/${filename}"
            ;;
        darwin-arm64)
            filename="arm-gnu-toolchain-${TOOLCHAIN_VERSION}-darwin-arm64-arm-none-eabi.tar.xz"
            url="https://developer.arm.com/-/media/Files/downloads/gnu/${TOOLCHAIN_VERSION}/binrel/${filename}"
            ;;
        mingw-w64-x86_64)
            filename="arm-gnu-toolchain-${TOOLCHAIN_VERSION}-mingw-w64-x86_64-arm-none-eabi.zip"
            url="https://developer.arm.com/-/media/Files/downloads/gnu/${TOOLCHAIN_VERSION}/binrel/${filename}"
            ;;
        *)
            echo "Error: Unknown platform: ${platform}" >&2
            rm -rf "${temp_dir}"
            exit 1
            ;;
    esac

    local tarball="${temp_dir}/${filename}"

    echo "Downloading toolchain for ${platform}..."
    echo "URL: ${url}"

    # Try wget first, fall back to curl
    if command -v wget &> /dev/null; then
        wget -O "${tarball}" "${url}" || {
            echo "Download failed with wget, trying curl..."
            curl -L -o "${tarball}" "${url}" || {
                echo "Error: Failed to download toolchain" >&2
                echo "Please download manually from: https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads" >&2
                rm -rf "${temp_dir}"
                exit 1
            }
        }
    elif command -v curl &> /dev/null; then
        curl -L -o "${tarball}" "${url}" || {
            echo "Error: Failed to download toolchain" >&2
            echo "Please download manually from: https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads" >&2
            rm -rf "${temp_dir}"
            exit 1
        }
    else
        echo "Error: Neither wget nor curl found" >&2
        rm -rf "${temp_dir}"
        exit 1
    fi

    # Extract the toolchain to a temporary location first
    echo "Extracting toolchain..."
    mkdir -p "${temp_dir}/extracted"
    
    if [[ "${filename}" == *.zip ]]; then
        # Windows uses zip format
        if command -v unzip &> /dev/null; then
            unzip -q "${tarball}" -d "${temp_dir}/extracted"
        elif command -v 7z &> /dev/null; then
            7z x -o"${temp_dir}/extracted" -y "${tarball}" > /dev/null
        else
            echo "Error: Neither unzip nor 7z found for extracting zip file" >&2
            rm -rf "${temp_dir}"
            exit 1
        fi
    else
        # Linux/macOS use tar.xz format
        tar -xf "${tarball}" -C "${temp_dir}/extracted"
    fi

    # Normalize the path: rename extracted folder to just 'arm-gnu-toolchain-15.2.rel1'
    # This ensures cmake/arm-gcc.cmake can always find it at a predictable location
    local extracted_dir="${temp_dir}/extracted/arm-gnu-toolchain-${TOOLCHAIN_VERSION}-*"
    local extracted_path
    extracted_path="$(ls -d ${extracted_dir} 2>/dev/null | head -1)"
    
    if [ -n "${extracted_path}" ] && [ -d "${extracted_path}" ]; then
        rm -rf "${TOOLCHAIN_DIR}"
        mkdir -p "${TOOLCHAIN_DIR}"
        mv "${extracted_path}" "${TOOLCHAIN_DIR}/arm-gnu-toolchain-${TOOLCHAIN_VERSION}"
    else
        echo "Error: Unexpected extraction structure" >&2
        rm -rf "${temp_dir}"
        exit 1
    fi

    # Clean up
    rm -rf "${temp_dir}"

    echo "Toolchain installed successfully to: ${TOOLCHAIN_DIR}/arm-gnu-toolchain-${TOOLCHAIN_VERSION}"
}

# Print toolchain info
print_info() {
    local platform="$1"
    echo ""
    echo "=========================================="
    echo "ARM GNU Toolchain ${TOOLCHAIN_VERSION}"
    echo "=========================================="
    echo "Platform: ${platform}"
    echo "Location: ${TOOLCHAIN_DIR}/arm-gnu-toolchain-${TOOLCHAIN_VERSION}"
    echo ""
    echo "To use this toolchain, add to your PATH:"
    echo "  export PATH=\"${TOOLCHAIN_DIR}/arm-gnu-toolchain-${TOOLCHAIN_VERSION}/bin:\$PATH\""
    echo ""
    echo "Or use the CMake toolchain file: cmake/arm-gcc.cmake"
    echo "=========================================="
}

# Main
main() {
    echo "ARM GCC Toolchain Download Script"
    echo "=================================="
    echo ""

    # Check if already installed
    if [ -d "${TOOLCHAIN_DIR}/arm-gnu-toolchain-${TOOLCHAIN_VERSION}" ]; then
        echo "Toolchain already exists at: ${TOOLCHAIN_DIR}/arm-gnu-toolchain-${TOOLCHAIN_VERSION}"
        read -p "Do you want to reinstall? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 0
        fi
    fi

    # Detect platform
    local platform
    platform="$(detect_platform)"
    echo "Detected platform: ${platform}"

    # Download and install
    download_toolchain "${platform}"

    # Print info
    print_info "${platform}"
}

main "$@"
