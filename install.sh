#!/bin/bash
# ntscan installer script
# Usage: curl -fsSL https://raw.githubusercontent.com/Aaron-Savron/ntscan/main/install.sh | bash

set -e

REPO="Aaron-Savron/ntscan"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$OS" in
        linux)
            PLATFORM="linux"
            ;;
        darwin)
            PLATFORM="darwin"
            ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            echo "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    echo "${PLATFORM}-${ARCH}"
}

# Get latest release version
get_latest_version() {
    curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

main() {
    echo "Detecting platform..."
    PLATFORM=$(detect_platform)
    echo "  Platform: $PLATFORM"
    
    echo "Getting latest version..."
    VERSION=$(get_latest_version)
    if [ -z "$VERSION" ]; then
        echo "  No release found, will build from source..."
        install_from_source
        return
    fi
    echo "  Version: $VERSION"
    
    # Set download URL
    BINARY_NAME="ntscan-${PLATFORM}"
    if [ "$PLATFORM" = "windows-amd64" ]; then
        BINARY_NAME="${BINARY_NAME}.exe"
    fi
    
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY_NAME"
    
    echo "Downloading from $DOWNLOAD_URL..."
    TMP_DIR=$(mktemp -d)
    if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/ntscan" 2>/dev/null; then
        echo "  Download failed, will build from source..."
        rm -rf "$TMP_DIR"
        install_from_source
        return
    fi
    
    chmod +x "$TMP_DIR/ntscan"
    
    echo "Installing to $INSTALL_DIR..."
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_DIR/ntscan" "$INSTALL_DIR/ntscan"
    else
        echo "  sudo required for $INSTALL_DIR"
        sudo mv "$TMP_DIR/ntscan" "$INSTALL_DIR/ntscan"
    fi
    
    rm -rf "$TMP_DIR"
    
    echo "ntscan installed successfully!"
    echo ""
    echo "Run 'ntscan --help' to get started"
    echo "Run 'ntscan --tui' for interactive mode"
}

install_from_source() {
    echo ""
    echo "Building ntscan from source..."
    echo "  This requires Rust to be installed"
    
    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        echo ""
        echo "ERROR: Rust is not installed."
        echo ""
        echo "Install Rust first:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo ""
        echo "Or download a pre-built binary from:"
        echo "  https://github.com/Aaron-Savron/ntscan/releases"
        exit 1
    fi
    
    # Clone and build
    TMP_DIR=$(mktemp -d)
    echo "  Cloning repository..."
    git clone --depth 1 "https://github.com/$REPO.git" "$TMP_DIR/ntscan" 2>/dev/null
    
    echo "  Building (this may take a few minutes)..."
    (cd "$TMP_DIR/ntscan" && cargo build --release 2>&1 | tail -5)
    
    echo "  Installing..."
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_DIR/ntscan/target/release/ntscan" "$INSTALL_DIR/ntscan"
    else
        echo "    sudo required for $INSTALL_DIR"
        sudo mv "$TMP_DIR/ntscan/target/release/ntscan" "$INSTALL_DIR/ntscan"
    fi
    
    rm -rf "$TMP_DIR"
    
    echo ""
    echo "ntscan built and installed successfully!"
    echo ""
    echo "Run 'ntscan --help' to get started"
}

main
