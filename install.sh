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
    echo "🔍 Detecting platform..."
    PLATFORM=$(detect_platform)
    echo "   Platform: $PLATFORM"
    
    echo "📦 Getting latest version..."
    VERSION=$(get_latest_version)
    if [ -z "$VERSION" ]; then
        echo "❌ Could not determine latest version"
        exit 1
    fi
    echo "   Version: $VERSION"
    
    # Set download URL
    BINARY_NAME="ntscan-${PLATFORM}"
    if [ "$PLATFORM" = "windows-amd64" ]; then
        BINARY_NAME="${BINARY_NAME}.exe"
    fi
    
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY_NAME"
    
    echo "⬇️  Downloading from $DOWNLOAD_URL..."
    TMP_DIR=$(mktemp -d)
    curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/ntscan" || {
        echo "❌ Download failed"
        rm -rf "$TMP_DIR"
        exit 1
    }
    
    chmod +x "$TMP_DIR/ntscan"
    
    echo "📁 Installing to $INSTALL_DIR..."
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_DIR/ntscan" "$INSTALL_DIR/ntscan"
    else
        echo "   sudo required for $INSTALL_DIR"
        sudo mv "$TMP_DIR/ntscan" "$INSTALL_DIR/ntscan"
    fi
    
    rm -rf "$TMP_DIR"
    
    echo "✅ ntscan installed successfully!"
    echo ""
    echo "Run 'ntscan --help' to get started"
    echo "Run 'ntscan --tui' for interactive mode"
}

main
