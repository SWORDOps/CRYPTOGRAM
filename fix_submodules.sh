#!/bin/bash
# Fix broken submodule state
set -e

echo "Fixing submodule issues..."

# Remove empty lib_tsm directory if it exists
if [ -d "Telegram/lib_tsm" ]; then
    if [ -z "$(ls -A Telegram/lib_tsm 2>/dev/null)" ]; then
        echo "Removing empty Telegram/lib_tsm directory..."
        rmdir Telegram/lib_tsm
        echo "✓ Removed empty directory"
    else
        echo "⚠ Telegram/lib_tsm is not empty, checking if it's a valid git repository..."
        if [ ! -d "Telegram/lib_tsm/.git" ]; then
            echo "✗ Directory exists but is not a git repository"
            echo "Please manually remove or backup: Telegram/lib_tsm"
            exit 1
        fi
    fi
fi

# Initialize and update submodules
echo "Initializing git submodules..."
if git submodule init; then
    echo "✓ Submodules initialized"
else
    echo "✗ Failed to initialize submodules"
    exit 1
fi

echo "Updating git submodules..."
if git submodule update --recursive; then
    echo "✓ Submodules updated"
else
    echo "✗ Failed to update submodules"
    exit 1
fi

echo ""
echo "✓ Submodule fix complete!"
echo ""
git submodule status
