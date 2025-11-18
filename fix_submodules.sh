#!/bin/bash

################################################################################
# Git Submodule Repair Script v2.0
# Fixes broken submodule states with comprehensive error handling
################################################################################

set -Eeo pipefail

# Colors for output
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Symbols
readonly CHECK="✓"
readonly CROSS="✗"
readonly WARN="⚠"
readonly ARROW="→"

# Script metadata
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"

# ──────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ──────────────────────────────────────────────────────────────────────────────
print_info() {
    echo -e "${GREEN}${CHECK}${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${WARN}${NC} $1"
}

print_error() {
    echo -e "${RED}${CROSS}${NC} $1" >&2
}

print_progress() {
    echo -e "${BLUE}${ARROW}${NC} $1"
}

fail() {
    local msg="${1:-Submodule fix failed}"
    echo ""
    print_error "$msg"
    echo ""
    echo "For more help, see: SUBMODULE_FIX.md"
    exit 1
}

# ──────────────────────────────────────────────────────────────────────────────
# Main Logic
# ──────────────────────────────────────────────────────────────────────────────
main() {
    echo "════════════════════════════════════════════════════════════════"
    echo "Git Submodule Repair Script v${SCRIPT_VERSION}"
    echo "════════════════════════════════════════════════════════════════"
    echo ""

    # Check if in a git repository
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        fail "Not in a git repository"
    fi
    print_info "Git repository detected"

    # Check if .gitmodules exists
    if [ ! -f ".gitmodules" ]; then
        print_warning "No .gitmodules file found"
        echo "This repository doesn't have any submodules configured."
        exit 0
    fi
    print_info "Found .gitmodules configuration"

    # Get list of submodules
    echo ""
    print_progress "Analyzing submodules..."
    local submodule_count=$(git config --file .gitmodules --get-regexp path 2>/dev/null | wc -l)

    if [ "$submodule_count" -eq 0 ]; then
        print_warning "No submodules configured in .gitmodules"
        exit 0
    fi

    print_info "Found ${submodule_count} submodule(s)"

    # List all submodules
    echo ""
    echo "Submodules in this repository:"
    git config --file .gitmodules --get-regexp path | while read -r key path; do
        echo "  • $path"
    done
    echo ""

    # Check for broken submodule directories
    print_progress "Checking for broken submodule directories..."
    local fixed_count=0
    local broken_count=0

    while IFS= read -r submodule_path; do
        if [ -d "$submodule_path" ]; then
            if [ ! -d "$submodule_path/.git" ]; then
                # Directory exists but is not a git repository
                if [ -z "$(ls -A "$submodule_path" 2>/dev/null)" ]; then
                    # Directory is empty - safe to remove
                    print_warning "Found empty directory: $submodule_path"
                    if rmdir "$submodule_path" 2>/dev/null; then
                        print_info "Removed empty directory: $submodule_path"
                        ((fixed_count++))
                    else
                        print_error "Failed to remove: $submodule_path"
                        ((broken_count++))
                    fi
                else
                    # Directory has content but no .git - problematic
                    print_error "Directory exists but is not a git repository: $submodule_path"
                    echo ""
                    echo "Directory contains:"
                    ls -la "$submodule_path" | head -10 | sed 's/^/  /'
                    echo ""
                    echo "Manual action required:"
                    echo "  Option 1 - Backup and remove:"
                    echo "    mv $submodule_path ${submodule_path}.backup"
                    echo ""
                    echo "  Option 2 - Remove completely:"
                    echo "    rm -rf $submodule_path"
                    echo ""
                    ((broken_count++))
                fi
            fi
        fi
    done < <(git config --file .gitmodules --get-regexp path 2>/dev/null | awk '{print $2}')

    # Report on fixes
    echo ""
    if [ $fixed_count -gt 0 ]; then
        print_info "Fixed ${fixed_count} broken submodule director(ies)"
    fi

    if [ $broken_count -gt 0 ]; then
        echo ""
        print_error "Found ${broken_count} broken submodule(s) requiring manual intervention"
        fail "Manual cleanup required before submodules can be initialized"
    fi

    if [ $fixed_count -eq 0 ] && [ $broken_count -eq 0 ]; then
        print_info "No broken submodule directories found"
    fi

    # Initialize submodules
    echo ""
    print_progress "Initializing git submodules..."
    if git submodule init 2>&1; then
        print_info "Submodules initialized"
    else
        fail "Failed to initialize submodules"
    fi

    # Update submodules
    echo ""
    print_progress "Updating git submodules recursively (this may take a while)..."
    echo ""

    if git submodule update --init --recursive 2>&1; then
        echo ""
        print_info "Submodules updated successfully"
    else
        echo ""
        print_error "Failed to update submodules"
        echo ""
        echo "Common solutions:"
        echo "  1. Check network connectivity"
        echo "  2. Verify access to submodule repositories"
        echo "  3. Verify .gitmodules configuration"
        echo "  4. Try manually: git submodule update --init --recursive --force"
        echo ""
        fail "Submodule update failed"
    fi

    # Show final status
    echo ""
    print_progress "Verifying submodule status..."
    echo ""
    git submodule status --recursive

    # Success summary
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    print_info "Submodule repair complete!"
    echo "════════════════════════════════════════════════════════════════"
    echo ""

    if [ $fixed_count -gt 0 ]; then
        echo "Summary:"
        echo "  • Fixed: ${fixed_count} broken director(ies)"
        echo "  • Initialized: ${submodule_count} submodule(s)"
        echo "  • Status: All submodules ready"
        echo ""
    fi

    echo "You can now run the build script:"
    echo "  ./build_all.sh"
    echo ""
}

# Entry point
main "$@"
