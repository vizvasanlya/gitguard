#!/bin/bash
# GitGuard Demo Script
# Run this to generate a demo GIF using terminalizer or agg

set -e

echo "=== GitGuard Demo Generator ==="
echo ""
echo "This script helps you create a demo GIF for GitGuard."
echo ""
echo "Option 1: Using terminalizer (recommended)"
echo "  1. Install terminalizer: npm install -g terminalizer"
echo "  2. Run: terminalizer record demo"
echo "  3. Run: terminalizer render demo"
echo "  4. Upload the GIF to your README"
echo ""
echo "Option 2: Using agg (Rust-based, faster)"
echo "  1. Install agg: cargo install --git https://github.com/asciinema/agg"
echo "  2. Run: asciinema rec demo.cast"
echo "  3. Run: agg demo.cast demo.gif"
echo ""
echo "Option 3: Using VHS (Go-based, beautiful)"
echo "  1. Install VHS: go install github.com/charmbracelet/vhs@latest"
echo "  2. Create demo.tape (see below)"
echo "  3. Run: vhs demo.tape"
echo ""
echo "=== VHS demo.tape template ==="
echo ""
cat << 'EOF'
# GitGuard Demo Tape

output demo.gif

set font-size 24
set theme Monokai Extended

type "pip install gitguard"

sleep 1s

type "gitguard scan ."

sleep 3s

type "gitguard fix ."

sleep 2s

type "gitguard explain SEC001"

sleep 2s

type "gitguard history ."

sleep 2s

type "gitguard sarif . --output results.sarif"

sleep 1s

type "cat results.sarif | head -20"
EOF

echo ""
echo "=== Quick Demo Commands ==="
echo ""
echo "To record a quick demo, run these commands in your terminal:"
echo ""
echo "  # Scan a project"
echo "  gitguard scan ."
echo ""
echo "  # Auto-fix issues"
echo "  gitguard fix ."
echo ""
echo "  # Explain a finding"
echo "  gitguard explain SEC001"
echo ""
echo "  # Scan git history"
echo "  gitguard history ."
echo ""
echo "  # Generate SARIF output"
echo "  gitguard sarif . --output results.sarif"
echo ""
echo "=== Recording Tips ==="
echo ""
echo "1. Use a clean terminal with good contrast"
echo "2. Set terminal width to 80-100 columns"
echo "3. Use a dark theme for better visibility"
echo "4. Record at 1920x1080 or higher"
echo "5. Keep the demo under 30 seconds"
echo "6. Show the most impressive features first"
