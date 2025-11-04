#!/bin/bash

# Build the CLI application
cargo build --release

echo "✓ Build complete!"
echo "Binary location: target/release/qpkv"
echo ""
echo "To install globally, run:"
echo "  cargo install --path ."