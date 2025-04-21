#!/bin/bash
# Remove the dist directory to ensure a clean build (optional)
rm -rf dist
# Build the package with wasm-pack
wasm-pack build --out-dir dist --release --target web
# Replace the default README with the npm-specific one
cp README.npm.md dist/README.md