#!/bin/bash

rm -rf dist
wasm-pack build --out-dir dist --release --target web
cp README.npm.md dist/README.md