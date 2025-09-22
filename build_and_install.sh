#!/bin/bash

set -eux pipefail

rm -f dist/*
./gradlew
TZIP=$(ls dist | head -1)
TZIP_PATH=$(pwd)/dist/$TZIP
unzip $TZIP_PATH -d ${GHIDRA_INSTALL_DIR}/Ghidra/Extensions/