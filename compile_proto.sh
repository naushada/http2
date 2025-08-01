#!/bin/bash

# Script to compile protobuf files with correct import paths for gNMI

# Set the base directory
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set protobuf import paths
PROTO_IMPORT_DIRS=(
    "${BASE_DIR}/third_party/gnmi/proto"
    "${BASE_DIR}/third_party/gnmi"
)

# Build the import path string
IMPORT_PATHS=""
for dir in "${PROTO_IMPORT_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        IMPORT_PATHS="$IMPORT_PATHS -I$dir"
    fi
done

echo "Compiling protobuf files with import paths:"
echo "$IMPORT_PATHS"

# Example: Compile a proto file
# protoc $IMPORT_PATHS --cpp_out=. your_file.proto

# For specific gNMI files, you can use:
# protoc $IMPORT_PATHS --cpp_out=. third_party/gnmi/proto/gnmi/gnmi.proto
# protoc $IMPORT_PATHS --cpp_out=. third_party/gnmi/proto/gnmi_ext/gnmi_ext.proto

echo "Usage: protoc $IMPORT_PATHS --cpp_out=. <your_proto_file>" 