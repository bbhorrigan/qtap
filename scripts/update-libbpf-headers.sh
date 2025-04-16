#!/usr/bin/env bash

# You don't need to run this script unless you're updating the libbpf headers.
# This script is used to fetch the libbpf headers from the libbpf GitHub repository.

# Version of libbpf to fetch headers from
LIBBPF_VERSION=1.4.7

# The headers we want
prefix=libbpf-"$LIBBPF_VERSION"
headers=(
    "$prefix"/src/bpf_helper_defs.h
    "$prefix"/src/bpf_helpers.h
    "$prefix"/src/bpf_tracing.h
    "$prefix"/src/bpf_core_read.h
    "$prefix"/src/bpf_endian.h
)

# Define output directory
OUTPUT_DIR="internal/tap/bpf/headers"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Create a temporary directory for extraction
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Fetch libbpf release and extract to temp directory
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar -xz -C "$TEMP_DIR"

# Copy headers to final destination, stripping directory structure
for header in "${headers[@]}"; do
    find "$TEMP_DIR" -name "$(basename "$header")" -exec cp {} "$OUTPUT_DIR/" \;
done
