#!/bin/bash

# Directory to start the search from (current directory by default)
SEARCH_DIR="${1:-/}"

# Temporary file to store results
TEMP_FILE=$(mktemp)

# Function to check and decode Base64 strings
decode_base64() {
  local encoded="$1"
  # Attempt to decode and handle errors
  decoded=$(echo "$encoded" | base64 --decode 2>/dev/null)
  if [ $? -eq 0 ]; then
    echo "Decoded Base64 found:"
    echo "$decoded"
    echo "==============================="
  fi
}

# Function to search for potential Base64-encoded data
search_base64() {
  # Use grep to search for Base64-like patterns
  echo "Searching for Base64-like patterns in $SEARCH_DIR..."
  
  # Pattern to find Base64-like strings (e.g., long strings of A-Z, a-z, 0-9, +, /, and possibly padding '=')
  grep -rhoE '[A-Za-z0-9+/=]{20,}' "$SEARCH_DIR" | while read -r base64_string; do
    # Decode found Base64 string
    decode_base64 "$base64_string"
  done
}

# Function to look for Base64-encoded items in files that might have been obfuscated
find_base64_in_files() {
  echo "Searching for potential obfuscated Base64 items in files..."
  for file in $(find "$SEARCH_DIR" -type f); do
    # Search for Base64-like patterns in each file
    grep -oE '[A-Za-z0-9+/=]{20,}' "$file" 2>/dev/null | while read -r base64_string; do
      echo "Potential Base64 found in file: $file"
      decode_base64 "$base64_string"
    done
  done
}

# Main execution
search_base64
find_base64_in_files

# Clean up
rm -f "$TEMP_FILE"

echo "Base64 search and decoding completed."
