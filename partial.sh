#!/bin/bash

# Function to display usage information
usage() {
  echo "Usage: $0 -s SOURCE_DIR -d DESTINATION_DIR -f START_NUM -t END_NUM"
  echo ""
  echo "Arguments:"
  echo "  -s SOURCE_DIR       Source directory containing the JSON files"
  echo "  -d DESTINATION_DIR  Destination directory where files will be copied"
  echo "  -f START_NUM        Starting number in the range (inclusive)"
  echo "  -t END_NUM          Ending number in the range (inclusive)"
  echo ""
  echo "Example: $0 -s /path/to/source -d /path/to/destination -f 1000 -t 2000"
  exit 1
}

# Parse command line arguments
while getopts "s:d:f:t:h" opt; do
  case ${opt} in
    s )
      SOURCE_DIR=$OPTARG
      ;;
    d )
      DEST_DIR=$OPTARG
      ;;
    f )
      START_NUM=$OPTARG
      ;;
    t )
      END_NUM=$OPTARG
      ;;
    h )
      usage
      ;;
    \? )
      usage
      ;;
  esac
done

# Check if all required parameters are provided
if [ -z "$SOURCE_DIR" ] || [ -z "$DEST_DIR" ] || [ -z "$START_NUM" ] || [ -z "$END_NUM" ]; then
  echo "Error: Missing required parameters."
  usage
fi

# Validate source directory
if [ ! -d "$SOURCE_DIR" ]; then
  echo "Error: Source directory '$SOURCE_DIR' does not exist."
  exit 1
fi

# Create destination directory if it doesn't exist
if [ ! -d "$DEST_DIR" ]; then
  mkdir -p "$DEST_DIR"
  echo "Created destination directory: $DEST_DIR"
fi

# Validate the range
if ! [[ "$START_NUM" =~ ^[0-9]+$ ]] || ! [[ "$END_NUM" =~ ^[0-9]+$ ]]; then
  echo "Error: START_NUM and END_NUM must be integers."
  exit 1
fi

if [ "$START_NUM" -gt "$END_NUM" ]; then
  echo "Error: START_NUM cannot be greater than END_NUM."
  exit 1
fi

# Initialize counters
total_files=0
copied_files=0
missing_files=0

# clear dest
rm -f $DEST_DIR/*

# Process the range
for ((i=START_NUM; i<=END_NUM; i++)); do
  filename="$i.json"
  source_file="$SOURCE_DIR/$filename"
  
  if [ -f "$source_file" ]; then
    cp "$source_file" "$DEST_DIR/"
    echo "Copied: $filename"
    ((copied_files++))
  else
    echo "Missing: $filename"
    ((missing_files++))
  fi
  
  ((total_files++))
done

# Print summary
echo ""
echo "Copy operation completed!"
echo "-------------------------"
echo "Total files in range: $total_files"
echo "Files copied: $copied_files"
echo "Files missing: $missing_files"
echo "Source: $SOURCE_DIR"
echo "Destination: $DEST_DIR"
echo "Range: $START_NUM to $END_NUM"

exit 0
