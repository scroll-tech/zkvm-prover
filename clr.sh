#!/bin/bash

# Loop through all files matching the pattern
for file in flight?_?0M; do
  # Create the output file name
  output_file="${file}_clr"
  
  # Process with sed and redirect to output file
  echo "Processing $file -> $output_file"
  sed -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[mGK]//g' "$file" > "$output_file"
done

