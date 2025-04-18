#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

sample_path_root="crates/integration/testdata"
mkdir -p .output

# Define the names array
steps=("10M" "20M" "30M" "40M" "60M")
batches=("1" "2" "3" "4" "5")

# Define the full_tasks array (as a bash array of arrays)
blocks_begin=("9254770" "8021038" "12999827" "8257000" "8257066")
declare -a full_tasks
blocks_tills[0]="9255177 9255613 9256023 9256236 9256682"
blocks_tills[1]="8021105 8021183 8021236 8021299 8021435"
blocks_tills[2]="12999862 12999897 12999924 12999949 13000000"
blocks_tills[3]="8257056 8257104 8257154 8257228 8257275"
blocks_tills[4]="8257072 8257076 8257081 8257086 8257100"

# Loop through the full_tasks array
for task_set_index in "${!batches[@]}"; do
  echo "Processing task set $task_set_index"
  
  batch=${batches[$task_set_index]} 
  sample_path="${sample_path_root}/flight${batch}"
  if [ ! -e "$sample_path" ]; then
    echo "Error: Path '$sample_path' does not exist."
    exit 1
  fi
  
  begin_block=${blocks_begin[$task_set_index]}
  # Convert the current task set string into an array
  IFS=' ' read -ra blocks_till <<< "${blocks_tills[$task_set_index]}"
  
  # Loop through the names array
  for i in {4..4}; do
    step=${steps[$i]}
    working_path=".output/${step}"
    mkdir -p $working_path

    # copy sample data to working path
    bash partial.sh -s $sample_path -d $working_path -f $begin_block -t ${blocks_till[$i]}
    
    working_path=$(realpath $working_path)    
    # Execute the command with the parameters
    TRACE_PATH=${working_path}/*.json make test-single-chunk 2>&1 | tee flight${batch}_${step}
  done
  
  echo "Completed task set $task_set_index"
done

