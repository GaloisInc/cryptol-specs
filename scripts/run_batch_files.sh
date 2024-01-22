#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $DIR/.. > /dev/null

NUM_FILES=0
NUM_BATCH_FILES=0
BATCH_FILES=()
NUM_FAILS=0
FAILS=()

run_batch() {
  for FILE in "$1"/*; do
    if [ -d "$FILE" ]; then
      run_batch "$FILE"
    elif [[ -f "$FILE" && "$FILE" == *"$STAGE".bat ]]; then
      NUM_FILES=$(($NUM_FILES+1))
      echo "Running $FILE..."
      result=$(cryptol -e --batch $FILE)
      echo "$result"
      if grep -q "Counterexample" <<< "$result"; then
        NUM_FAILS=$(($NUM_FAILS+1))
        FAILS+=("$FILE")
      else
        NUM_BATCH_FILES=$(($NUM_BATCH_FILES+1))
        BATCH_FILES+=("$FILE")
      fi
    fi
  done
}

run_batch "Common"
run_batch "Primitive"

echo ""
echo "=== Done running $NUM_FILES Cryptol batch file(s) ==="

if (( $NUM_BATCH_FILES != 0 )); then
  echo "$NUM_BATCH_FILES Cryptol batch files ran:"
  for FILE in "${BATCH_FILES[@]}"; do
    echo "  $FILE"
  done
fi

if (( $NUM_FAILS != 0 )); then
  echo "$NUM_FAILS batch file(s) failed:"
  for prop in "${FAILS[@]}"; do
    echo "  $prop"
  done
  exit 1
else
  echo "All batch files succeeded."
  exit 0
fi

popd > /dev/null
