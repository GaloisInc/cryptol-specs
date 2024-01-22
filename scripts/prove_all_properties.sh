#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd)"
pushd $DIR/.. > /dev/null

SCRIPT=$(mktemp)
NUM_MORE_TIME=0
MORE_TIME=()
RUN_AGAIN=()
NUM_FAILS=0
FAILS=()
NUM_NOT_MONOMORPHIC=0
NOT_MONOMORPHIC=()
NUM_NOT_TESTABLE=0
NOT_TESTABLE=()
MANUAL_PROVE_FILENAME="manual_proves.txt"
FAST_PROVES="fast_proves.txt"

prove_properties() {
  for FILE in "$1"/*; do
    if [ -d "$FILE" ]; then
      echo "$FILE is a directory."
      prove_properties "$FILE"
    elif [[ -f "$FILE" && ("$FILE" == *.cry || "$FILE" == *.md || "$FILE" == *.tex) ]]; then
      # Find all of the properties in the file
      props=$(grep -oE "^property [a-zA-Z0-9_']+" $FILE | awk '{print $2}')
      if [ -z "$props" ]; then
        echo "$FILE has no properties to prove."
      else
        for prop in $props; do
          echo "Proving $prop in $FILE..."
          echo ":l $FILE" > $SCRIPT
          echo ":prove $prop" >> $SCRIPT
          ( cryptol -e --batch $SCRIPT ) & pid=$!
          ( sleep 15 && kill -HUP $pid ) 2>/dev/null & watcher=$!
          if wait $pid 2>/dev/null; then
            echo "  $prop finished!"
            pkill -HUP -P $watcher
            wait $watcher
            RUN_AGAIN+=("$FILE $prop")
          else
            echo "  $prop did not prove in time."
            NUM_MORE_TIME=$(($NUM_MORE_TIME+1))
            MORE_TIME+=("$FILE $prop")
          fi
        done
      fi
    fi
  done
}

rerun_proofs() {
  echo "--------------------------------"
  for property in "${RUN_AGAIN[@]}"; do
    echo "$property..."
    file="$(echo $property | awk '{print $1;}')"
    prop="$(echo $property | awk '{print $2;}')"
    echo ":l $file" > $SCRIPT
    echo ":prove $prop" >> $SCRIPT
    result=$(cryptol -e --batch $SCRIPT)
    echo "$result"
    if grep -q "Not a monomorphic type" <<< "$result"; then
      echo "  $property is not monomorphic"
      NUM_NOT_MONOMORPHIC=$(($NUM_NOT_MONOMORPHIC+1))
      NOT_MONOMORPHIC+=("$property")
    elif grep -q "Not a valid predicate type" <<< "$result"; then
      echo "  $property is not of a testable type."
      NUM_NOT_TESTABLE=$(($NUM_NOT_TESTABLE+1))
      NOT_TESTABLE+=("$property")
    elif grep -q "not in scope" <<< "$result"; then
      echo "  $property failed."
      NUM_FAILS=$(($NUM_FAILS+1))
      FAILS+=("$property")
    elif grep -q "Counterexample" <<< "$result"; then
      echo "  $property failed."
      NUM_FAILS=$(($NUM_FAILS+1))
      FAILS+=("$property")
    else
      echo "  $property passed!"
      echo "$property" >> $FAST_PROVES
    fi
  done
}

prove_properties "Common"
prove_properties "Primitive"
rerun_proofs

rm $SCRIPT

echo ""
echo "=== Done proving Cryptol properties ==="

if (( $NUM_MORE_TIME != 0 )); then
  echo "$NUM_MORE_TIME properties need more time to prove. You can run them manually."
  for prop in "${MORE_TIME[@]}"; do
    echo "  $prop"
    echo "$prop" >> $MANUAL_PROVE_FILENAME
  done
fi

if (( $NUM_NOT_MONOMORPHIC != 0 )); then
  echo "$NUM_NOT_MONOMORPHIC properties are not monomorphic types and cannot be proven."
  for prop in "${NOT_MONOMORPHIC[@]}"; do
    echo "  $prop"
  done
fi

if (( $NUM_NOT_TESTABLE != 0 )); then
  echo "$NUM_NOT_TESTABLE properties are not valid predicate types and cannot be proven."
  for prop in "${NOT_TESTABLE[@]}"; do
    echo "  $prop"
  done
fi

if (( $NUM_FAILS != 0 )); then
  echo "$NUM_FAILS property(ies) failed to prove: "
  for prop in "${FAILS[@]}"; do
    echo "  $prop"
  done
  exit 1
else
  echo "All cryptol properties prove."
  exit 0
fi

popd > /dev/null
