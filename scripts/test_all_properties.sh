#!/bin/bash

DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd)"
pushd $DIR/.. > /dev/null

NUM_FAILS=0
FAILS=()
SCRIPT=$(mktemp)

test_properties() {
  for FILE in "$1"/*; do
    if [ -d "$FILE" ]; then
      echo "$FILE is a directory"
      test_properties "$FILE"
    elif [[ -f "$FILE" && ("$FILE" == *.cry || "$FILE" == *.md || "$FILE" == *.tex) ]]; then
      # Find all the properties in the file
      props=$(grep -oE "^property [a-zA-Z0-9_']+" $FILE | awk '{print $2}')
      if [ -z "$props" ]; then
        echo "$FILE has no properties to check."
      else
        echo "Checking $FILE..."
        echo ":l $FILE" > $SCRIPT
        echo ":s tests=3" >> $SCRIPT
        for prop in $props; do
          echo ":check $prop" >> $SCRIPT
        done
        result=$(cryptol -e --batch $SCRIPT)
        if grep -q "False" <<< "$result"; then
          echo "$result"
          echo "  At least one property failed."
          NUM_FAILS=$(($NUM_FAILS+1))
          FAILS+=("$FILE")
        else
          echo "  All properties passed."
        fi
      fi
    fi
  done
}

test_properties "Common"
test_properties "Primitive"

rm $SCRIPT

echo ""
echo "=== Done checking Cryptol properties ==="

if (( $NUM_FAILS != 0)); then
  echo "$NUM_FAILS cryptol-spec property(ies) failed:"
  for FILE in "${FAILS[@]}"; do
    echo " $FILE"
  done
  exit 1
else
  echo "All cryptol properties pass."
  exit 0
fi

popd > /dev/null
