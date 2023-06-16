#! /bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $DIR/.. > /dev/null




NUM_FILES=0
NUM_FAILS=0
FAILS=()
SCRIPT=$(mktemp)

load_cry_files() {
    for FILE in "$1"/*;do
        if [ -d "$FILE" ];then
            load_cry_files "$FILE"
        elif [[ -f "$FILE" && "$FILE" == *.cry ]]; then
          NUM_FILES=$(($NUM_FILES+1))
          echo ":load $FILE" > $SCRIPT
          cryptol -e --batch $SCRIPT
          if (( $? != 0 )); then
            NUM_FAILS=$(($NUM_FAILS+1))
            FAILS+=("$FILE")
          fi
        fi
    done
}

load_cry_files "Common"
load_cry_files "Primitive"

rm $SCRIPT


echo ""
echo "=== Done checking $NUM_FILES Cryptol files ==="

if (( $NUM_FAILS != 0 ))
then
  echo "$NUM_FAILS cryptol-spec files failed to load:"
  for FILE in "${FAILS[@]}"
  do
      echo "  $FILE"
  done
  exit 1
else
  echo "All cryptol-spec files loaded successfully."
  exit 0
fi


popd > /dev/null
