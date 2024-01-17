#! /bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $DIR/.. > /dev/null

NUM_FILES=0
NUM_FAILS=0
FAILS=()
NUM_WARNS=0
WITH_WARNS=()
SCRIPT=$(mktemp)

# These files hang while loading due to the type complexity
SKIP=("Primitive/Asymmetric/Signature/SphincsPlus/3.1/specification.tex"
      "Primitive/Asymmetric/Signature/SphincsPlus/3.1/sphincs.tex"
      "Primitive/Asymmetric/Signature/SphincsPlus/3.1/sphincsplus128f.cry"
      "Primitive/Asymmetric/Signature/SphincsPlus/3.1/sphincsplus128s.cry"
      "Primitive/Asymmetric/Signature/SphincsPlus/3.1/sphincsplus192f.cry"
      "Primitive/Asymmetric/Signature/SphincsPlus/3.1/sphincsplus192s.cry"
      "Primitive/Asymmetric/Signature/SphincsPlus/3.1/sphincsplus256f.cry"
      "Primitive/Asymmetric/Signature/SphincsPlus/3.1/sphincsplus256s.cry"
      "Primitive/Asymmetric/Signature/SphincsPlus/1.0/SphincsPlus.md")

load_cry_files() {
    for FILE in "$1"/*; do
        if [ -d "$FILE" ]; then
          load_cry_files "$FILE"
        elif [[ ${SKIP[@]} =~ $FILE ]]; then
          echo "Skipping $FILE."
        elif [[ -f "$FILE" && ("$FILE" == *.cry && "$FILE" == *.tex || ("$FILE" == *.md && "$FILE" != *README.md)) ]]; then
          NUM_FILES=$(($NUM_FILES+1))
          echo ":load $FILE" > $SCRIPT
          result=$(cryptol -e --batch $SCRIPT)
          echo "$result"
          # Check for loading errors
          if grep -q "error" <<< "$result"; then
            NUM_FAILS=$(($NUM_FAILS+1))
            FAILS+=("$FILE")
          # Check for files that loaded with warnings
          elif grep -q "warning" <<< "$result"; then
            NUM_WARNS=$(($NUM_WARNS+1))
            WITH_WARNS+=("$FILE")
          fi
        fi
    done
}

load_cry_files "Common"
load_cry_files "Primitive"

rm $SCRIPT

echo ""
echo "=== Done checking $NUM_FILES Cryptol files ==="

echo "The following files were skipped: "
for FILE in "${SKIP[@]}"; do
  echo " $FILE"
done

if (( $NUM_WARNS != 0 )); then
  echo "$NUM_WARNS files loaded with warnings:"
  for FILE in "${WITH_WARNS[@]}"; do
    echo " $FILE"
  done
fi

if (( $NUM_FAILS != 0 )); then
  echo "$NUM_FAILS cryptol-spec files failed to load:"
  for FILE in "${FAILS[@]}"; do
      echo "  $FILE"
  done
  exit 1
else
  echo "All cryptol-spec files loaded successfully."
  exit 0
fi

popd > /dev/null
