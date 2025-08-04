#!/usr/bin/env bash

# This is modified from `harupy`'s `find-trailing-whitespace` action
# @see https://github.com/harupy/find-trailing-whitespace/blob/56310d70ae8fd21afec8d4307d2d9ab6c15e7c5d/entrypoint.sh

set -e

function file_ends_with_newline() {
    [[ $(tail -c1 "$1" | wc -l) -gt 0 ]]
}

function file_has_trailing_whitespace() {
  lines=$(egrep -rnIH " +$" $1 | cut -f-2 -d ":")
  if [ ! -z "$lines" ]; then
    echo "$([[ -z "$tw_lines" ]] && echo "$lines" || echo $'\n'"$lines")"
  fi
}

mn_files="" # Files missing a final newline.
tw_lines=""  # Lines containing trailing whitespaces.

# The `sed` command adds `./` in front of each path.
for file in $(git ls-files | sed -e 's/^/.\//')
do
  # Ignore non-text files.
  case ${file##*.} in
    "pdf" | "jpg" | "xcf" | "pptx" | "vsd" ) continue;;
    *) ;;
  esac

  if ! file_ends_with_newline $file; then
    mn_files+="$file\n"
  fi
  tw_lines+=$(file_has_trailing_whitespace $file)
done

exit_code=0

# If `tw_lines`` is not empty, fail.
if [ ! -z "$tw_lines" ]; then
  echo -e "\n***** Lines containing trailing whitespace *****\n"
  echo -e "${tw_lines[@]}"
  echo -e "\nFailed.\n"
  exit_code=1
else
  echo -e "\n***** No lines contained trailing whitespace! *****\n"
fi

# If `mn_files` is not empty, fail.
if [ ! -z "$mn_files" ]; then
  echo -e "\n***** Files missing a final newline *****\n"
  echo -e "${mn_files}"
  echo -e "\nFailed.\n"
  exit_code=1
else
  echo -e "\n***** No files were missing a final newline! *****\n"
fi

exit $exit_code
