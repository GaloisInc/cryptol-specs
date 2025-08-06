#!/usr/bin/env bash

# This is modified from `harupy`'s `find-trailing-whitespace` action
# @see https://github.com/harupy/find-trailing-whitespace/blob/56310d70ae8fd21afec8d4307d2d9ab6c15e7c5d/entrypoint.sh
#
# It checks all git-tracked files (`git ls-files`) for unwanted trailing
# whitespace and correctly newline-terminated files.
#

function files_end_with_newline() {
  # `egrep` is used to ignore binary files (`-I`) and return the
  # original file name (`-l`).
  # The conditional:
  # - checks the last byte of the file (`tail`),
  # - counts the number of newlines (`wc`), and
  # - fails if there are none (`gt`).
  # If the conditional fails, we output the file name (`echo`).
  for file in $(git ls-files | xargs egrep -Il ""); do
    [[ $(tail -c1 "$file" | wc -l) -gt 0 ]] || printf '%s\n' "$file"
  done
}

function files_have_trailing_whitespace() {
  # egrep arguments are:
  # -H: print the file name
  # -n: print the line number
  # -o: print only the matching part of the line (invisible, since it's whitespace)
  # -I: ignore binary files
  # The regex checks for any amount of blank space at the end of the line.
  git ls-files | xargs egrep -HnoI "[[:blank:]]+$"
}

function print_findings() {
  type=$1
  shift
  failing_lines=$@

  if [ ! -z "$failing_lines" ]; then
    printf "\n=== Failure! The following have $type :( ===\n"
    printf '%s\n' $failing_lines
    return 1
  else
    printf "\n=== Success! No $type!! ===\n"
    return 0
  fi

}

# Check for trailing whitespace
tw_lines=$(files_have_trailing_whitespace);
print_findings "trailing whitespace" "$tw_lines"
c1=$?

# Check for final newlines
mn_files=$(files_end_with_newline);
print_findings "missing final newlines" "$mn_files"
c2=$?

exit $c1 || $c2
