#!/bin/bash
# Checks that the docstrings in the Cryptol source files pass.
# This leverages the `cryptol --project` command.
# @see https://galoisinc.github.io/cryptol/master/Project.html
#
# This script takes two positional arguments:
# 1. The path to the cryproject.toml file's directory.
# 2. (Optional) "1" to enable the --refresh-project flag.
#

# Check for the correct number of arguments.
# Exit on failure.
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Wrong number of arguments."
    exit 1
fi

# Check if the directory exists.
# Exit on failure.
if [ ! -d "$1" ]; then
    echo "Directory does not exist."
    exit 1
fi

# Set the --refresh-project flag.
# If the second argument is not "1", the flag is not set.
REFRESH_PROJECT=""
if [ "$#" -eq 2 ] && [ "$2" -eq "1" ]; then
    REFRESH_PROJECT="--refresh-project"
fi

# Run the Cryptol project command.
# Return the exit code of the subshell.
cryptol --project "$1" $REFRESH_PROJECT
exit $?
