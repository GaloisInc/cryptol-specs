#!/bin/bash

COPYRIGHT="@copyright Galois"
AUTHOR="@author .*@galois.com>"

# The get-changed-files Github Action requires filenames have no spaces in them.
FILES=$@
echo -e "Checking the following files: $FILES"

missing_copyright=""
missing_author=""
for file in $FILES ; do
    if ! (grep -qr "${COPYRIGHT}" $file); then
        missing_copyright+="  $file\n"
    fi

    if !(grep -qr "${AUTHOR}" $file); then
        missing_author+="  $file\n"
    fi
done

failed=0
if [ ! -z "$missing_copyright" ]; then
    failed=1
    echo "Missing copyright notice on the following changed files:"
    echo -e "Add a comment containing '$COPYRIGHT Inc' to each file."
    echo -e "$missing_copyright"
fi

if [ ! -z "$missing_author" ]; then
    failed=1
    echo "Missing author on the following changed files:"
    echo "Add a comment containing '@author Name <email@galois.com>' to each file."
    echo -e "$missing_author"
fi

exit $failed
