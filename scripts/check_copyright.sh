#!/bin/bash
# Checks that every file indicated has an appropriate copyright notice.
#
# @copyright Galois, Inc
# @author Marcella Hastings <marcella@galois.com>
#

COPYRIGHT="@copyright"
AUTHOR="@author"

# Filters the set of changed files to only those we want copyright
# notices on -- files that likely have cryptol code in them.
#
# Skips images, pdfs, bibliographies, Makefiles, and infrastructure
# (configs, ymls, dotfiles, etc.).
interesting_files() {
    for fname in $@ ; do
        case $fname in
            README.md) continue ;;

            *.cry | *.tex | *.md | *.bat | *.awk)
                echo $fname ;;
        esac
    done
}

# This will fail if any file names have spaces in them
FILES=$(interesting_files $@)
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
