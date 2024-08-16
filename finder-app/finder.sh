#!/bin/sh

if [ "$#" -ne 2 ]; then
    echo "ERROR - please specify 2 arguments. 1: filesdir, 2: searchstr"
    exit 1
fi

filesdir=$1
searchstr=$2

if [ ! -d "$filesdir" ]; then
    echo "ERROR - ensure <filesdir> points to a directory that exists in the filesystem"
    exit 1
fi

num_files=$(find "$filesdir" -type f | wc -l)

num_lines=$(grep -r "$searchstr" "$filesdir" | wc -l)

echo "The number of files are $num_files and the number of matching lines are $num_lines"
