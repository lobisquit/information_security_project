#!/bin/sh
find . -name "*.cpp" -o -name ".h" | \
# inspect headers for each file
xargs gcc -M -I/usr/include/pbc -lgmp -lgmpxx -lpbc | sed -e 's/[\\ ]/\n/g' | \
# format output
sed -e '/^$/d' -e '/\.o:[ \t]*$/d' | \
# generates TAGS file
ctags -eL - --c++-kinds=+p --fields=+iaS --extra=+q
