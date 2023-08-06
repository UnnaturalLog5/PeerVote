#! /bin/bash

AUTHOR=Marc
echo $AUTHOR
git log --shortstat --author $AUTHOR --since "05.12.2022" \
          | grep "files\? changed" \
          | awk '{files+=$1; inserted+=$4; deleted+=$6} END \
             {print "files changed", files, "lines inserted:", inserted, "lines deleted:", deleted}'

AUTHOR=Vasilije
echo $AUTHOR
git log --shortstat --author $AUTHOR --since "05.12.2022" \
          | grep "files\? changed" \
          | awk '{files+=$1; inserted+=$4; deleted+=$6} END \
             {print "files changed", files, "lines inserted:", inserted, "lines deleted:", deleted}'

AUTHOR=Dejan
echo $AUTHOR
git log --shortstat --author $AUTHOR --since "05.12.2022" \
          | grep "files\? changed" \
          | awk '{files+=$1; inserted+=$4; deleted+=$6} END \
             {print "files changed", files, "lines inserted:", inserted, "lines deleted:", deleted}'