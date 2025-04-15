#!/bin/bash


tmp_file=c.txt
grep_content="Bump tests run OK!"

cd arceos/ || exit


rm pflash.img -f
rm disk.img -f

make pflash_img
make disk_img


make A=exercises/alt_alloc/ run > $tmp_file 2>/dev/null

output=$(tail -n1 ./$tmp_file | grep -a "$grep_content")

rm -rf $tmp_file 

if [[ -z "$output" ]] ;then
    echo "alt_alloc default"
    exit 1
else 
    echo "alt_alloc pass"
    exit 0
fi
