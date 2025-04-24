#!/bin/bash


tmp_file=b.txt
grep_content="\[Ramfs-Rename\]: ok!"

cd arceos/ || exit


rm pflash.img -f 
rm disk.img -f

make pflash_img
make disk_img


make run A=exercises/ramfs_rename/ BLK=y > $tmp_file 2>/dev/null

output=$(tail -n1 ./$tmp_file | grep -a "$grep_content")

rm -rf $tmp_file 

if [[ -z "$output" ]] ;then
    echo "ramfs_rename fault"
    exit 1
else 
    echo "ramfs_rename pass"
    exit 0
fi
