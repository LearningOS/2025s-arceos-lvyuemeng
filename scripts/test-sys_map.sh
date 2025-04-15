#!/bin/bash

tmp_file=mmap_test_output.txt
grep_content="Read back content: hello, arceos!"

cd arceos/ || exit

rm pflash.img -f
rm disk.img -f

make pflash_img
make disk_img

make payload
./update_disk.sh payload/mapfile_c/mapfile

make run A=exercises/sys_map/ BLK=y > $tmp_file 2>/dev/null

output=$(grep -Ea "$grep_content" ./$tmp_file)

rm -rf $tmp_file 

if [[ -z "$output" ]]; then
    echo "sys_mmap default"
    exit 1
else 
    echo "sys_mmap pass"
    exit 0
fi
