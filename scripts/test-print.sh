#!/bin/bash

cd arceos/ || exit

# rm pflash.img -f 
# rm disk.img -f

# make pflash_img
# make disk_img


make run A=exercises/print_with_color/ > a.txt 2>/dev/null

output=$(grep -a "$(printf '\x1b')"  ./a.txt | grep "Hello, Arceos!"  ) || true

# cat a.txt
# echo "$output"

rm a.txt -f

if [[ -z "$output" ]] ;then
    echo "print_with_color default"
    exit 1
else 
    echo "print_with_color pass"
    exit 0
fi
