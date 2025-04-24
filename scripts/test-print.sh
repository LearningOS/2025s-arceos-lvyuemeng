#!/bin/bash

cd arceos/ || exit

rm pflash.img -f 
rm disk.img -f

make pflash_img
make disk_img


make run A=exercises/print_with_color/ > a.txt 2>/dev/null

context=$(tail -n 20 ./a.txt )

has_color=false
has_text=false


if [[ "$context" == *$'\x1b['* ]]; then
    echo "Has color"
    has_color=true

    sed_context=$(echo "$context" | sed 's/\x1b\[[0-9;]*m//g')

    echo "$sed_context" > c.txt

    if grep -q "Hello, Arceos!" c.txt ; then
        echo "Has Hello, Arceos!"
        has_text=true
    else
        echo "No Hello, Arceos!"
    fi
else
    echo "No color"
fi


rm a.txt b.txt c.txt -f

if [[ "$has_color" == true && "$has_text" == true ]]; then
    echo "print_with_color pass"
    exit 0
else
    echo "print_with_color fault"
    exit 1
fi