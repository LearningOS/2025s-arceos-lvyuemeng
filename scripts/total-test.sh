#!/bin/bash
file_name=test.output
score=0

rm -f $file_name

touch  $file_name

if ./scripts/test-print.sh ; then
    ((score += 100))
else
    echo "test-print failed" >> $file_name
fi

if ./scripts/test-ramfs_rename.sh ; then
    ((score += 100))
else
    echo "test-ramfs_rename failed" >> $file_name
fi

if ./scripts/test-alt_alloc.sh ; then
    ((score += 100))
else
    echo "test-alt_alloc failed" >> $file_name
fi

if ./scripts/test-support_hashmap.sh ; then
    ((score += 100))
else
    echo "test-support_hashmap failed" >> $file_name
fi

if ./scripts/test-sys_map.sh ; then
    ((score += 100))
else
    echo "test-sys_map failed" >> $file_name
fi

if ./scripts/test-simple_hv.sh ; then
    ((score += 100))
else
    echo "test-simple_hv failed" >> $file_name
fi

echo "$score"
